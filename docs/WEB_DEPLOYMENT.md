# Deploying sysmon-web behind a web server

`sysmon-web` speaks **FastCGI over a Unix domain socket**. It does not
terminate TLS or serve HTTP to the world itself — you put nginx (Linux)
or httpd(8) (OpenBSD) in front of it. This document covers both, plus the
two things that bite everyone: **socket ownership** and **daemonization**.

> Quick reference for the impatient:
> - Default socket: `/var/www/run/sysmon-web.sock`, mode `0660`.
> - Run as the web-server user, OR pass `-socket-user`/`-socket-group` so
>   the web server can connect.
> - `sysmon-web` daemonizes by default. Use `-foreground` under a
>   supervisor (systemd, rc.d) and `-debug` to see logs.

---

## 1. Daemonization and logging

`sysmon-web` **daemonizes by default**: run it by hand and it detaches
(new session, std streams to `/dev/null`), prints the child PID, and
returns your shell prompt.

| Invocation | Behaviour |
|---|---|
| `sysmon-web …` | Daemonizes, **silent** (no logs). |
| `sysmon-web -debug …` | Stays in the foreground, logs to **stderr**. Use this to find out why something won't start. |
| `sysmon-web -foreground …` | Stays in the foreground, still silent. For process supervisors that track the PID themselves (systemd `Type=simple`, OpenBSD `rc.d`). Add `-debug` to also get logs. |

Logs are **off unless `-debug`** is given — a daemon shouldn't chatter.
If the service won't come up, the move is always: stop it, run it once
in the foreground with `-debug`, read the error, fix, restart under the
supervisor.

> Under a supervisor you almost always want `-foreground`. If you let it
> self-daemonize under `Type=simple`, systemd sees the parent exit
> immediately and assumes the service crashed.

---

## 2. Privilege dropping and socket ownership

`sysmon-web` is built to be **started as root and immediately drop
privileges**. The only thing it does as root is the unavoidable part —
bind the listening socket (a unix socket inside httpd's `/var/www`
chroot, or a low TCP port) and hand that socket to the web server's user.
Then, before opening any database or serving a single request, it:

1. **Chowns the socket** to the web server's identity so it can connect.
   Default: the first of **`www`, `www-data`, `nobody`** that exists.
   Override with `-socket-user` / `-socket-group`.
2. **Prepares its data directories** (`/var/lib/sysmon`,
   `/var/backups/sysmon`, the audit log) owned by the unprivileged user.
3. **Drops to an unprivileged user/group** for the rest of its life.
   Default: **`_sysmon`** if it exists, otherwise **`nobody`**. Override
   with `-user` / `-group`. The group defaults to that user's primary
   group (so the `nobody`/`nogroup` split across distros is handled for
   you).

If it's started as root and can't find *any* unprivileged account to drop
to, it **refuses to run** rather than silently stay root. Create a
`_sysmon` user, or pass `-user`/`-group`.

If `sysmon-web` is started by something that has **already** dropped
privileges (the systemd unit runs as `www-data`), it detects it isn't
root and skips all of the above — the socket is simply created owned by
that user.

> The socket is mode `0660` (owner+group read/write, world none), so only
> the web server's user/group can connect. A `502` with
> "connect() failed (13: Permission denied)" in the web-server log means
> the socket is still owned by the wrong user — i.e. it was started as a
> non-root, non-web user, or the resolved socket owner is wrong.

For the unprivileged user to work, its data paths must be writable by it.
`sysmon-web` creates and chowns `/var/lib/sysmon` and the backup dir on
first start, but **`/etc/sysmon.conf` is yours**: if you want to use the
config editor, that file must be writable by the drop user (or its
group). Reading it only needs world-read, which is the default.

---

## 3. Linux + nginx

### 3.1 systemd unit

Use the shipped unit (`web-ui/sysmon-web.service`); the important bits:

```ini
[Service]
Type=simple
User=www-data
Group=www-data
# www-data can't mkdir under root-owned /var/www, so create the socket
# dir as root first (the "+" runs these as root despite User=www-data).
ExecStartPre=+/bin/mkdir -p /var/www/run
ExecStartPre=+/bin/chown www-data:www-data /var/www/run
ExecStart=/usr/local/bin/sysmon-web \
  -foreground \
  -socket /var/www/run/sysmon-web.sock \
  -config /etc/sysmon.conf \
  -templates /usr/local/libexec/sysmon-web/templates \
  -backups /var/backups/sysmon \
  -audit /var/log/sysmon-web-audit.log
Restart=always
```

Because it runs as `www-data`, the socket is already owned by nginx's
user — no `-socket-*` flags needed. The `ExecStartPre` lines create
`/var/www/run` (which `ProtectSystem=strict` also lists in
`ReadWritePaths`). Add `-debug` to the `ExecStart` line temporarily to
get logs in the journal (`journalctl -u sysmon-web -f`).

```sh
cp web-ui/sysmon-web.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sysmon-web
```

### 3.2 nginx server block

See `web-ui/nginx.conf.example` for the full TLS version. Minimum:

```nginx
server {
    listen 443 ssl http2;
    server_name sysmon.example.com;

    ssl_certificate     /etc/ssl/certs/sysmon.example.com.crt;
    ssl_certificate_key /etc/ssl/private/sysmon.example.com.key;

    location / {
        include fastcgi_params;
        fastcgi_pass unix:/var/www/run/sysmon-web.sock;
    }

    # Static assets are served straight off disk, bypassing FastCGI.
    location /static/ {
        alias /usr/local/libexec/sysmon-web/static/;
        expires 1h;
        add_header Cache-Control "public, immutable";
    }
}
```

```sh
nginx -t && systemctl reload nginx
```

If you get a 502, check `/var/log/nginx/error.log`:
- `Permission denied` → socket ownership (section 2).
- `No such file or directory` → sysmon-web isn't running, or the socket
  path differs. `systemctl status sysmon-web`, then run it `-debug`.

---

## 4. OpenBSD + httpd(8)

The OpenBSD gotcha: **httpd runs chrooted in `/var/www`**. A FastCGI
`socket` path in `httpd.conf` is interpreted **relative to that chroot**.
So the socket must physically live under `/var/www`, and httpd.conf
references it without the `/var/www` prefix.

We put it at `/var/www/run/sysmon-web.sock` and reference
`/run/sysmon-web.sock` in httpd.conf.

### 4.1 rc.d script

Install the shipped script (`web-ui/rc.d/sysmon_web`):

```sh
cp web-ui/rc.d/sysmon_web /etc/rc.d/sysmon_web
chmod 555 /etc/rc.d/sysmon_web
rcctl enable sysmon_web
rcctl start sysmon_web
```

It runs `sysmon-web` as **root** just long enough to bind the socket
inside the chroot and chown it to `www` (httpd's user); it then drops to
`_sysmon` (or `nobody` if you haven't created `_sysmon`). The socket path,
the `www` socket owner, and the `_sysmon` drop target are all defaults on
OpenBSD, so the script doesn't need to spell them out — it only sets
`-foreground`, the paths, and the sysmond address.

Create the unprivileged user so it doesn't fall back to `nobody`:

```sh
useradd -d /var/empty -s /sbin/nologin -g =uid _sysmon
# sysmon-web creates+chowns /var/lib/sysmon and /var/backups/sysmon on
# first start; if you want the config editor to work, make /etc/sysmon.conf
# writable by _sysmon as well.
```

To see why it won't start:

```sh
rcctl -d start sysmon_web          # rc.d debug
/usr/local/bin/sysmon-web -debug … # run the binary directly, read stderr
```

### 4.2 httpd.conf

```
server "sysmon.example.com" {
    listen on * tls port 443
    tls {
        certificate "/etc/ssl/sysmon.example.com.crt"
        key         "/etc/ssl/private/sysmon.example.com.key"
    }

    # Everything goes to sysmon-web over FastCGI. The socket path is
    # chroot-relative: /run/... maps to /var/www/run/... on disk.
    location "/*" {
        fastcgi socket "/run/sysmon-web.sock"
    }

    # Serve static assets directly. They must live inside the chroot;
    # copy or symlink them under /var/www.
    location "/static/*" {
        root "/htdocs/sysmon-web"   # => /var/www/htdocs/sysmon-web
    }
}
```

Place the static assets where httpd can reach them inside the chroot:

```sh
mkdir -p /var/www/htdocs/sysmon-web
cp -R /usr/local/libexec/sysmon-web/static /var/www/htdocs/sysmon-web/
```

Then:

```sh
httpd -n            # check the config
rcctl reload httpd
```

A plain-HTTP variant (no TLS) just drops the `tls { … }` block and uses
`listen on * port 80`.

---

## 5. Verifying socket and process

After starting sysmon-web, check **both** the socket ownership and that
the process actually dropped root.

```sh
# Socket: owned by the web server's user/group, mode 0660.
# (/var/www/run is the default on both platforms.)
ls -l /var/www/run/sysmon-web.sock
# Linux  -> srw-rw----  1 www-data www-data 0 … sysmon-web.sock
# OpenBSD -> srw-rw----  1 www      www      0 … sysmon-web.sock

# Process: must NOT be root.
ps -o user,group,comm -C sysmon-web     # Linux
ps -axo user,comm | grep sysmon-web     # OpenBSD
# _sysmon (or nobody)  sysmon-web        <- never "root"
```

Troubleshooting:
- Socket shows `root wheel`/`root root` → it was started by a non-root,
  non-web user, or by the wrong supervisor flags. Only a **root**-started
  instance chowns the socket.
- Process shows `root` → either it was started non-root by some account
  that happens to be root's, or (if you see "refusing to run as root" with
  `-debug`) there was no `_sysmon`/`nobody` account to drop to.
- `502 / Permission denied` in the web-server log → socket group isn't the
  web server's group. Re-check `-socket-user`/`-socket-group`, or just run
  sysmon-web as the web user (the systemd unit does).

---

## 6. First login

Once the web server can reach sysmon-web, browse to the site and log in
with the auto-seeded admin account: **`admin` / `sysmon`**. Change the
password immediately (Admin page → user list → key icon). Push
notifications, if you use them, are configured entirely in the admin UI
(Admin → Push Configuration) — not in `sysmon.conf`. See
`docs/PUSH_NOTIFICATIONS.md`.
