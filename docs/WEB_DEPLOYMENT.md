# Deploying sysmon-web behind a web server

`sysmon-web` speaks **FastCGI over a Unix domain socket**. It does not
terminate TLS or serve HTTP to the world itself — you put nginx (Linux)
or httpd(8) (OpenBSD) in front of it. This document covers both, plus the
two things that bite everyone: **socket ownership** and **daemonization**.

> Quick reference for the impatient:
> - Default socket: `/var/run/sysmon-web.sock`, mode `0660`.
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

## 2. Socket ownership (the root:wheel problem)

`sysmon-web` creates the socket mode `0660` (owner+group read/write,
world nothing). If you start it as **root** and do nothing else, the
socket ends up owned by `root:root` (`root:wheel` on BSD) — and your web
server, which runs as `www-data`/`www`, gets **permission denied** (502 /
"connect() failed (13: Permission denied)").

Two ways to fix it:

1. **Run sysmon-web as the web-server user** (simplest). The socket is
   then created already owned correctly. The systemd unit does this
   (`User=www-data`).

2. **Hand the socket over after creating it** with
   `-socket-user`/`-socket-group`. Use this when sysmon-web must run as
   root (e.g. so it can read a root-only `sysmon.conf`, or on OpenBSD
   where it places the socket inside httpd's chroot). Either flag may be
   given alone; the other component is left unchanged.

   ```sh
   sysmon-web -socket-group www-data …      # nginx / Linux
   sysmon-web -socket-user www -socket-group www …   # OpenBSD httpd
   ```

---

## 3. Linux + nginx

### 3.1 systemd unit

Use the shipped unit (`web-ui/sysmon-web.service`); the important bits:

```ini
[Service]
Type=simple
User=www-data
Group=www-data
ExecStart=/usr/local/bin/sysmon-web \
  -foreground \
  -socket /var/run/sysmon-web.sock \
  -config /etc/sysmon.conf \
  -sysmon localhost:1345 \
  -templates /usr/local/libexec/sysmon-web/templates \
  -backups /var/backups/sysmon \
  -audit /var/log/sysmon-web-audit.log
Restart=always
```

Because it runs as `www-data`, the socket is already owned by nginx's
user — no `-socket-*` flags needed. Add `-debug` to the `ExecStart` line
temporarily to get logs in the journal (`journalctl -u sysmon-web -f`).

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
        fastcgi_pass unix:/var/run/sysmon-web.sock;
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

Its flags (already set in the script):

```
-foreground
-socket /var/www/run/sysmon-web.sock
-socket-user www -socket-group www
-config /etc/sysmon.conf
-sysmon 127.0.0.1:1345
-templates /usr/local/libexec/sysmon-web/templates
-backups /var/backups/sysmon
-audit /var/log/sysmon-web-audit.log
```

It runs `sysmon-web` as root (so it can place the socket inside the
chroot and read a root-owned config) and chowns the socket to `www:www`
so httpd can connect. The `rc_pre` step creates `/var/www/run` if needed.

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

## 5. Verifying the socket

Regardless of platform, after starting sysmon-web:

```sh
ls -l /var/run/sysmon-web.sock          # Linux
ls -l /var/www/run/sysmon-web.sock      # OpenBSD
# srw-rw----  1 root  www-data  0 … sysmon-web.sock   <- group must be the web user
```

The group must be the web server's group and the mode `0660`. If it
shows `root wheel` / `root root`, the chown didn't happen — you started
it as root without `-socket-group`, or the supervisor's flags are stale.

---

## 6. First login

Once the web server can reach sysmon-web, browse to the site and log in
with the auto-seeded admin account: **`admin` / `sysmon`**. Change the
password immediately (Admin page → user list → key icon). Push
notifications, if you use them, are configured entirely in the admin UI
(Admin → Push Configuration) — not in `sysmon.conf`. See
`docs/PUSH_NOTIFICATIONS.md`.
