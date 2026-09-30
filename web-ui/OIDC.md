# authd sign-in

Sysmon selects authentication for the whole installation. With no OIDC configuration it uses its existing internal accounts. With OIDC enabled, the web UI, iOS, and Android use authd. Local password sign-in and local user management are disabled, and existing local sessions are refused. Removing the OIDC configuration restores local-account mode and its stored users.

## Bootstrap on the Sysmon host

Ask the authd administrator for a one-use registration token authorized to register the `sysmon.` namespace. authd and Sysmon can run on separate hosts. The token is the only value transferred between operators; Sysmon performs registration through the provider's HTTPS endpoint.

Save the token in a regular file with mode `0600`, owned by the account that reads credentials after privilege dropping. On OpenBSD the rc script starts as root but sysmon-web switches to `_sysmon` (or the account selected by `-user`, with `nobody` as the fallback) **before** OIDC initialization. Bootstrap as that unprivileged account, not root. The supplied Linux systemd unit runs directly as `www-data`.

For the default OpenBSD `_sysmon` account, prepare the credential directory and hand over the token file as root:

```sh
doas install -d -o _sysmon -g _sysmon -m 0700 /var/lib/sysmon
doas chown _sysmon:_sysmon /path/to/registration-token
doas chmod 0600 /path/to/registration-token
```

Then bootstrap on the Sysmon host:

```sh
doas -u _sysmon sysmon-web oidc-bootstrap \
  -issuer https://auth.example.com \
  -redirect https://sysmon.example.com/auth/callback \
  -registration-token-file /path/to/registration-token \
  -client-file /var/lib/sysmon/oidc-client.json
```

On Linux, run the same command with `sudo -u www-data` instead of `doas -u _sysmon`, after preparing the directory and token file for `www-data`. For a custom OpenBSD `-user`, substitute that account throughout. A token kept under a root-only home directory is still inaccessible after `chown`; use a path whose parent directories the service account can traverse.

The account must be able to write the client-file directory. The command discovers authd's registration endpoint and registers a confidential Authorization Code client with S256 PKCE, offline refresh, `sysmon.read`, and `sysmon.manage`. It submits authd role templates for `sysmon.viewer` (read) and `sysmon.administrator` (read and manage). It saves the client ID, client secret, management URI, and management token in an atomic `0600` credentials file. It prints only the client ID and file path. Remove the spent registration-token file after success.

Assign the new roles to users in authd. Creating a role does not assign it to anybody. A user must have `sysmon.read` to enter Sysmon; `sysmon.manage` additionally permits administration. Authorization uses the verified access token's exact granted scopes.

## Service configuration

Configure these variables for sysmon-web:

```sh
SYSMON_OIDC_ISSUER=https://auth.example.com
SYSMON_OIDC_REDIRECT_URL=https://sysmon.example.com/auth/callback
SYSMON_OIDC_CLIENT_FILE=/var/lib/sysmon/oidc-client.json
```

The callback must match the registered public HTTPS URL exactly. The supplied systemd unit and OpenBSD rc script read `/etc/sysmon-web/oidc.env` if present. Keep that environment file root-owned with mode `0600`; quote shell metacharacters when using the rc script. The credentials file must remain readable and writable only by the service account. Restart the service after changing configuration.

At startup, Sysmon loads saved credentials and keeps the registered scope list current through authd's management endpoint, as temary-relay does. It refuses files readable by other users, changed issuers or callbacks, incomplete configuration, and failed registration. It can also register on first start if `SYSMON_OIDC_REGISTRATION_TOKEN_FILE` is supplied instead of running the bootstrap command. That token file must likewise be `0600` and owned by `_sysmon` (or the configured unprivileged account) on OpenBSD, or by `www-data` under the supplied Linux unit; startup does not transfer ownership of existing files. After registration, restart uses the saved file and does not spend another token.

A manually registered client is an alternative: set `SYSMON_OIDC_CLIENT_ID` and `SYSMON_OIDC_CLIENT_SECRET` together. That client must allow `authorization_code`, `refresh_token`, `openid profile email offline_access sysmon.read sysmon.manage`, and `client_secret_basic`. These settings bypass managed registration.

## Sessions and mobile apps

The backend verifies signatures, issuer, audience, client binding, expiry, subject, nonce, and access-token hash. Refresh credentials stay in the owner-only backend auth database. Grants are renewed through authd with rotating refresh tokens and a durable in-flight marker. Requests for the same session serialize their refresh; different users refresh independently. A definite provider refusal or a crash during refresh requires a new sign-in. Failed refresh requests can be retried only when they indicate a transport failure or temporary provider outage.

Sysmon retries transport failures (including timeouts and resets after connecting), HTTP `429`/`500`/`502`/`503`/`504`, and OAuth `temporarily_unavailable`. Definite OAuth refusals, including `invalid_grant` and `invalid_client`, and HTTP `400`/`401` end the session even if the response also suggests temporary unavailability. Sysmon clears the in-flight marker after a classified temporary failure, retains the last verified role for at most five minutes after the verified access token expires, and retries at 30-second intervals. The grace deadline never slides. After that deadline, protected requests return `503` with `Retry-After: 30` while retaining the session for recovery. A successful refresh replaces the grant and role normally.

If the lost request had already rotated the credential, retrying the stored token causes authd to detect reuse, revoke its family, and return `invalid_grant`; Sysmon then ends the session. A retry can occupy that session's refresh lock for up to 15 seconds, while other sessions remain independent.

This grace policy applies to an already running backend; initial OIDC discovery at startup and new sign-ins still require authd. Local password authentication remains a separate installation mode.

Sessions have a 30-day absolute limit. bbolt opens the database exclusively. Session termination attempts refresh-token revocation; cleanup runs at startup and every minute to remove expired sessions and abandoned mobile handoffs. Logout can remove the local session even during a provider outage. Revocation is best effort when authd is unreachable. If the configured issuer or client has changed, credentials for the original client are needed to revoke its grants; Sysmon never sends those old credentials to the replacement provider.

Audit entries and configuration authorship record the verified display name alongside the stable `authd:<hash>` account ID. Push subscriptions remain keyed by that stable ID.

The mobile apps check `/api/auth/mode`. OIDC mode opens the system browser for authd, and the backend completes the confidential exchange. The callback returns to `sysmon://auth/callback` with a one-minute, one-use handoff code. The app proves possession of its own PKCE verifier to receive its Sysmon bearer session over HTTPS. Client secrets, refresh credentials, and session tokens do not appear in browser redirects. Local-account installations show the existing password form.
