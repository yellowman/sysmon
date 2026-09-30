# authd sign-in

Sysmon selects authentication for the whole installation. With no OIDC configuration it uses its existing internal accounts. With OIDC enabled, the web UI, iOS, and Android use authd. Local password sign-in and local user management are disabled, and existing local sessions are refused. Removing the OIDC configuration restores local-account mode and its stored users.

## Bootstrap on the Sysmon host

Ask the authd administrator for a one-use registration token authorized to register the `sysmon.` namespace. authd and Sysmon can run on separate hosts. The token is the only value transferred between operators; Sysmon performs registration through the provider's HTTPS endpoint.

Save the token in a regular file with mode `0600`, owned by the account that runs sysmon-web. Run this command as that same account on the Sysmon host:

```sh
sysmon-web oidc-bootstrap \
  -issuer https://auth.example.com \
  -redirect https://sysmon.example.com/auth/callback \
  -registration-token-file /path/to/registration-token \
  -client-file /var/lib/sysmon/oidc-client.json
```

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

At startup, Sysmon loads saved credentials and keeps the registered scope list current through authd's management endpoint, as temary-relay does. It refuses files readable by other users, changed issuers or callbacks, incomplete configuration, and failed registration. It can also register on first start if `SYSMON_OIDC_REGISTRATION_TOKEN_FILE` is supplied instead of running the bootstrap command. After registration, restart uses the saved file and does not spend another token.

A manually registered client is an alternative: set `SYSMON_OIDC_CLIENT_ID` and `SYSMON_OIDC_CLIENT_SECRET` together. That client must allow `authorization_code`, `refresh_token`, `openid profile email offline_access sysmon.read sysmon.manage`, and `client_secret_basic`. These settings bypass managed registration.

## Sessions and mobile apps

The backend verifies signatures, issuer, audience, client binding, expiry, subject, nonce, and access-token hash. Refresh credentials stay in the owner-only backend auth database. Grants are renewed through authd with rotating refresh tokens and a durable in-flight marker; an ambiguous refresh requires a new sign-in. Sessions have a 30-day absolute limit. bbolt opens the database exclusively, and refresh is serialized within that backend process. Logout deletes the local session and attempts refresh-token revocation.

The mobile apps check `/api/auth/mode`. OIDC mode opens the system browser for authd, and the backend completes the confidential exchange. The callback returns to `sysmon://auth/callback` with a one-minute, one-use handoff code. The app proves possession of its own PKCE verifier to receive its Sysmon bearer session over HTTPS. Client secrets, refresh credentials, and session tokens do not appear in browser redirects. Local-account installations show the existing password form.
