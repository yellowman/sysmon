# sysmon Push Notifications Guide

Push notifications deliver real-time mobile alerts when monitored hosts
change state. The sysmon web-ui backend polls the C daemon every second,
detects state transitions, and pushes alerts to subscribed iOS and
Android devices via APNs and FCM respectively.

## Architecture

```
sysmond (C daemon)
    |
    | TCP :1345 (poll every 1s)
    v
sysmon-web (Go backend)
    |
    |-- APNs (HTTP/2) --> iOS devices
    |-- FCM  (HTTPS)  --> Android devices
    |
    +-- bbolt: push.db (subscriptions, push log)
    +-- bbolt: auth.db (users, sessions)
```

## Authentication Model

Every API call requires a valid user session. The mobile app:

1. Logs in once with username/password → gets a session token
2. Sends `Authorization: Bearer <token>` on all subsequent requests
3. Token expires after 24 hours — app prompts for login again

Two roles:
- **admin** — full access including pushing test notifications to any
  device and removing any subscription
- **user** — can manage their own push subscriptions only

A regular `user` account is fine for the mobile app. Each subscription
is tied to the user account that registered it.

## Server Setup

Push notifications are configured in the admin UI, **not** in
`sysmon.conf`. The C daemon never used these settings; they live in the
web-ui-only settings store (bbolt at `/var/lib/sysmon/settings.db`).

Open the web UI → log in as an admin → **Admin** → **Push Configuration**.

### 1. FCM (Android)

sysmon-web talks to FCM via the HTTP v1 API and authenticates with a
Google service-account JSON.

1. Firebase Console → Project Settings → **Service accounts** → "Generate
   new private key" → download the JSON. (This is **not** the
   `google-services.json` your Android app ships with.)
2. Make sure the **Firebase Cloud Messaging API** is enabled in the
   matching Google Cloud project.
3. In the admin UI, click **Upload service-account JSON** under the FCM
   section and select the downloaded file.

The credentials are validated on upload (rejected with a clear error if
you accidentally upload `google-services.json` or any other non
service-account file). Project ID and service-account email are extracted
and shown in the admin UI; the private key itself is never re-served by
the API. sysmon-web mints short-lived OAuth access tokens transparently
and refreshes them automatically.

### 2. APNs (iOS)

Export your push certificate from the Apple Developer portal as `.p12`,
then convert to PEM (locally — you'll upload, not deploy to disk):

```sh
openssl pkcs12 -in cert.p12 -out apns-cert.pem -clcerts -nokeys
openssl pkcs12 -in cert.p12 -out apns-key.pem -nocerts -nodes
```

In the admin UI under **APNs**:

- Upload `apns-cert.pem` and `apns-key.pem`.
- Set **Bundle ID** to match your app (e.g. `com.example.sysmon`).
- Toggle **Production** on for App Store builds; leave it off to use
  the APNs sandbox gateway during development.

The certificate is validated on upload; its Subject CN and expiry are
shown in the panel.

**With both FCM and APNs configured**, each iOS device still receives
exactly one notification — there is one subscription row per device,
and the send path picks one transport per token. Which one is decided
by the token itself: a raw APNs device token (64 hex chars, registered
by app builds without a `GoogleService-Info.plist`) goes direct to
APNs; anything else goes via FCM, which relays to APNs internally.
This means a mixed fleet — some installs built with Firebase, some
without — delivers correctly from one server, and neither transport
is ever handed a token it can't deliver to.

### 3. Enable

Flip the master **Enabled** switch in the admin UI to start the push
watcher. Changes take effect immediately without a restart.

### 4. Create a mobile user account

After the first run of sysmon-web, log in as the default admin
(`admin` / `sysmon`), change the admin password, then create a
dedicated user account for the mobile app via the Admin page or
the API:

```sh
curl -X POST https://sysmon.example.com/api/auth/users \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"username":"mobile","password":"<strong-password>","role":"user"}'
```

### 5. Restart sysmon-web

Logs on startup should show:

```
auth: initialized (2 users)
push: FCM client initialized
push: APNs client initialized (production, bundle: com.example.sysmon)
push: database opened at /var/lib/sysmon/push.db (0 subscriptions)
push: state change watcher started (1s poll interval)
```

## API Reference

All endpoints require `Authorization: Bearer <token>` from a valid
login session, except `POST /api/auth/login`.

### Log in

```
POST /api/auth/login
Content-Type: application/json

{"username": "mobile", "password": "..."}
```

Response:
```json
{
  "token": "abc123...",
  "username": "mobile",
  "role": "user"
}
```

Store the `token` in secure storage (Keychain on iOS, EncryptedSharedPreferences
on Android). Use it as `Authorization: Bearer <token>` for all other
requests. Token is valid for 24 hours.

### Log out

```
POST /api/auth/logout
Authorization: Bearer <token>
```

Invalidates the session server-side.

### Subscribe a device

```
POST /api/push/subscribe
Authorization: Bearer <token>
Content-Type: application/json

{
  "device_token": "<from APNs or FCM>",
  "platform": "ios" or "android",
  "label": "Chris's iPhone"
}
```

The subscription is tied to the authenticated user. If the same
`device_token` was previously registered by a different user, the
request fails with 400. Re-subscribing your own device updates the
label and last-seen but returns the same `api_key`.

Response:
```json
{"status": "subscribed", "api_key": "a1b2c3d4..."}
```

The `api_key` is a per-device fingerprint returned for the app's own
record. It is NOT an authorization credential — all unsubscribe and
test operations require a valid session that owns the device. The
api_key is reserved for future use (e.g., letting the daemon mark
device-specific delivery state).

If FCM has previously refused this exact token with `UNREGISTERED`
(see Token Lifecycle below), the subscription is still stored but the
response carries a verdict:

```json
{
  "status": "subscribed",
  "api_key": "a1b2c3d4...",
  "token_status": "invalid",
  "message": "FCM reports this device token is no longer valid - delete the cached token, obtain a fresh one, and subscribe again"
}
```

`token_status: "invalid"` is the app's cue to force a token rotation —
`deleteToken()` then `getToken()` on Android, `deleteToken()` then
`token()` on iOS — and subscribe again with the fresh token. This
matters because FCM only ever reports a dead token to the *sender*: the
Firebase SDK on the device keeps returning the dead token from its
cache and `onNewToken` / the MessagingDelegate never fires, so without
this signal the app would re-register the same dead token forever.

### List my subscriptions

```
GET /api/push/me
Authorization: Bearer <token>
```

Returns only the current user's own subscriptions. `api_key` is
stripped from the response (the app already has it). A subscription
whose token FCM has refused with `UNREGISTERED` additionally carries
`"unregistered": true`.

```json
{
  "subscriptions": [
    {
      "device_token": "abc...",
      "platform": "ios",
      "label": "Chris's iPhone",
      "created_at": "2026-05-27T12:00:00Z",
      "last_seen": "2026-05-27T14:30:00Z",
      "last_push_at": "2026-05-27T14:25:00Z",
      "last_push_status": "ok",
      "push_count": 47
    }
  ],
  "count": 1
}
```

### Unsubscribe a device

```
DELETE /api/push/subscribe
Authorization: Bearer <token>
Content-Type: application/json

{"device_token": "<token>"}
```

You can only unsubscribe a device that your account owns. Admins can
unsubscribe any device. The `api_key` is NOT accepted as auth — it's
just a per-device fingerprint, not an authorization credential.

### Send a test notification

```
POST /api/push/test
Authorization: Bearer <token>
Content-Type: application/json

{"device_token": "<token>"}
```

You can only test devices your account owns. Admins can test any device.

### Admin: list all subscriptions

```
GET /api/push/subscriptions
Authorization: Bearer <admin-token>
```

Returns every device with full metadata (IP, user agent, push stats,
owner). `api_key` is stripped.

### Admin: remove any device

```
DELETE /api/push/remove/<device_token>
Authorization: Bearer <admin-token>
```

### Admin: push notification log

```
GET /api/push/log?limit=50
Authorization: Bearer <admin-token>
```

## Notification Payloads

### iOS (APNs)

```json
{
  "aps": {
    "alert": {
      "title": "router-core DOWN",
      "subtitle": "Core router - DC1",
      "body": "router-core rtt check failed - rtt avg 143.2ms (limit 80ms), jitter 12.1ms (limit 20ms), 3/5 replies"
    },
    "sound": "default"
  }
}
```

### Android (FCM)

```json
{
  "notification": {
    "title": "router-core DOWN",
    "body": "router-core rtt check failed - rtt avg 143.2ms (limit 80ms), jitter 12.1ms (limit 20ms), 3/5 replies"
  },
  "data": {
    "hostname": "router-core",
    "status": "CRITICAL",
    "type": "rtt",
    "details": "rtt avg 143.2ms (limit 80ms), jitter 12.1ms (limit 20ms), 3/5 replies",
    "related": "core-temp reading 38 (max 45); core-loss loss 0.0% (0/64 lost)"
  }
}
```

When the object measures something, the figures ride in the visible
body (and again in the `details` data key for programmatic use): rtt
checks quote latency/jitter against the configured limits and any
probe loss, pktloss checks quote the loss percentage and counts, SNMP
value checks quote the last reading against its threshold ("reading 52
(max 45)" for a temperature check), and SNMP reboot checks quote the
device's uptime — how long ago it came back. Plain ping/tcp checks
have nothing to measure, so their body stays as-is. Recoveries carry
the current (healthy) figures too.

The notification also quotes what the *other* objects watching the
same box last measured — matched by hostname/address within the same
site. A ping object can only say down/up, but its siblings (the rtt
object, the temperature check) hold the last readings the fleet has
for that machine, so a ping-down body ends with e.g.
`- also: core-rtt rtt avg 44.0ms (limit 80ms); core-temp reading 38
(max 45)`. Siblings that measure nothing are skipped, a sibling that
is itself failing is marked (`[CRITICAL]`), and the list is capped at
3 (`+N more`). The same string rides in the `related` data key.

Recovery: title becomes `"router-core RECOVERED"`, body is
`"router-core is back up (was CRITICAL) - rtt avg 11.0ms (limit 80ms)"`.

## Mobile App Integration

### iOS (Swift)

```swift
import UserNotifications

class SysmonClient {
    let baseURL = "https://sysmon.example.com"
    var token: String? { UserDefaults.standard.string(forKey: "sysmon_token") }

    func login(username: String, password: String) async throws {
        var req = URLRequest(url: URL(string: "\(baseURL)/api/auth/login")!)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: [
            "username": username, "password": password
        ])
        let (data, _) = try await URLSession.shared.data(for: req)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: String]
        UserDefaults.standard.set(json["token"], forKey: "sysmon_token")
    }

    func subscribe(deviceToken: Data) async throws {
        let tokenHex = deviceToken.map { String(format: "%02x", $0) }.joined()
        var req = URLRequest(url: URL(string: "\(baseURL)/api/push/subscribe")!)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("Bearer \(token!)", forHTTPHeaderField: "Authorization")
        req.httpBody = try JSONSerialization.data(withJSONObject: [
            "device_token": tokenHex,
            "platform": "ios",
            "label": UIDevice.current.name
        ])
        let (data, _) = try await URLSession.shared.data(for: req)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: String]
        UserDefaults.standard.set(json["api_key"], forKey: "sysmon_api_key")
    }
}

// AppDelegate:
func application(_ app: UIApplication,
                 didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
    Task { try? await SysmonClient().subscribe(deviceToken: deviceToken) }
}
```

### Android (Kotlin)

```kotlin
class SysmonClient(private val context: Context) {
    private val baseURL = "https://sysmon.example.com"
    private val prefs = context.getSharedPreferences("sysmon", Context.MODE_PRIVATE)

    fun login(username: String, password: String) {
        val body = JSONObject().put("username", username).put("password", password)
        val resp = post("/api/auth/login", body, includeAuth = false)
        prefs.edit().putString("token", resp.getString("token")).apply()
    }

    fun subscribe(fcmToken: String) {
        val body = JSONObject()
            .put("device_token", fcmToken)
            .put("platform", "android")
            .put("label", Build.MODEL)
        val resp = post("/api/push/subscribe", body)
        prefs.edit().putString("api_key", resp.getString("api_key")).apply()
    }

    private fun post(path: String, body: JSONObject, includeAuth: Boolean = true): JSONObject {
        val conn = (URL("$baseURL$path").openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
            if (includeAuth) {
                setRequestProperty("Authorization", "Bearer ${prefs.getString("token", "")}")
            }
        }
        conn.outputStream.write(body.toString().toByteArray())
        return JSONObject(conn.inputStream.bufferedReader().readText())
    }
}

class SysmonMessagingService : FirebaseMessagingService() {
    override fun onNewToken(token: String) {
        SysmonClient(this).subscribe(token)
    }
}
```

## Token Lifecycle

- **Login**: Get a session token. Store securely.
- **Subscribe**: Use session token to register device with sysmon.
  Receive an `api_key` per device. Store it.
- **Session expires (24h)**: Login again, get new token. The `api_key`
  remains valid and tied to the same device subscription.
- **OS issues new push token**: Subscribe again with the same session
  token but the new device_token. A new `api_key` is issued. Optionally
  unsubscribe the old token.
- **The transport declares the token dead**: FCM answers a send with
  `UNREGISTERED`; direct APNs answers HTTP 410 `Unregistered` — the
  same verdict in different clothes. It happens on app uninstall,
  cleared app data, restore to a new device, provider-side key
  rotations, or (FCM) after ~270 days of device inactivity. The
  verdict is permanent for that token string, and only the sender ever
  sees it — the device's own push SDK keeps returning the dead token
  from cache. The server reacts identically for both transports:
  flagging the subscription (`unregistered`, shown on the admin page
  as "token dead"), skipping it during alert fan-outs (per the
  providers' guidance to stop sending to dead tokens), and answering
  the app's next subscribe of that token with
  `token_status: "invalid"`. The apps (Android and iOS alike) then
  delete their cached token, mint a fresh one, and re-subscribe — the
  flagged row is replaced and delivery resumes. The row is kept (not deleted) exactly
  so this handshake can happen; an admin can still remove it manually
  via `DELETE /api/push/remove/<token>`. A test push to a flagged
  token is still attempted, and a success clears the flag.
  The handshake runs on every app launch/foreground AND once a day in
  the background (WorkManager on Android; BGTaskScheduler app refresh
  on iOS, so its timing rides the system's refresh budget) - a phone
  left in a drawer heals without anyone opening the app. The daily job
  is only scheduled while a login is stored: an installed-but-unpointed
  app does no background work at all.

## Database

bbolt at `/var/lib/sysmon/push.db`. Two buckets:

- **subscriptions** — keyed by `device_token`, value is JSON Subscription
  (with owner field linking to auth user)
- **push_log** — auto-incrementing sequence key, JSON log entry

Subscriptions persist across restarts. The push log grows over time
and has no auto-cleanup yet (planned).

## Troubleshooting

**"Login required" on every API call**
The session token expired (24h) or is wrong. Log in again.

**"device_token already registered to another account"**
Another user already subscribed this exact device token. The original
owner must unsubscribe first, or an admin can `DELETE /api/push/remove/<token>`.

**Subscribe returns 503 "Push notifications not configured"**
Either `config push-notifications;` is missing from sysmon.conf, or
sysmon-web couldn't open `/var/lib/sysmon/push.db`. Check the logs.

**One device shows "failed: token dead" and gets no alerts**
FCM refused that device's token with `UNREGISTERED` — the token is
gone for good (uninstall, cleared data, device restore, or the
270-day inactivity purge). The subscription is flagged (red "token
dead" badge on the admin page) and alert sends skip it. It heals
itself the next time the app is opened on that device: the launch-time
subscribe is answered with `token_status: "invalid"`, and the app
mints a fresh token and re-registers. If the device is genuinely gone,
kick the row via the admin page or `DELETE /api/push/remove/<token>`.

**Test push sent but not received**
- iOS: notification permissions in Settings > Notifications
- Android: battery optimization isn't blocking FCM
- Both: verify with `GET /api/push/me` that the device is registered
- Check `GET /api/push/log` (admin) for delivery failures

**Notifications delayed**
Watcher polls every 1 second, with a 1-second cache on GetStatus.
Worst case: ~2 seconds from state change to push send, plus APNs/FCM
transit time.
