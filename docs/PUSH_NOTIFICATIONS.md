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

### 1. Enable push in sysmon.conf

```
config push-notifications;
```

### 2. Configure FCM (Android)

sysmon-web uses the FCM HTTP v1 API. Authenticate with a Google
service-account JSON file:

1. Firebase Console → Project Settings → **Service accounts** → "Generate
   new private key". Save the downloaded JSON somewhere readable only by
   the sysmon-web process (e.g. `/var/lib/sysmon/fcm-credentials.json`,
   `chmod 600`, owned by the sysmon user).
2. Make sure the **Firebase Cloud Messaging API** is enabled in the
   matching Google Cloud project.
3. Point sysmon at the file:

```
config push-fcm-credentials-file "/var/lib/sysmon/fcm-credentials.json";
```

The project ID is read from the JSON; no separate config directive is
needed. sysmon-web mints short-lived OAuth access tokens transparently
and refreshes them automatically.

> The previous server-key (Legacy HTTP API) flow was shut down by Google
> in June 2024. Any `config push-fcm-serverkey "..."` directives in
> existing configs will be ignored and must be replaced.

### 3. Configure APNs (iOS)

Export your push certificate from the Apple Developer portal as `.p12`,
then convert to PEM:

```sh
openssl pkcs12 -in cert.p12 -out /etc/sysmon/apns-cert.pem -clcerts -nokeys
openssl pkcs12 -in cert.p12 -out /etc/sysmon/apns-key.pem -nocerts -nodes
chmod 600 /etc/sysmon/apns-key.pem
```

```
config push-apns-certfile "/etc/sysmon/apns-certificate.pem";
config push-apns-keyfile "/etc/sysmon/apns-key.pem";
config push-apns-bundleid "com.example.sysmon";
config push-apns-production;
```

Omit `push-apns-production` to use the APNs sandbox gateway.

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

### List my subscriptions

```
GET /api/push/me
Authorization: Bearer <token>
```

Returns only the current user's own subscriptions. `api_key` is
stripped from the response (the app already has it).

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
      "body": "router-core ping check failed"
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
    "body": "router-core ping check failed"
  },
  "data": {
    "hostname": "router-core",
    "status": "CRITICAL",
    "type": "ping"
  }
}
```

Recovery: title becomes `"router-core RECOVERED"`, body is
`"router-core is back up (was CRITICAL)"`.

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
- **App uninstall**: Subscription remains in the database but pushes
  to the dead token will fail silently. An admin can clean it up via
  `DELETE /api/push/remove/<token>`.

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

**Test push sent but not received**
- iOS: notification permissions in Settings > Notifications
- Android: battery optimization isn't blocking FCM
- Both: verify with `GET /api/push/me` that the device is registered
- Check `GET /api/push/log` (admin) for delivery failures

**Notifications delayed**
Watcher polls every 1 second, with a 1-second cache on GetStatus.
Worst case: ~2 seconds from state change to push send, plus APNs/FCM
transit time.
