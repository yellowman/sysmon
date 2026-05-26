# sysmon Push Notifications Guide

Push notifications deliver real-time mobile alerts when monitored hosts
change state. The sysmon web-ui backend polls the C daemon every second,
detects state transitions, and pushes alerts to all subscribed iOS and
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
    +-- bbolt database (subscriptions + push log)
```

The Go backend is the only component that talks to Apple/Google.
Mobile apps register once, then receive alerts passively.

Subscriptions are stored in a bbolt embedded database (the same
key-value store used by etcd and Kubernetes). Pure Go, no cgo,
single-file database that persists across restarts.

## Server Setup

### 1. Enable push in sysmon.conf

Add these directives to your `sysmon.conf`. The C daemon accepts and
ignores them; the Go web-ui backend reads and acts on them.

```
config push-notifications;
```

### 2. Configure FCM (Android)

Get a server key from Firebase Console > Project Settings > Cloud Messaging.

```
config push-fcm-serverkey "AAAAxxxxxxx:APA91bxxxxxxxxxxxxxxxxxxxxxxxxx";
```

### 3. Configure APNs (iOS)

Export your push certificate from the Apple Developer portal as a `.p12`
file, then convert to PEM:

```sh
openssl pkcs12 -in cert.p12 -out /etc/sysmon/apns-cert.pem -clcerts -nokeys
openssl pkcs12 -in cert.p12 -out /etc/sysmon/apns-key.pem -nocerts -nodes
chmod 600 /etc/sysmon/apns-key.pem
```

Then configure:

```
config push-apns-certfile "/etc/sysmon/apns-cert.pem";
config push-apns-keyfile "/etc/sysmon/apns-key.pem";
config push-apns-bundleid "com.example.sysmon";
config push-apns-production;
```

Omit `push-apns-production` to use the APNs sandbox (development) gateway.

### 4. Database directory

The web-ui stores subscriptions and push history in a bbolt database
file. The default path is `/var/lib/sysmon/push.db`. Make sure the
directory exists and is writable by the sysmon-web process:

```sh
mkdir -p /var/lib/sysmon
chown www-data:www-data /var/lib/sysmon
```

The database is created automatically on first run. Subscriptions
persist across restarts. The file is a single bbolt B+ tree — no
external database process needed.

### 5. Restart sysmon-web

After changing `sysmon.conf`, restart the web-ui backend. It reads
push configuration at startup. You should see:

```
push: FCM client initialized
push: APNs client initialized (production, bundle: com.example.sysmon)
push: database opened at /var/lib/sysmon/push.db (0 subscriptions)
push: state change watcher started (1s poll interval)
```

## API Reference

All endpoints are on the sysmon web-ui base URL
(e.g., `https://sysmon.example.com`).

### Authentication

Push endpoints use two layers of auth:

1. **Global authkey** (from `config authkey` in sysmon.conf) — required to
   subscribe new devices and list all subscriptions. This is the same key
   used for admin operations in the web UI. Pass it via `X-Auth-Key` header.

2. **Per-device API key** — returned on subscribe, unique to each device.
   Required for unsubscribe and test. This prevents one device from
   managing another device's subscription. The app must store this key.

If no authkey is configured in sysmon.conf, subscribe and list are open
(per-device API keys still apply for unsubscribe/test).

### Subscribe a device

```
POST /api/push/subscribe
X-Auth-Key: <sysmon authkey>
Content-Type: application/json

{
  "device_token": "<token from OS>",
  "platform": "ios" or "android",
  "label": "Chris's iPhone"
}
```

- `device_token` (required): The token from APNs or FCM.
- `platform` (required): `"ios"` or `"android"`.
- `label` (optional): Human-readable name for identifying the device.

If the token already exists, platform and label are updated but the
same API key is returned.

Response:
```json
{"status": "subscribed", "api_key": "a1b2c3d4e5f6..."}
```

**The app must store `api_key`** — it's needed for unsubscribe and test.

### Unsubscribe a device

```
DELETE /api/push/subscribe
Content-Type: application/json

{
  "device_token": "<token>",
  "api_key": "<api_key from subscribe>"
}
```

The API key must match the one issued for this device token.

Response: `{"status": "unsubscribed"}`

### List subscriptions (admin)

```
GET /api/push/subscriptions
X-Auth-Key: <sysmon authkey>
```

Requires the global authkey. API keys are not included in the response.
Returns full metadata for each device: when it enrolled, when it last
checked in, push delivery stats, source IP, and user agent.

Response:
```json
{
  "subscriptions": [
    {
      "device_token": "abc123...",
      "platform": "ios",
      "label": "Chris's iPhone",
      "created_at": "2025-05-26T21:00:00Z",
      "last_seen": "2025-05-26T22:15:00Z",
      "last_push_at": "2025-05-26T22:14:58Z",
      "last_push_status": "ok",
      "push_count": 47,
      "fail_count": 0,
      "ip_address": "192.168.1.42",
      "user_agent": "SysmonApp/1.0 iOS/18.0"
    }
  ],
  "count": 1
}
```

### Send a test notification

```
POST /api/push/test
Content-Type: application/json

{"api_key": "<api_key from subscribe>"}
```

Looks up the device by its API key and sends a test push. No need to
specify token or platform — the backend resolves them from the key.

Response: `{"status": "sent"}`

### Admin: remove a device (kick)

```
DELETE /api/push/remove/<device_token>
X-Auth-Key: <sysmon authkey>
```

Forcibly removes a subscription. The device will stop receiving alerts
immediately. Use this to kick lost/stolen devices or clean up dead tokens.

Response: `{"status": "removed", "device_token": "..."}`

### Admin: push notification log

```
GET /api/push/log?limit=50
X-Auth-Key: <sysmon authkey>
```

Returns the most recent push notifications sent, newest first. Each
entry shows which host triggered it, the status transition, and how
many devices received it.

Response:
```json
{
  "entries": [
    {
      "timestamp": "2025-05-26T22:15:03Z",
      "hostname": "router-core",
      "status": "CRITICAL",
      "prev_status": "OK",
      "recipients": 3
    }
  ],
  "count": 1
}
```

## Notification Payloads

When a monitored host changes state (OK -> CRITICAL, CRITICAL -> OK, etc.),
the backend sends a push to every subscribed device.

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

### Recovery

```
title: "router-core RECOVERED"
body:  "router-core is back up (was CRITICAL)"
```

The `data` payload on Android is available for building richer UIs
(tap-to-open host detail, color-code by severity) but basic alert
display works with zero custom notification handling.

## Mobile App Integration

### iOS (Swift)

```swift
// 1. Request permission
UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { granted, _ in
    guard granted else { return }
    DispatchQueue.main.async { UIApplication.shared.registerForRemoteNotifications() }
}

// 2. Register token with sysmon
func application(_ app: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
    let token = deviceToken.map { String(format: "%02x", $0) }.joined()
    let sysmonURL = "https://sysmon.example.com"
    let authKey = "your-sysmon-authkey"  // from config authkey in sysmon.conf

    var req = URLRequest(url: URL(string: "\(sysmonURL)/api/push/subscribe")!)
    req.httpMethod = "POST"
    req.setValue("application/json", forHTTPHeaderField: "Content-Type")
    req.setValue(authKey, forHTTPHeaderField: "X-Auth-Key")
    req.httpBody = try? JSONSerialization.data(withJSONObject: [
        "device_token": token,
        "platform": "ios",
        "label": UIDevice.current.name
    ])

    URLSession.shared.dataTask(with: req) { data, _, _ in
        guard let data = data,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: String],
              let apiKey = json["api_key"] else { return }
        // Store apiKey in Keychain — needed for unsubscribe and test
        UserDefaults.standard.set(apiKey, forKey: "sysmon_api_key")
    }.resume()
}

// 3. That's it. Notifications arrive via APNs automatically.
```

### Android (Kotlin)

```kotlin
// build.gradle: implementation("com.google.firebase:firebase-messaging:24.0.0")

class SysmonMessagingService : FirebaseMessagingService() {
    override fun onNewToken(token: String) {
        val json = JSONObject().apply {
            put("device_token", token)
            put("platform", "android")
            put("label", Build.MODEL)
        }

        val url = URL("https://sysmon.example.com/api/push/subscribe")
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setRequestProperty("X-Auth-Key", "your-sysmon-authkey")
        conn.doOutput = true
        conn.outputStream.write(json.toString().toByteArray())

        val response = JSONObject(conn.inputStream.bufferedReader().readText())
        val apiKey = response.getString("api_key")
        // Store apiKey in SharedPreferences — needed for unsubscribe and test
        getSharedPreferences("sysmon", MODE_PRIVATE)
            .edit().putString("api_key", apiKey).apply()
    }

    // Notifications with a "notification" payload are shown automatically
    // by the system tray. No onMessageReceived override needed for basic alerts.

    // For custom handling (tap action, rich UI):
    override fun onMessageReceived(message: RemoteMessage) {
        val hostname = message.data["hostname"]
        val status = message.data["status"]
        // Build custom notification or update in-app state
    }
}
```

## Token Lifecycle

- **Registration**: Call `POST /api/push/subscribe` with `X-Auth-Key`
  on every app launch. The endpoint uses upsert — re-registering the
  same token returns the same `api_key` and updates the label.

- **Store the api_key**: The app must persist the `api_key` returned
  by subscribe (Keychain on iOS, SharedPreferences on Android). It's
  needed for unsubscribe and test.

- **Token refresh**: When the OS issues a new token, subscribe with the
  new token (same authkey). You get a new api_key for the new token.
  Optionally unsubscribe the old token using its old api_key.

- **Uninstall**: The subscription remains in the database but pushes
  to a dead token will fail silently (APNs 410 Gone, FCM NotRegistered).

## Database

Subscriptions and push history are stored in a bbolt database at
`/var/lib/sysmon/push.db` (configurable). bbolt is the embedded
key-value store used by etcd and Kubernetes — pure Go, single file,
ACID transactions, zero configuration.

Two buckets:

- **subscriptions** — keyed by device token, value is JSON:
  `{"device_token":"...","platform":"ios","label":"...","created_at":"..."}`

- **push_log** — keyed by auto-incrementing sequence, value is JSON:
  `{"timestamp":"...","hostname":"...","status":"...","prev_status":"...","recipients":3}`

The push log records every notification sent, which host triggered it,
and how many devices received it. Useful for debugging delivery issues.

## Troubleshooting

**"push: notifications disabled in config"**
Add `config push-notifications;` to sysmon.conf and restart sysmon-web.

**"push: no FCM or APNs credentials configured"**
At least one of FCM server key or APNs cert/key/bundle must be configured.

**"push: WARNING: APNs client init failed"**
Check that the cert and key PEM files exist and are readable. Verify
they haven't expired: `openssl x509 -in apns-cert.pem -noout -dates`

**Test notification sent but not received**
- iOS: Check notification permissions in Settings > Notifications.
- Android: Check battery optimization isn't blocking FCM.
- Both: Verify the device token is correct with `GET /api/push/subscriptions`.
- Try `POST /api/push/test` and check sysmon-web logs for errors.

**Notifications delayed**
The watcher polls sysmond every 1 second. GetStatus results are cached
for 1 second. Worst case latency is ~2 seconds from state change to
push delivery (plus APNs/FCM transit time).

**Database location**
Default: `/var/lib/sysmon/push.db`. To use a different path, modify the
`push.NewService()` call in `cmd/sysmon-web/main.go`.
