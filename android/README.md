# Sysmon Android App

Native Jetpack Compose app for sysmon. Login, view monitored hosts,
receive Firebase Cloud Messaging push notifications when hosts go down
or recover.

## Requirements

- Android Studio Hedgehog (2023.1.1) or newer
- Android SDK 34 (compileSdk) / API 26+ device (minSdk)
- A Firebase project (free Spark tier is fine) for FCM push delivery

## Firebase Setup

1. Create a new Firebase project at https://console.firebase.google.com
2. Add an Android app to the project:
   - Package name: `com.sysmon.app` (must match `applicationId` in
     `app/build.gradle.kts` and `config push-fcm-package` in `sysmon.conf`
     if you set it)
3. Download the generated `google-services.json` and drop it at
   `android/app/google-services.json` (do NOT commit it — it's in
   `.gitignore`)
4. Project Settings → Cloud Messaging → copy the **Server key** (Legacy
   API). Put it in `sysmon.conf` as:
   ```
   config push-fcm-server-key <your-server-key>
   ```
   If the Legacy API is disabled in your project, enable it under
   Cloud Messaging → Manage API in Google Cloud Console.

## Building

Open `android/` in Android Studio. Sync Gradle. Run on a device or
emulator (push notifications require a device with Play Services).

Command line:

```sh
cd android
./gradlew :app:assembleDebug
./gradlew :app:installDebug
```

## First Run

The app shows a login screen. Enter:

- **Server URL**: your sysmon-web URL (e.g., `https://sysmon.example.com`)
- **Username** / **Password**: a user account you created via the
  web admin page (use `role: "user"`)

On successful login, the app requests notification permission
(Android 13+) and registers the FCM token with sysmon. From then on
you'll receive a push whenever a monitored host changes state.

## Files

```
android/
├── build.gradle.kts                  — root Gradle
├── settings.gradle.kts               — project settings
├── gradle.properties                 — AndroidX, parallel builds
└── app/
    ├── build.gradle.kts              — module Gradle (Compose, Firebase)
    ├── proguard-rules.pro            — R8 keep rules
    ├── google-services.json.example  — template; replace before building
    └── src/main/
        ├── AndroidManifest.xml
        ├── java/com/sysmon/app/
        │   ├── SysmonApplication.kt  — app init, notification channel
        │   ├── MainActivity.kt       — Compose entry + push permission
        │   ├── MessagingService.kt   — FirebaseMessagingService
        │   ├── Session.kt            — auth state, encrypted prefs
        │   ├── Api.kt                — HTTP client with Bearer auth
        │   ├── Models.kt             — kotlinx.serialization DTOs
        │   └── ui/
        │       ├── RootScreen.kt     — login/main routing
        │       ├── LoginScreen.kt
        │       ├── MainScreen.kt     — tab nav
        │       ├── AlertsScreen.kt
        │       ├── HostsScreen.kt
        │       ├── SettingsScreen.kt
        │       ├── Components.kt     — shared cards/headers/dots
        │       └── theme/Theme.kt    — Material3 + magazine typography
        └── res/
            ├── values/strings.xml
            ├── values/themes.xml
            └── xml/                  — backup config
```

## Design

Material3 with a custom typography scale: serif display weights for
headings, sans-serif body, monospace for data values. Uppercase
tracked labels mirror the sysmon web UI's editorial magazine style.

## Troubleshooting

**Push notifications never arrive**
- Verify the package name matches the Firebase app
- Verify the Server key in `sysmon.conf` is the **Cloud Messaging API
  (Legacy)** key, not the Web API key
- Settings → Apps → Sysmon → Notifications → enabled
- In the Settings tab inside the app, tap "Send Test Notification"

**"Session expired" on every action**
- Sessions stay alive as long as you keep using the app. They expire
  after 24 hours of inactivity, with a hard 30-day ceiling regardless
  of activity. Log in again.

**Server URL**
- Scheme is optional — `sysmon.example.com` is accepted and resolved
  to `https://sysmon.example.com`. Use `http://` explicitly only if
  your server is plain HTTP. Trailing slashes are stripped.

**Build fails: `google-services.json is missing`**
- Drop the real file (downloaded from Firebase Console) at
  `app/google-services.json`.
