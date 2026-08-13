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
     `app/build.gradle.kts`)
3. Download the generated `google-services.json` and drop it at
   `android/app/google-services.json` (do NOT commit it - it's in
   `.gitignore`). This is the client-side Firebase config bundled into
   the Android app.
4. Project Settings → **Service accounts** → "Generate new private key".
   This downloads a *different* JSON (a service-account key, with
   `"type": "service_account"`). Don't deploy it to disk - upload it
   through the sysmon-web admin UI: **Admin** → **Push Configuration**
   → **Upload service-account JSON**. sysmon-web uses the FCM HTTP v1
   API; the older Server Key (Legacy HTTP API) was shut down by Google
   in June 2024.

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

The registration repeats on every app launch - and once a day in the
background via WorkManager - and the server's reply carries a verdict:
if FCM has refused the token with `UNREGISTERED` since the last check
(uninstall/reinstall, cleared data, device restore, or the 270-day
inactivity purge - the Firebase SDK itself never finds out and keeps
serving the dead token from cache), the app deletes the cached token,
mints a fresh one, and re-registers automatically. No user action
needed; even a phone that sits unopened heals within a day.

## Files

```
android/
├── build.gradle.kts                  - root Gradle
├── settings.gradle.kts               - project settings
├── gradle.properties                 - AndroidX, parallel builds
└── app/
    ├── build.gradle.kts              - module Gradle (Compose, Firebase)
    ├── proguard-rules.pro            - R8 keep rules
    ├── google-services.json.example  - template; replace before building
    └── src/main/
        ├── AndroidManifest.xml
        ├── java/com/sysmon/app/
        │   ├── SysmonApplication.kt  - app init, notification channel
        │   ├── MainActivity.kt       - Compose entry + push permission
        │   ├── MessagingService.kt   - FirebaseMessagingService
        │   ├── Session.kt            - auth state, encrypted prefs
        │   ├── Api.kt                - HTTP client with Bearer auth
        │   ├── Models.kt             - kotlinx.serialization DTOs
        │   └── ui/
        │       ├── RootScreen.kt     - login/main routing
        │       ├── LoginScreen.kt
        │       ├── MainScreen.kt     - tab nav
        │       ├── AlertsScreen.kt
        │       ├── HostsScreen.kt
        │       ├── SettingsScreen.kt
        │       ├── Components.kt     - shared cards/headers/dots
        │       └── theme/Theme.kt    - Material3 + magazine typography
        └── res/
            ├── values/strings.xml
            ├── values/themes.xml
            └── xml/                  - backup config
```

## Design

Material3 with a custom typography scale: serif display weights for
headings, sans-serif body, monospace for data values. Uppercase
tracked labels mirror the sysmon web UI's editorial magazine style.

## Troubleshooting

**Push notifications never arrive**
- Verify the package name matches the Firebase app
- Open sysmon-web → **Admin** → **Push Configuration**. The FCM panel
  should show **project id**, **service-account email**, and a key id.
  If it's empty, re-upload the service-account JSON.
- The project id shown there must match the `project_id` in your
  Android-side `google-services.json`.
- Verify the **Firebase Cloud Messaging API** (not the old Legacy HTTP
  API) is enabled in Google Cloud Console for that project.
- Settings → Apps → Sysmon → Notifications → enabled.
- In the Settings tab inside the app, tap "Send Test Notification".

**"Session expired" on every action**
- Once you sign in, the session stays alive for as long as you keep
  opening the app. Sysmon-web only forgets you if the app hasn't been
  used in over 30 days. Log in again.

**Server URL**
- Scheme is optional - `sysmon.example.com` is accepted and resolved
  to `https://sysmon.example.com`. Use `http://` explicitly only if
  your server is plain HTTP. Trailing slashes are stripped.

**Build fails: `google-services.json is missing`**
- Drop the real file (downloaded from Firebase Console) at
  `app/google-services.json`.
