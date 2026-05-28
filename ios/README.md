# Sysmon iOS App

Native SwiftUI app for sysmon. Login, view monitored hosts, receive
push notifications when hosts go down or recover.

## Requirements

- Xcode 15+
- iOS 16+
- An Apple Developer account (for push notifications)

## Setup

1. Open Xcode → File → New → Project → iOS → App
2. Product Name: `Sysmon`, Interface: SwiftUI, Language: Swift
3. Bundle Identifier: `com.yourcompany.sysmon` (must match what you
   configured in `sysmon.conf` as `config push-apns-bundleid`)
4. Delete the default `ContentView.swift` and `SysmonApp.swift` that
   Xcode created.
5. Drag every `.swift` file from `Sysmon/` into the project (check
   "Copy items if needed").
6. Replace the auto-generated `Info.plist` with the one in `Sysmon/`
   (or merge the keys: `UIBackgroundModes` with `remote-notification`).
7. Drag `Sysmon.entitlements` into the project. In Build Settings →
   Code Signing Entitlements, set the path to `Sysmon/Sysmon.entitlements`.
8. Signing & Capabilities → + Capability → Push Notifications
9. Build & Run on a real device (push notifications don't work in
   the simulator).

## Releasing to the App Store

Before archiving for App Store distribution, change `aps-environment` in
`Sysmon.entitlements` from `development` to `production` — or remove the
file and let Xcode manage entitlements automatically through Signing &
Capabilities.

## First Run

The app shows a login screen. Enter:
- **Server URL**: your sysmon-web hostname (e.g., `sysmon.example.com`
  or `https://sysmon.example.com`; `https://` is assumed if omitted)
- **Username** / **Password**: a user account you created via the
  web admin page (use `role: "user"`)

On successful login, the app requests push notification permission
and registers the device token with sysmon. From then on, you'll
receive a push whenever a monitored host changes state.

## Files

- `SysmonApp.swift` — app entry, routes between login and main view
- `AppDelegate.swift` — APNs token registration
- `Session.swift` — auth state, Keychain storage, push registration
- `API.swift` — typed HTTP client with Bearer auth and 401 handling
- `Models.swift` — Codable types matching the sysmon-web JSON API
- `LoginView.swift` — login form (server URL + username + password)
- `MainView.swift` — tab bar with Alerts / Hosts / Settings
- `SettingsView.swift` — account info, test push button, sign out

## Design

Inter-style system fonts (SF Pro), uppercase tracked labels, mono
data values, minimal color palette. Matches the sysmon web UI's
"editorial magazine" aesthetic.

## Troubleshooting

**Push notifications never arrive**
- Verify the bundle ID matches `config push-apns-bundleid` in `sysmon.conf`
- Verify the APNs cert in `config push-apns-certfile` was issued for
  the same bundle ID
- Check Settings → Notifications → Sysmon → enabled
- In Settings tab inside the app, tap "Send Test Notification"

**"Login required" on every action**
- Sessions stay alive as long as you keep using the app. They expire
  after 24 hours of inactivity, with a hard 30-day ceiling regardless
  of activity. Log in again.

**Server URL**
- Scheme is optional — `sysmon.example.com` is accepted and resolved
  to `https://sysmon.example.com`. Use `http://` explicitly only if
  your server is plain HTTP. Trailing slashes are stripped.
