# Building Network Audit (Android app)

The phone version of `tools/lan_agent.py`. On site, connected to the building's Wi-Fi, it checks the router's
management ports, which devices expose file shares / Remote Desktop / cameras / printers to the network, UPnP and
latency, then uploads the results to the grader with the customer's API key. Only audit networks you're authorised to test.

How customers use it is explained on the website at `/network-audit` (linked from the Dashboard and Account pages).

## Building the APK

Needs the Flutter SDK (3.47 or newer) and the Android SDK (platform 36). Then:

```
cd mobile_app
flutter test                    # widget tests
flutter build apk --release     # -> build/app/outputs/flutter-apk/app-release.apk
copy build\app\outputs\flutter-apk\app-release.apk ..\tools\building-network-audit.apk
```

Copying it to `tools/building-network-audit.apk` puts it on the website at `/downloads/building-network-audit.apk`
(the AlmaLinux installer copies `tools/` to the server).

## Signing

The release build is currently signed with Flutter's debug key, which is fine for installing from the website
("unknown apps"). Before publishing on Google Play, create your own upload key and configure it in
`android/app/build.gradle.kts` (see https://docs.flutter.dev/deployment/android#sign-the-app). Keep that key safe:
updates must be signed with the same key.

## iPhone

Not built. iOS apps need a Mac with Xcode and an Apple developer account, and can only be installed through the
App Store or TestFlight. Technicians with iPhones can use the laptop agent instead.
