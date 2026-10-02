# IntelFeed for Android

A native Android client (Kotlin, Jetpack Compose) for an IntelFeed server: the feed, reader, search, entity profiles, ATT&CK matrix, ransomware tracker, keyword alerts and notifications. It talks to the same REST API as the web frontend.

## Get the APK

Every new version is published on the repo's [Releases page](https://github.com/a-oneil/IntelFeed/releases) as `android-v<version>`, with the APK attached as `IntelFeed.apk`. On the phone, download it and allow installs from the browser when Android asks. Each version installs over the previous one and keeps your login and settings. The app shows its version at the bottom of **Settings**.

## How builds and releases work

The `android` job in `.github/workflows/ci.yml` runs when anything under `android/` changes. It runs the unit tests and builds the debug APK, and on every run the APK is attached to the workflow run as an artifact.

On `main` it also publishes a release, but only when `version.properties` holds a version that has no `android-v<version>` release yet. A change that doesn't bump the version still gets built and tested but isn't published, and the job summary says so. `tools/release_apk.sh "<what changed>"` bumps the version, builds, and records the release in `APK_VERSIONS.md`.

The APK is signed with the shared debug key from the `ANDROID_DEBUG_KEYSTORE` repository secret, so every release installs over the last one. Without that secret, CI still builds and tests, but it publishes nothing: an APK signed with a throwaway key would refuse to install over an existing copy.

## Where the code is edited

This folder is a copy of the app's working folder (`IntelFeed_App`, outside this repo), where most of the development happens. `tools/sync_to_github.sh "<what changed>"` opens a pull request that updates `android/` from there. Changes made here on GitHub are fine too: the next sync refuses to overwrite them until `tools/sync_to_github.sh --pull` has brought them back.

## Build locally

You need JDK 17 and the Android SDK (`local.properties` with `sdk.dir=`, or `ANDROID_HOME`).

```bash
cd android
./gradlew :app:testDebugUnitTest :app:assembleDebug   # APK: app/build/outputs/apk/debug/app-debug.apk
```

`claude_changes.md` is the detailed change log (written for the AI agents that work on the app). `APK_VERSIONS.md` lists every released version.
