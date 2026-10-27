# IntelFeed for Android

*Last verified: 2026-10-27 (app version 1.5, build 6)*

This page is for anyone who wants to install the Android app, or build and
release it. It covers what the app does, how to get it, how to build it, and
how CI publishes a new version.

The app is a native Android client (Kotlin, Jetpack Compose) for an IntelFeed
server. It talks to the same REST API as the web app and uses the same
accounts, feeds, entities, notes, tags and campaigns. The source is in
[`android/`](../android/).

It is a **mobile companion**, not a copy of the web app. It covers reading and
triage, search, entity profiles and a read-only part of the workbench.
Dashboards, detection-rule authoring, automation, reports, the copilot and the
admin pages are web-only.

---

## Get the APK

Each app version is published on the repo's
[Releases page](https://github.com/a-oneil/IntelFeed/releases) as
`android-v<version>`, with the installer attached as `IntelFeed.apk`.

1. On the phone, open the release and download `IntelFeed.apk`.
2. Allow installs from the browser when Android asks. The app is installed
   from a file (sideloaded), not from the Play Store.
3. Open the file. A new version installs over the old one and keeps your
   login and settings.

The app shows its version at the bottom of **Settings**, for example
"IntelFeed for Android 1.5 (build 6)".

While the repo is private, downloading a release needs a GitHub account with
access to it.

Every CI run of the `android` job also attaches the APK it built to the run
as an artifact named `IntelFeed-<version>-apk`, kept for 30 days. Use that to
try a build from a PR that is not merged yet.

---

## What the app does

| Area | What is there |
| --- | --- |
| **Sign-in** | Server address plus username and password (`POST /api/auth/login`). The app refreshes its token when the server answers 401. There is no built-in server: you type your own instance's address. |
| **Feed** | Priority Queue, quick views (last 24h, starred, bookmarked, watched), the folder and feed tree with unread counts, articles grouped by day with day summaries and intel chips, list and grid layouts, a time-range picker. Mark read or unread, star, bookmark, mark all read, bulk actions. |
| **Reader** | Cleaned-up article HTML, badges for the intelligence found in the article (actors, malware, CVEs, CWEs, TTPs, vendors, products, tools, countries, observables, mitigations), entity previews, similar articles, notes, tags, add to campaign, share, open in browser. |
| **Read aloud** | Text-to-speech on the phone, with a choice of voice (`ui/reader/ArticleSpeaker.kt`). URLs, hashes and code are rewritten so they read sensibly. |
| **Translation** | Translation on the phone with Google ML Kit (`util/ArticleTranslator.kt`). Language models download the first time you use them. |
| **Search** | Unified search (`POST /api/search/unified`) with autocomplete, search operators and saved searches. |
| **Entity profiles** | A profile for each entity type: description, mentions over time, timeline, relationship graph (`ui/entity/EntityGraphView.kt`), story threads, "what's new", watchlist and entity notes. |
| **Story threads** | Open a thread from a Priority Queue story row or a similar-article link. |
| **Workbench** | ATT&CK matrix (`ui/workbench/AttackMatrixView.kt`) and the ransomware victim tracker (`ui/workbench/RansomwareView.kt`). Both are read-only. |
| **Requirements** | The server's intelligence requirements and the articles that match them. |
| **Alerts** | Keyword alerts, checked in the background about every 15 minutes (`notifications/IntelNotificationWorker.kt`). Tapping one opens the matching article. |
| **Share to IntelFeed** | Share an http(s) link from a browser and pick "Add to IntelFeed". After you confirm, the app adds the page as an article (`POST /api/entries/ingest/url`). |
| **Languages** | English, Spanish, French, German, Ukrainian, Russian, Chinese, Japanese, Portuguese and Italian (`ui/i18n/AppStrings.kt`). |

Every endpoint the app calls is listed in the Retrofit interface
`android/app/src/main/java/com/example/intelfeed/data/network/IntelFeedApi.kt`
(111 at version 1.5). The app uses no endpoint that the web app does not also
use.

---

## Security

- **Tokens.** The login tokens are stored encrypted, with a key held in the
  Android Keystore (`data/local/TokenCipher.kt`). Backups and phone-to-phone
  transfer of that file are turned off (the manifest and the backup rules in
  `res/xml/`).
- **TLS.** `res/xml/network_security_config.xml` allows plain `http://` and
  certificates you installed yourself, so a self-hosted server on a home or
  office network works. The login screen warns when the address starts with
  `http://`.
- **Server address.** `data/network/ServerUrl.kt` cleans up what you type,
  adds `https://` when you leave the scheme out, and refuses an address with a
  username or password in it.
- **Other apps.** `MainActivity` accepts the launcher and the share sheet but
  ignores any navigation data another app sends. Notification taps go through
  `NotificationRouteActivity`, which other apps cannot start, so they cannot
  push the app to a page. Broken share data is dropped instead of crashing
  the app.
- **Logging.** Request lines are written to the Android log (logcat) only in
  debug builds. The released APK **is** a debug build (see
  [The signing key](#the-signing-key)), so released installs log them too.

---

## Build locally

You need JDK 17 and the Android SDK (set `ANDROID_HOME`, or put `sdk.dir=` in
`android/local.properties`). The Gradle wrapper (9.1) is in the repo and
downloads itself.

```bash
# On your machine, from the repo root
cd android
./gradlew :app:testDebugUnitTest :app:assembleDebug
# APK: android/app/build/outputs/apk/debug/app-debug.apk
```

| Setting | Value | Where |
| --- | --- | --- |
| Application id | `cc.intelfeed.app` | `app/build.gradle.kts` |
| Package namespace | `com.example.intelfeed` | `app/build.gradle.kts` |
| minSdk / targetSdk / compileSdk | 24 / 36 / 36 | `app/build.gradle.kts` |
| Android Gradle plugin / Kotlin | 9.0.1 / 2.3.20 | `gradle/libs.versions.toml` |
| Version | `versionCode` + `versionName` | `version.properties` |

The tests are JVM unit tests in `app/src/test/`: API-contract and
serialization tests against a mock server, URL and date helpers, keyword
alerts, navigation routes, and the matrix and ransomware screens. There is one
on-device test in `app/src/androidTest/`. CI does not run it, because it needs
an emulator.

---

## Versioning and releases

The version lives in one place, `android/version.properties`, and
`app/build.gradle.kts` reads it. `versionCode` must only go up: Android will
not install a lower one over a higher one.

The `android` CI job:

1. Runs when anything under `android/` or `.github/workflows/ci.yml` changes,
   on PRs and on pushes to `main`. It also runs on a manual run of the
   workflow. It is skipped on the Monday security sweep.
2. Loads the shared signing key from the `ANDROID_DEBUG_KEYSTORE` secret (see
   below), then runs the unit tests and builds the debug APK in one Gradle run
   on JDK 17.
3. Checks that the APK is signed with the shared key, and fails if not.
4. Attaches the APK to the run as an artifact.
5. On `main` only, if no `android-v<versionName>` release exists yet,
   publishes a GitHub release with that tag. The release has the APK, its
   SHA-256, and the merge commit's subject as the notes. A merge that does not
   change the version is built and tested but not released. The job summary
   says which happened.

To release a new version:

```bash
# On your machine, from the repo root
scripts/build_apk.sh            # bump the version (1.x -> 1.x+1), test, build,
                                # install on connected phones
scripts/build_apk.sh --major    # bump 1.x -> 2.0 instead
scripts/build_apk.sh --install  # only install the last build on connected phones
```

The APK stays at `android/app/build/outputs/apk/debug/app-debug.apk`. If no
phone is connected, the script tells you to plug one in with USB debugging on
and run it again with `--install`. If the build or tests fail, the script puts
the old version number back, so a number is never used up.

Then commit `android/version.properties`, open a PR titled
`android: <what changed>` (that title becomes the release notes), and merge.

### The signing key

Android only installs an update over an app signed with the same key. All
releases are signed with one shared debug keystore, so CI must use it too, or
the update fails with "App not installed". CI decodes the secret into its own
folder and points `ANDROID_USER_HOME` at it, which is the first place the
Android Gradle plugin looks for `debug.keystore`. After the build it compares
the certificate in the APK with the one in the keystore and fails the job if
they differ, so a release can never ship with a key the phones do not have.

Releases start at 1.3, the first version signed with the shared key.

To set the secret (repo admin, once):

```bash
# On your machine, with the keystore file in the current folder
base64 -i debug.keystore | gh secret set ANDROID_DEBUG_KEYSTORE -R a-oneil/IntelFeed
```

Then delete the local copy of the keystore. Without the secret the job still
builds and tests, but it publishes nothing and logs a warning. If a version
was merged before the secret was set, run the workflow again on `main`
(Actions → CI → Run workflow) and it will publish.

A local build (`scripts/build_apk.sh`) is signed with that machine's own
`~/.android/debug.keystore`. To install a local build over the released app,
or the other way round, put the shared keystore at that path. Back up the
existing file first: it is the debug key for every Android project built on
that machine.

The released APK is a **debug build** signed with a debug key. That works
while the only users are the developers' phones, but it means the app is
debuggable, not minified, and logs request lines. Moving to a release build
needs a real signing key, a one-time reinstall for everyone, and
`assembleRelease` in CI.

---

## Where the code is edited

`android/` is edited in this repo like everything else: branch, commit, PR
against `main`. Documentation for the app is this file. The release history
is the Releases page.

### `.gitignore` notes

- The root `.gitignore` ignores `data/` folders at any depth (backend runtime
  data), which would also hide the app's `data` source package.
  `android/.gitignore` adds it back with `!data/`, so files under
  `app/src/main/java/com/example/intelfeed/data/` are tracked normally.
- Keystores (`*.keystore`, `*.jks`, `*.p12`) and built packages (`*.apk`,
  `*.aab`) are ignored both in `android/` and at the repo root, so a keystore
  dropped anywhere in the checkout cannot be committed by accident.
  `android/.gitignore` also ignores `local.properties`, build output, and
  Gradle and IDE files.

---

## Related docs

- [api-reference.md](api-reference.md) for the endpoints the app calls.
- [guide/reading-and-triage.md](guide/reading-and-triage.md) and
  [guide/priority-queue.md](guide/priority-queue.md) for the web screens the
  app follows.
- [contributing.md](contributing.md) for how CI is laid out.
