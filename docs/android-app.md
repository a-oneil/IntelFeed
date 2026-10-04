# IntelFeed for Android

*Last verified: 2026-10-03 (app version 1.2, build 3)*

A native Android client (Kotlin, Jetpack Compose) for an IntelFeed server. It
talks to the same REST API as the web frontend and reuses the server's
accounts, feeds, entities, notes, tags and campaigns. The source lives in
[`android/`](../android/) and is built, tested and released by the `android`
job in `.github/workflows/ci.yml`.

The app is a **mobile companion**, not a port of the web UI. It covers the
reading and triage loop, search, entity dossiers and a read-only slice of the
workbench. Dashboards, detection-rule authoring, automation, reports, the
copilot and the admin surfaces are web-only.

---

## Get the APK

Every new app version is published on the repo's
[Releases page](https://github.com/a-oneil/IntelFeed/releases) as
`android-v<version>`, with the installer attached as `IntelFeed.apk`.

1. On the phone, open the release and download `IntelFeed.apk`.
2. Allow installs from the browser when Android asks (it is a sideload, not a
   Play Store install).
3. Open the file. Each version installs over the previous one and keeps the
   login and settings.

The app shows its version at the bottom of **Settings**
("IntelFeed for Android 1.2 (build 3)").

The repo is private, so release downloads need a GitHub account with access to
it. Making the APK public means either making this repo public or publishing
the releases from a separate public repo (which needs a token secret).

Every CI run of the `android` job also attaches the APK it built as a workflow
artifact (`IntelFeed-<version>-apk`, kept 30 days), released or not. That is
the place to grab a build from an unmerged PR.

---

## What the app does

| Area | What is there |
| --- | --- |
| **Sign-in** | Server address + username/password against `POST /api/auth/login`; JWT refresh on 401. The default server is `https://intelfeed.cc`; any self-hosted address works. |
| **Feed** | Priority Queue, quick views (last 24h, starred, bookmarked, watched), the category and feed tree with unread counts, day grouping with day summaries and intel chips, list/grid layouts, a time-range picker. Mark read/unread, star, bookmark, mark-all-read, bulk actions. |
| **Reader** | Sanitised article HTML (jsoup), extracted-intelligence badges (actors, malware, CVEs, CWEs, TTPs, vendors, products, tools, countries, observables, mitigations), entity previews, similar articles, notes, tags, add-to-campaign, share, open in browser. |
| **Read aloud** | On-device TTS with voice selection (`ui/reader/ArticleSpeaker.kt`) and text preprocessing so URLs, hashes and code read sensibly. |
| **Translation** | On-device translation with Google ML Kit (`util/ArticleTranslator.kt`). Models download on first use. |
| **Search** | Unified search (`POST /api/search/unified`) with autocomplete, operators, saved searches. |
| **Entity profiles** | Dossier per entity type with description, mentions timeseries, timeline, relationship graph (`ui/entity/EntityGraphView.kt`), story threads, "what's new", watchlist and entity notes. |
| **Story threads** | Open a thread from a Priority Queue story row or a similar-article link. |
| **Workbench** | ATT&CK matrix (`ui/workbench/AttackMatrixView.kt`) and the ransomware victim tracker (`ui/workbench/RansomwareView.kt`), both read-only. |
| **Requirements** | The server's intelligence requirements and their matches. |
| **Alerts** | Keyword alerts checked in the background about every 15 minutes with WorkManager (`notifications/IntelNotificationWorker.kt`). A tap opens the matching article through a non-exported route activity, so other apps cannot inject a route. |
| **Share to IntelFeed** | Sharing an http(s) link from a browser offers "Add to IntelFeed", which ingests it via `POST /api/entries/ingest/url` after confirmation. |
| **Languages** | UI strings in English, Spanish, French, German, Ukrainian, Russian, Chinese, Japanese, Portuguese and Italian (`ui/i18n/AppStrings.kt`). |

The full list of endpoints the app calls is the Retrofit interface in
`android/app/src/main/java/com/example/intelfeed/data/network/IntelFeedApi.kt`
(107 operations at version 1.2). Nothing in the app needs an endpoint the web
frontend does not already use.

---

## Security posture

- **Tokens.** The access and refresh tokens live in DataStore, encrypted with
  a key in the Android Keystore (`data/local/TokenCipher.kt`). Backups and
  device-to-device transfer of that file are disabled in the manifest and the
  `res/xml` backup rules.
- **TLS.** `res/xml/network_security_config.xml` forbids cleartext and trusts
  only system certificate authorities for `intelfeed.cc`. Every other host (a
  self-hosted instance on a LAN) may use cleartext and user-installed CAs; the
  login screen warns when the address is `http://`.
- **Server address.** `data/network/ServerUrl.kt` normalises what the user
  types, defaults to `https`, and rejects addresses with embedded credentials.
- **Intents.** `MainActivity` is exported for the launcher and the share
  sheet but ignores route extras; notification taps go through the private
  `NotificationRouteActivity`. Malformed share extras are dropped, not crashed on.
- **Logging.** The OkHttp logging interceptor runs only when
  `BuildConfig.DEBUG` is true. Note that the released APK **is** a debug
  build (see below), so request lines are written to logcat on released
  installs.

---

## Build locally

Requirements: JDK 17 and the Android SDK (either `ANDROID_HOME` or a
`local.properties` with `sdk.dir=`). The Gradle wrapper (9.1) is committed and
downloads itself.

```bash
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

Tests are JVM unit tests under `app/src/test/` (serialization and API-contract
tests against a MockWebServer, URL and date utilities, keyword alerts, route
codec, matrix and ransomware view models). There is one instrumented test under
`app/src/androidTest/`, which CI does not run (it needs an emulator).

---

## Versioning and releases

`android/version.properties` is the single place the version lives;
`app/build.gradle.kts` reads it. `versionCode` must only ever go up, because
Android refuses to install a lower one over a higher one.

The `android` CI job:

1. runs when anything under `android/` or `ci.yml` changes, on PRs and on
   pushes to `main`. It is skipped on the Monday advisory sweep.
2. restores the shared signing key from the `ANDROID_DEBUG_KEYSTORE` secret
   (see below), then runs the unit tests and `assembleDebug` in one Gradle
   invocation on JDK 17 with `gradle/actions/setup-gradle` caching.
3. uploads the APK as a workflow artifact.
4. on `main` only, and only if no `android-v<versionName>` release exists
   yet, publishes a GitHub release with that tag, the APK, the SHA-256 and the
   merge commit's subject as the notes. A merge that does not bump the version
   is built and tested but not released; the job summary says which happened.

So the release flow is: bump `version.properties` (in the working folder,
`tools/release_apk.sh "<what changed>"` does it and runs the tests), open the
sync PR, merge. One release per app version, named after the version.

### The signing key

Android only installs an update over an app signed with the same key. Every
APK so far was signed with one shared debug keystore, so CI must sign with it
too, or the release would refuse to install over existing copies. CI writes
the secret to `~/.android/debug.keystore`, which is where the Android Gradle
plugin looks for the debug key.

Setting it (repo admin, once):

```bash
base64 -i debug.keystore | gh secret set ANDROID_DEBUG_KEYSTORE -R a-oneil/IntelFeed
```

Then delete the local copy of the keystore. Without the secret the job still
builds and tests but publishes nothing and logs a warning. If a version was
merged before the secret existed, re-run the CI workflow on `main`
(Actions → CI → Run workflow) and it will publish.

The released APK is a **debug build** signed with a debug key. That is the
right choice while the install base is the developers' phones, but it means
the app is debuggable, unminified, and logs request lines. Moving to a
release build needs a real upload key, a one-time reinstall for everyone, and
`assembleRelease` in CI.

---

## Where the code is edited

Most development happens in a separate working folder (`IntelFeed_App`,
outside this repo) where Kurt, Claude and Gemini work. Two scripts in
[`android/tools/`](../android/tools/) bridge the two:

- `sync_to_github.sh "<what changed>"` opens or updates a PR from the branch
  `android-sync` that replaces `android/` with the working folder's last
  commit.
- `sync_to_github.sh --pull` brings changes merged here on GitHub back into
  the working folder. The push refuses to run until this has happened, so
  edits made directly in this repo are never silently overwritten.

Squash-merging sync PRs is fine; the scripts compare tree hashes, not commit
history.

The working folder keeps its own markdown logs (`claude_changes.md`,
`codex_changes.md`, `APK_VERSIONS.md`, implementation reviews). Those are
deliberately **not** in this repo: documentation for the app lives here, in
`docs/`, and the release history is the Releases page. The sync script must
exclude them, otherwise the next sync re-adds them.

### `.gitignore` notes

- The root `.gitignore` ignores `data/` at any depth (backend runtime data),
  which would hide the app's `data` source package. `android/.gitignore`
  re-includes it with `!data/`, so new files under
  `app/src/main/java/com/example/intelfeed/data/` are tracked normally.
- Keystores (`*.keystore`, `*.jks`, `*.p12`), built packages (`*.apk`,
  `*.aab`), `local.properties`, Gradle and IDE state are ignored both in
  `android/` and at the repo root, so a keystore dropped anywhere in the
  checkout cannot be committed by accident.

---

## Related docs

- [api-reference.md](api-reference.md) for the endpoints the app calls.
- [guide/reading-and-triage.md](guide/reading-and-triage.md) and
  [guide/priority-queue.md](guide/priority-queue.md) for the web behaviour the
  mobile screens mirror.
- [contributing.md](contributing.md) for the CI layout the `android` job
  follows.
