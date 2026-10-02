# Claude changes log

This file records every change Claude makes to the IntelFeed Android app, so that Gemini (the main agent building the app) knows what changed and why. Claude adds a new dated section for each work session and never rewrites earlier ones. The project isn't a git repository, so this log is the only record of Claude's edits.

**Gemini, please read the "API and signature changes" and "Rules for future code" sections of each entry before editing the files listed there.**

---

## 2026-09-29: Project is now a local git repository

### Summary
The project is now a git repository, so git history will record edits from here on and this log stays as the explanation of why. The line in the intro saying the project isn't a git repository is out of date (earlier entries are left as written).
- The git directory lives **outside Drive** at `~/programming/IntelFeed_App.git`. The project root holds only a `.git` pointer file (`gitdir: ...`). This keeps Drive from syncing thousands of git object files. Do not delete or move that pointer file.
- `.gitignore` gained `build/` (the old `/build` rule missed `app/build`, 787 MB), `.kotlin/`, `*.apk`, `*.aab`, `*.jks`, `*.keystore`, `*.p12`. No app source changed.
- Workflow going forward: develop locally on a feature branch, commit, then push the branch and open a pull request against `main`.

### Rules for future code
- Never commit `local.properties`, keystores, or built APKs. The release script writes `../IntelFeed.apk`, which is outside the repo.

---

## 2026-09-24: Natural voice enhancement for Read Aloud (Option 1: On-device neural voices & text preprocessing)

### Summary
1. **Natural Neural Voice Selection (`ArticleSpeaker`):**
   - Eliminated robotic TalkBack default speech by querying the active engine's installed voices (`engine.voices`).
   - Implemented voice scoring heuristics that automatically prioritize high-definition, neural, WaveNet, and Studio voice models (`Voice.QUALITY_VERY_HIGH`, `Voice.QUALITY_HIGH`, `Voice.LATENCY_NORMAL`, or name patterns containing `wavenet`, `neural`, `natural`, `premium`, `studio`, or `hd`).
   - Excludes low-quality, network-dependent, or screen-reader fast synthesis models (`QUALITY_LOW`, `QUALITY_VERY_LOW`, `LATENCY_VERY_LOW`).
   - Automatically matches the voice to the current language (including translated articles).
2. **Natural Cadence & Intelligent Text Preprocessing (`SpeechText`):**
   - Created `util/SpeechText.kt` with `SpeechText.cleanForSpeech(raw)`:
     - Formats markdown headers (`#`, `##`, `###`) into distinct spoken sentences ending with period pauses instead of symbol reading.
     - Strips bullet points, blockquotes, horizontal rules, markdown emphasis (`*`, `_`, `**`), and formatting delimiters.
     - Replaces long code blocks and terminal logs with natural conversational markers (`[code block omitted for brevity]`).
     - Formats cybersecurity identifiers like CVE IDs (`CVE-2024-12345` -> `C V E 2024-12345`) for clear natural cadence instead of mumbled syllables.
     - Omits raw hexadecimal hashes (32/40/64 characters) with conversational markers (`[cryptographic hash omitted]`).
     - Cleans markdown links and raw URLs into concise domain references (e.g. `[link to github.com]`) instead of robotic character-by-character URL spelling.
     - Normalizes multiple punctuation marks, symbols, and whitespace.
3. **User-Configurable Speech Rate & System Voice Settings:**
   - Added `KEY_TTS_SPEECH_RATE` to `UserPreferences` with options: 0.85x (Relaxed), 1.0x (Normal), 1.15x (Brisk), 1.3x (Fast). Default is 1.0x.
   - Built `VoiceSettingsDialog` in `ui/reader/VoiceSettingsDialog.kt` allowing users to adjust speech rate and directly open Android's System Text-to-Speech settings (`com.android.settings.TTS_SETTINGS` / `Intent("com.android.settings.TTS_SETTINGS")`) to download additional Google neural voice packs.
   - Added a "Read aloud voice & speed" row under the Reading section in `SettingsScreen.kt`.
   - Updated `EntryReaderScreen.kt` to read translated text in the translated target language when translation view is active, and apply user-selected speech rate.

### Verification
- `./gradlew testDebugUnitTest`: All unit tests passed, including `SpeechTextTest` (100% pass).
- `./gradlew :app:assembleDebug`: APK built successfully.
- Copied updated APK to `../IntelFeed.apk`.
- Installed on emulator (`emulator-5554`) via `adb install -r ../IntelFeed.apk`.

---

## 2026-09-24: Reader scroll position preservation on entity and back navigation

### Summary
1. **Root Cause Analysis:**
   - When tapping a highlighted entity (e.g. "FSB") inside an article, the app navigates to `Route.Entity` (`EntityProfileScreen`).
   - Upon pressing Back to return to `Route.Reader`, `ReaderBody` re-entered composition.
   - `produceState` for `blocks` and `linked` started with `initialValue = null`, causing `parsed == null` during the first layout pass.
   - While `parsed == null`, `ReaderBody` rendered `Text("Loading article…")` with a collapsed height of ~300px.
   - Because `contentHeight < viewportHeight`, `Modifier.verticalScroll(rememberScrollState())` calculated `maxValue = 0` and clamped `scrollState.value` to 0, wiping out the restored scroll position before the background parse finished.
2. **Synchronous In-Memory Block Caches (`ArticleHtml` & `ArticleLinker`):**
   - Added thread-safe synchronized LRU cache `blocksCache` in `ArticleHtml` and exposed `ArticleHtml.getCached(detail, serverUrl)`.
   - Added thread-safe synchronized LRU cache `linkerCache` in `ArticleLinker` and exposed `ArticleLinker.getCached(blocks, terms)`.
   - `ReaderBody` now synchronously checks `cachedBlocks` and `cachedLinked` for `produceState` initial values, ensuring `parsed` is non-null on the very first frame of composition.
3. **Scroll Position Retention in `ReaderViewModel` & Auto-Restoration:**
   - Added `var scrollPosition: Int = 0` in `ReaderViewModel` (retained across `Route.Entity` navigation via `ReaderPages`).
   - In `EntryReaderScreen.kt`:
     - Keyed `ScrollState` via `rememberSaveable(detail.id, saver = ScrollState.Saver) { ScrollState(initial = initialScrollPosition) }`.
     - Collected real-time scroll updates via `snapshotFlow { scrollState.value }` without triggering recompositions.
     - Added safeguard `LaunchedEffect` that automatically re-scrolls to `restoreTarget` if any temporary clamping occurred before layout reached full height.
     - Added pre-navigation scroll position capture to entity clicks, re-report banner clicks, and similar coverage clicks.

### Verification
- `./gradlew testDebugUnitTest`: All 17 unit tests passed.
- `./gradlew :app:assembleDebug`: APK built successfully.
- Copied updated APK to `../IntelFeed.apk`.
- Installed on emulator (`emulator-5554`) via `adb install -r ../IntelFeed.apk` and verified launch and crash-free execution.

---

## 2026-09-24: App-wide localization & device-default translation target

### Summary
1. **Device-Default Translation Target:**
   - Updated `UserPreferences.translateTargetLanguage` so when not explicitly customized by the user, it defaults dynamically to the phone's system language (`Locale.getDefault().language`) if supported by Google ML Kit on-device translation, falling back to English (`"en"`).
   - Preserved the user-facing "Translation target language" picker sheet and "Auto-translate foreign articles" toggle in Settings, allowing users to translate articles into any desired language independently.
2. **App-Wide Interface Language ("App Language"):**
   - Implemented an app-wide internationalization system using Compose `CompositionLocalProvider(LocalStrings provides currentStrings)` at the application root in `MainActivity.kt`.
   - Created `AppLanguage` enum in `ui/i18n/AppLanguage.kt` supporting `SYSTEM` ("System default (detected)"), `ENGLISH`, `SPANISH`, `FRENCH`, `GERMAN`, `UKRAINIAN`, `RUSSIAN`, `CHINESE`, `JAPANESE`, `PORTUGUESE`, and `ITALIAN`.
   - Created comprehensive localized dictionaries in `ui/i18n/AppStrings.kt` across all 10 supported languages + English default.
   - Connected `LocalStrings.current` to:
     - Bottom navigation bar & landscape navigation rail tabs (`navFeed`, `navWorkbench`, `navSearch`)
     - Feed drawer section headers, filter labels, and action buttons (`VIEWS`, `KEYWORDS`, `FOLDERS & FEEDS`, `Account & settings`)
     - Feed screen TopBar title and filter chips (`Priority Queue`, `Unread`, `Starred`, `Bookmarked`, etc.)
     - Workbench screen title, search placeholder (`Search threat actors`, `Search malware`, etc.), and scrollable tabs
     - Search screen title, search input placeholder, and recent search history labels
     - Entry reader screen actions menu (`Show original`, `Show translation`, `Translate`, `Export Markdown`, `Mark as read/unread`)
     - Settings screen headers, app language setting row, translation target setting row, auto-translate, auto-mark-read, and auto-read-scroll
   - Added an in-app "App language" setting row and `AppLanguagePickerSheet` in `SettingsScreen.kt`. Changing the language instantly updates the entire UI via reactive Compose flow without restarting the activity.

### Verification
- Ran `./gradlew :app:testDebugUnitTest`: All 17 unit tests passed cleanly.
- Ran `./gradlew :app:assembleDebug`: APK built successfully.
- Copied updated APK to `../IntelFeed.apk`.
- Installed on emulator (`emulator-5554`) with existing session kept (`adb install -r`). Verified startup, clean HTTP 200 responses from server, and error-free logs.

---

## 2026-09-22: Bug and security fixes from a full code review

### Summary

A read-only review of the whole project found crashes, broken features, server-contract mismatches, and security gaps. This session fixes all high-priority, medium-priority, and security findings, plus the low-priority items that were real bugs. It also fixes one bug found during emulator testing (raw HTML in feed cards). Backend behavior was checked against `docs/api-reference.md`.

### Verification

- `./gradlew :app:testDebugUnitTest :app:assembleDebug :app:lintDebug` succeeds.
- 17/17 unit tests pass. 4 are new: 2 in `ServerUrlTest`, and 2 in `DateUtilsTest`.
- Lint: 0 errors. The 22 warnings were all there before (dependency version bumps, `String.format` default locale, one modifier-order warning).
- The debug build was installed on the running emulator (`emulator-5554`, over the existing install, app data kept) and smoke-tested against the live server with the existing session:
  - Startup and Priority Queue load
  - Switching filter chips
  - Category-scoped view
  - Feed card summaries
  - Article reader
  - Workbench search (debounced)
  - Threat actor dossier opened by id
  - Unified search
  - The crash buffer stayed empty.
- **Not tested in the app**, because each would change the user's account or needs a logged-out or expired session:
  - Login screen, logout, token refresh
  - Adding and deleting notes
  - Star, bookmark, and mark-all-read
  - These paths are covered by code review and, where possible, unit tests.

### Fixes

#### 1. Typing a server address crashed the app, then crashed every launch (critical)
- **Problem:** `LoginScreen` saved the URL on every keystroke and rebuilt Retrofit. A partial value such as `h` or `https://` made `Retrofit.Builder().baseUrl()` throw inside `viewModelScope` and crash the app. The bad value was already saved, so the repository constructor crashed on every later launch.
- **Fix:**
  - New `data/network/ServerUrl.kt` with `ServerUrl.normalize(raw): String?`. It accepts only http(s), adds `https://` when no scheme is given, rejects half-typed schemes like `https:/`, and strips the query, fragment, and trailing slash.
  - The address is now validated and saved **only when the user taps Sign In** (`IntelFeedViewModel.login`). An invalid address shows an error message instead of crashing.
  - `AuthPreferences.serverUrl` re-validates the stored value and falls back to the default. This rescues installs already stuck in the crash loop.
  - `AuthPreferences.setServerUrl` now throws `IllegalArgumentException` for invalid input.
  - The repository creates the Retrofit API on first use, per server URL (`getApi()` is now `suspend`). Constructing it no longer blocks the main thread with `runBlocking`.
- **Files:** `ServerUrl.kt` (new), `AuthPreferences.kt`, `IntelFeedRepository.kt`, `ApiClient.kt`, `LoginScreen.kt`, `Navigation.kt`, `IntelFeedViewModel.kt`, `ServerUrlTest.kt` (new)

#### 2. Users were logged out whenever the access token expired (high)
- **Problem:** The server rotates refresh tokens and blacklists the old one (`POST /api/auth/refresh`). When several requests got a 401 at the same time, each ran its own refresh. The first succeeded; the others spent the already-used token, failed, and called `clear()`, which wiped the new tokens. Any refresh error, including a timeout or HTTP 429 (the limit is 10 refreshes per 5 minutes), also logged the user out.
- **Fix** (`ApiClient.kt`):
  - Refreshes run one at a time (`synchronized(refreshLock)`). A request that waited for the lock reuses the token another request just obtained.
  - Only a **401 or 403 from the refresh endpoint** ends the session, matching the web client. Network errors, 429, and 5xx keep the tokens.
  - The refresh uses a separate OkHttp client with no auth interceptor.
- After a forced logout (the server rejected the refresh), the login screen says "Your session has expired. Please sign in again."

#### 3. A wrong password showed the error "closed" (high)
- **Problem:** The interceptor closed every 401 response before deciding whether to retry, then returned the closed response. Retrofit threw `IllegalStateException("closed")` when reading its body.
- **Fix:** The 401 is closed only when the request is actually retried. Login errors are now readable: 401 shows "Invalid username or password." and 429 shows "Too many sign-in attempts…" (`IntelFeedViewModel.loginErrorMessage`).

#### 4. Deleting a note never worked (high)
- **Problem:** `Navigation.kt` passed `(entryId, noteId)` to `deleteNote(id, entryId)`, so `DELETE /api/notes/{entryId}` was sent and the error was hidden.
- **Fix:** Named arguments in `Navigation.kt`. If a delete fails, the note list is reloaded and an error is shown.

#### 5. Server errors on entry actions were treated as success (high)
- **Problem:** Endpoints that return `Response<Unit>` don't throw on 4xx or 5xx, so failed read/star/bookmark/mark-all-read/delete-note calls looked like successes, and the screen never undid its early update.
- **Fix:** The repository calls `Response.requireSuccess()`, which throws `HttpException` on failure. The ViewModel undoes its early update and shows the error in the feed error banner (`reportActionError`).

#### 6. Unstar and unbookmark called endpoints the server doesn't have (high)
- **Problem:** The API docs define `PUT /entries/{id}/star` and `/bookmark` as **toggles** and list no `/unstar` or `/unbookmark`, but the app called them. Combined with #5, unstar and unbookmark silently did nothing.
- **Fix:** Star and bookmark now set the state explicitly with the documented `POST /api/entries/bulk-action`, sending `{ "entry_ids": [id], "action": "star" | "unstar" | "bookmark" | "unbookmark" }`. Read and unread still use the explicit `PUT …/read` and `…/unread`.
- The `unstarEntry` and `unbookmarkEntry` API methods were removed. `starEntry` and `bookmarkEntry` were renamed to `toggleStar` and `toggleBookmark`; they're currently unused and kept for reference.

#### 7. "Mark all read" ignored the current filter and had no confirmation (high)
- **Fix:**
  - `POST /api/entries/mark-all-read` now sends `{ "feed_id", "category_id" }` for the selected feed or category. Null means every feed, as the API docs describe.
  - A confirmation dialog in `FeedScreen` names the scope.
  - After the call, the feed reloads to match the server, and any failure is shown.

#### 8. Choosing a category or feed on the Priority Queue showed the unfiltered queue (high)
- **Problem:** The priority-queue endpoint can't filter by feed or category. The app still called it and ignored the scope, while the banner showed the category name.
- **Fix:** With a feed or category selected, the Priority Queue view shows that scope's **unread** entries (`GET /api/entries?is_read=false&category_id=…`). This is a product decision; change it if another behavior is wanted (see "To check against the backend").

#### 9. Overlapping requests: older responses overwrote newer ones (medium)
- **Fix:** The ViewModel keeps one `Job` per screen area: `feedJob`, `drawerJob`, `readerJob`, `notesJob`, `workbenchJob`, `dossierJob`, `searchJob`. Starting a new load cancels the old one.
  - A feed refresh cancels any feed load in progress. "Load more" is skipped while any feed load is running, so a page fetched with an old cursor can't land on a new list.
  - Changing the filter, feed, or category clears the list and cursor immediately (`loadFeed(scopeChanged = true)`).
  - `setFilter()` now clears the feed/category selection itself, so each chip or drawer tap starts one load instead of two racing loads.
  - Workbench search waits 350 ms after the last keystroke (`loadWorkbenchData(debounceMs)`).
  - Opening an entry clears the previous article's detail and notes, so the reader can't show article A while its actions go to entry B.
  - Feed pages are de-duplicated by `id` (`distinctBy`) so `LazyColumn` can't crash on a repeated key.
  - The repository's new `apiCall {}` helper rethrows `CancellationException` instead of reporting it as a failure, which the cancellation above depends on.

#### 10. The whole app reloaded on every token refresh (medium)
- **Problem:** `isLoggedIn` re-emitted `true` on every DataStore write, including each token save, and the collector reloaded the feed, drawer, and Workbench each time. Login also loaded everything twice.
- **Fix:** All `AuthPreferences` flows use `distinctUntilChanged()`. `login()` no longer starts loads itself; the `isLoggedIn` collector does it once.

#### 11. Notes (medium)
- Saving a note no longer throws away the typed text on failure. The reader clears the draft only when the save succeeds (`addNote(..., onResult)`), shows `uiState.noteError`, and disables Save while saving.
- A note that finishes saving after the user opened another article is no longer added to that other article's list.

#### 12. Entity dossiers (medium)
- Search result types the dossier can't render (`note`, `country`, `tool`, `vendor`, …) used to spin forever. They now show "Opening "x" results isn't supported in the app yet."
- `detection_rule` used to open a blank page. The type is now normalized to `rule` (and `actor` to `threat_actor`).
- Links from the reader and from campaign dossiers now pass the entity **id** when it's known (they used to pass the name).
- Lookup order: the Workbench list already on screen, then the detail endpoint, then search. The search step now accepts **only an exact id, name, or alias match**. It used to take the first fuzzy result, which could open the wrong actor. The generic logic is in `IntelFeedViewModel.resolveEntity`.
- CVE detail requests use the CVE identifier (e.g. `CVE-2024-1234`), which is what the server route expects.
- In search, a `note` result that belongs to an article (`entry_id`) opens that article. `SearchEntityItem.entryId` was added.

#### 13. The bottom of each tab was hidden behind the bottom navigation bar (medium)
- **Fix:** In `Navigation.kt`, the tab content is wrapped in a `Box` with `.padding(innerPadding).consumeWindowInsets(innerPadding)`.

### Security fixes

- **Auth tokens left the device in backups.** The DataStore file holds the access token and the 7-day refresh token.
  - The manifest now sets `android:allowBackup="false"`.
  - `data_extraction_rules.xml` (Android 12+, covering both cloud backup and **device-to-device transfer**, which `allowBackup=false` does not stop) and `backup_rules.xml` both exclude `datastore/`. Both files are now referenced in the manifest.
- **Logout now cancels the tokens on the server.** `IntelFeedRepository.logout()` clears the local tokens first, so the UI signs out right away. It then calls `POST /api/auth/logout` with the captured tokens: an explicit `Authorization` header plus `{ "refresh_token" }` in the body, best effort with a 5-second limit.
- **Links from feed content are checked before opening.** New `util/ExternalLinks.openInBrowser()` opens only http(s) URLs, adds `CATEGORY_BROWSABLE`, and catches `ActivityNotFoundException` (it used to crash when no app could open the link). It's used for article URLs, rule `entry_url`, TTP `mitre_url`, and the NVD link.
- **No network logging in release builds.** `HttpLoggingInterceptor` is only added when `BuildConfig.DEBUG` is true, which required `buildConfig = true` in `app/build.gradle.kts`.
- **Session data is cleared on logout.** `IntelFeedViewModel.resetSession()` runs whenever `isLoggedIn` becomes false (user logout or forced logout). It cancels all jobs and resets the UI state, so the next user doesn't see the previous user's feed, search, notes, or Workbench data.

### Smaller bug fixes

- **Keyboard covering fields:** `windowSoftInputMode="adjustResize"` moved from `<application>` (where Android ignores it) to the `<activity>`. `imePadding()` was added to the login screen and the reader, so the keyboard no longer hides the note field.
- **Date parsing** (`DateUtils.kt`):
  - Microsecond timestamps (`.123456`) were read as milliseconds, up to about 16 minutes off. The fraction is now normalized to 3 digits.
  - Timestamps with a timezone offset plus fractional seconds were read as UTC. Patterns with a timezone are now tried first. New tests cover both cases.
- **Article HTML:** New `util/HtmlText.kt` (`toPlainText`, `toSnippet`) uses `HtmlCompat`, which decodes all entities exactly once and drops `<script>`/`<style>` bodies.
  - The reader shows `content_text` as is. It used to run through a tag-stripping regex that deleted literal code such as `<script>` from security write-ups.
  - **Found during the emulator test:** feed and search cards showed raw HTML in summaries (`<p>…`, `&amp;`). Both card types now use `HtmlText.toSnippet`.
- **Opening an article marks it read explicitly** (`setReadState(id, true)`) instead of toggling, which could mark it unread if the list's copy was out of date.
- **Paging stall:** `FeedScreen`'s load-more effect is now also keyed on `entries.size` and `hasMore`, so paging continues when a short page leaves the end of the list visible.

### API and signature changes (update any callers)

| Where | Before | After |
|---|---|---|
| `LoginScreen` | `onLogin(username, password)`, `onUpdateServerUrl(url)` | `onLogin(serverUrl, username, password)`; `onUpdateServerUrl` removed |
| `IntelFeedViewModel` | `login(username, password)`, `updateServerUrl(url)` | `login(serverUrl, username, password)`; `updateServerUrl` removed |
| `IntelFeedViewModel` | `addNote(entryId, content, title)` | `addNote(entryId, content, title = null, onResult: (Boolean) -> Unit = {})` |
| `IntelFeedViewModel` | `setFilter(filter)` (callers cleared the feed filter first) | `setFilter(filter)` also clears the feed/category selection; **don't call `clearFeedFilter()` before it** |
| `IntelFeedViewModel` | `loadWorkbenchData()` | `loadWorkbenchData(debounceMs: Long = 0)` |
| `IntelFeedUiState` | none | new `noteError: String?` |
| `EntryReaderScreen` | `onAddNote: ((entryId, content) -> Unit)?` | `onAddNote: ((entryId, content, onResult: (Boolean) -> Unit) -> Unit)?` |
| `FeedDrawerSheet` | had `onClearFeedFilter` | parameter removed |
| `IntelFeedRepository` | `login(username, password)`, `setServerUrl(url)` | `login(serverUrl, username, password)` (saves the URL); `setServerUrl` removed |
| `IntelFeedRepository` | `toggleRead/Star/Bookmark(id, currentValue)` | `setRead/setStarred/setBookmarked(id, value)` |
| `IntelFeedRepository` | `markAllRead()` | `markAllRead(feedId = null, categoryId = null)` |
| `ApiClient` | `createApi()` | `createApi(serverUrl)` (must already be validated) |
| `IntelFeedApi` | `starEntry`, `unstarEntry`, `bookmarkEntry`, `unbookmarkEntry`, `markAllRead()` | `toggleStar`, `toggleBookmark`, `bulkAction(BulkActionRequest)`, `markAllRead(MarkAllReadRequest)`, `logout(authorization, LogoutRequest)` |
| Models | none | `BulkActionRequest`, `MarkAllReadRequest` (EntryModels.kt), `LogoutRequest` (AuthModels.kt), `SearchEntityItem.entryId` |
| New files | none | `data/network/ServerUrl.kt`, `util/ExternalLinks.kt`, `util/HtmlText.kt`, `test/.../data/ServerUrlTest.kt` |

### Rules for future code (to avoid these bugs coming back)

1. Open any URL from the server or a feed with `ExternalLinks.openInBrowser(context, url)`, never with a bare `Intent(ACTION_VIEW, …)`.
2. Wrap repository calls in `apiCall { … }`, which rethrows `CancellationException`. Call `.requireSuccess()` on any `Response<Unit>`.
3. Never save a server URL without passing it through `ServerUrl.normalize` first.
4. For any new load in the ViewModel that can be superseded, keep a `Job` and cancel the old one before starting a new one.
5. Don't add a second token-refresh path. All refreshes go through `ApiClient.refreshAccessToken` (single-flight, and only a 401 or 403 from the refresh endpoint logs the user out).
6. Show feed-supplied HTML with `HtmlText`, not ad-hoc regexes.

### To check against the backend (based on `docs/api-reference.md`, not the server code)

- `POST /api/entries/bulk-action` is used for star, unstar, bookmark, and unbookmark.
- `POST /api/entries/mark-all-read` accepts a JSON body with optional `feed_id` and `category_id`.
- `POST /api/auth/logout` takes `{ "refresh_token" }`. If the access token has already expired, this call gets a 401 and the refresh token isn't revoked on the server. That's accepted as a best-effort limitation.
- The Priority Queue with a feed or category selected shows that scope's unread entries (product decision, fix #8).

### Known issues deliberately not changed

- Tokens are still stored **unencrypted** in DataStore. Consider Android Keystore or Tink encryption.
- Release builds have `isMinifyEnabled = false`, and `app/proguard-rules.pro` doesn't exist. Turning on R8 needs rules for kotlinx.serialization and Retrofit, plus testing.
- The drawer shows only top-level categories (no `children`) and the first 100 feeds.
- Unused dependencies: Coil and Navigation3 (kept in case they're planned).
- Deprecation warnings that were already there: `LocalClipboardManager`, several `Icons.Filled.*` icons that have AutoMirrored versions, `ScrollableTabRow`. Also the `String.format` default-locale lint warnings.
- Priority Queue story-thread rows open their first absorbed entry. There's no thread view.
- Dossier navigation has no back stack (opening another entity replaces the current one).
- The feed list doesn't scroll to the top after a filter change, and deleting a note has no confirmation.
- `MainActivity` still builds a new `AuthPreferences` and repository on each configuration change. This is now cheap because construction does no I/O, but moving the construction into the ViewModel initializer would be cleaner.

---

## 2026-09-22 (second session): Friendlier UI and web-app parity

### Summary

The user asked Claude to lead development for a while, with two goals: make the UI as friendly as possible, and let the Android app do what the web app does. This session:

1. **Checked the live server's real response shapes** before building anything, and found three places where the app was silently broken (see "Server contract findings").
2. **Replaced the navigation** with a real back stack (Navigation3), so article → actor → article → Back retraces your steps.
3. **Rebuilt the reader, entity profiles, Workbench, search and feed**, and added story threads, settings and a share target.

`ANDROID_APP_IMPLEMENTATION_REVIEW.md` (GPT's review) was the starting checklist. Most of its "Phase 1–3" items are now done; see "Review items addressed".

### How the server contract was checked (and cleaned up)

`docs/api-reference.md` is older than the server in several places. To see real payloads without touching the user's account:

- A **temporary debug-only probe** (`DebugProbe.kt` plus a `@Url` GET/POST on the API) made **read-only** requests through the app's own signed-in client on the emulator and saved the JSON to the app's private storage. It was **deleted afterwards**; the four touched files were diffed against the backup and are identical apart from this session's real changes. No tokens were extracted or used outside the app.
- The public web bundle (`https://intelfeed.cc/assets/*.js`) was read to get the exact request bodies the web client sends for writes (notes, tags, watchlist, radar feedback, share). Write endpoints were **not** called against the live server; their shapes are pinned by `ApiContractTest` instead.

### Server contract findings (bugs in the old app)

| What the app expected | What the server actually sends | Effect in the old app |
|---|---|---|
| `GET /api/entries/{id}` includes `threat_actors`, `malware`, `cves`, `ttps`, `countries` | It includes none of them. Entities come from `GET /api/entries/{id}/threat-actors`, `/malware`, `/cves`, `/ttps`, `/countries`, `/tools`, `/vendors`, `/products` | The reader's "Threat intelligence extracted" panel was **always empty** |
| Notes have a `content` field; create via `POST /api/notes {entry_id, content}` | Notes have `content_markdown` + `content_html` (+ `is_pinned`, `created_by`, `creator_username`). The web client creates via `POST /api/notes/entry/{id}` with `{title, content_markdown, is_pinned}` and lists via `GET /api/notes/entry/{id}` (a bare array) | Existing notes **showed blank**; creating a note likely failed or saved an empty note |
| Threat actor techniques in `ttps` | `associated_ttps` | Actor dossiers **never showed techniques** |
| Malware `malware_types: [...]` | `malware_type: "backdoor"` (one string) + `associated_actors` | Malware type never shown |
| Search hits' `published_at` is an ISO string | Epoch seconds, sometimes decimal (`1790094767.0`) | Search cards showed the raw number |
| Search hits' `tags` are objects | Bare strings (`["morning-brief"]`); entry endpoints send objects | Found while testing this session: any search containing a tagged article **failed to load** |
| `GET /api/ttps/{id}` | 404. The web uses `GET /api/ttps/by-technique/{T1234}` | TTP dossiers only worked via the search fallback |
| `GET /api/feeds?limit=100` returns everything | The server has 306 feeds; the web asks for `limit=1000` | The drawer **hid about 200 feeds** |
| CVE `timeline` | A list in list responses, an object in per-entry responses | Not modelled (so it can't break decoding). Don't add it without a custom serializer |

### New and rebuilt features

**Navigation**
- Navigation3 `NavDisplay` with a back stack held in `IntelFeedViewModel.backStack` (`SnapshotStateList<Route>`). Routes are in `ui/navigation/Routes.kt`: `Home`, `Reader(entryId, contextIds)`, `Entity(type, idOrName, name)`, `Thread(slug, title)`, `Settings`.
- Each Reader/Entity/Thread entry gets its **own ViewModel** (`rememberViewModelStoreNavEntryDecorator`), so a profile you pivot through keeps its state when you come back.
- System back: pops the stack; on Home it closes the drawer, clears a selection, or returns Workbench/Search to Feed.

**Feed**
- Pull to refresh; day dividers ("Today", "Yesterday", "Monday, Sep 21") on date-ordered views.
- New views: **Last 24 hours** and **This week** (`since=`), matching the web's quick views.
- Cards show feed, score badge, time, title, snippet, the **top ranking signals** (`top_signals`), tags, author and reading time; re-reports (`is_echo`) are dimmed and labelled.
- **Priority Queue story rows** are now story cards (outlets, unread, key entities) that open the **story thread**, instead of opening the first absorbed article.
- **Swipe** right to toggle read, left to toggle star (the row springs back).
- **Long-press to multi-select**, then mark read/unread, star, bookmark in bulk, with **Undo** in a snackbar.
- Card menu: mark read/unread, **"Mark everything above as read"** (the web's Shift+M), open original, share link.
- Scrolls to the top when the scope changes; "That's everything in this view" at the end; loading states say when the server is slow (it takes 8–10 s for some unread lists and searches).
- Sign out moved to Settings with a confirmation (it used to be a one-tap toolbar icon).

**Feeds drawer** (now covers the whole screen, bottom bar included)
- All feeds (not the first 100), **Find a feed** box, nested folders with **summed unread counts**, an **Uncategorized** group, and a separate expand arrow (tapping a folder used to both filter and expand). Unread badges update as you read.

**Reader** (`ui/screens/EntryReaderScreen.kt`, `ui/reader/ReaderViewModel.kt`)
- **Rich article rendering**: headings, paragraphs, bold/italic/code, tappable links (http(s) only, via `ExternalLinks`), lists, quotes, code blocks with a copy button, tables, captions and **inline images**. Text is selectable (to copy IOCs). Parser: `util/ArticleHtml.kt` (jsoup), renderer: `ui/components/ArticleContent.kt`.
- Images from the server's proxy (`/api/proxy/image`, which needs auth) load through `ApiClient.imageHttpClient()`: the token is sent **only** to the IntelFeed server's own origin, never to third-party image hosts.
- **Linked intelligence** panel from the eight per-entry endpoints, grouped by type, KEV/CVSS-coloured CVEs first; every chip opens a profile.
- **"Why this is ranked"** card from `priority_signals` (family, weighted contribution, explanation) plus **thumbs up/down** (`PUT /api/engine/radar-feedback`).
- **Tags**: view, add existing, create new, remove (`/api/tags/entries/{id}`).
- **Notes**: create, **edit**, **pin**, delete **with confirmation**; edit/delete only offered on your own notes (or to admins), because notes are shared across the instance.
- **Similar coverage** (`GET /api/entries/{id}/similar`), with a link into the story when the article belongs to one.
- **Echo banner**: "This is a re-report… tap to read the original" (`echo_of`).
- **Previous / Next** bottom bar through the list the article came from (feed, search results, story, entity articles); pages the feed in as you go.
- Overflow menu: open original, share/copy source link, **share the IntelFeed public page** (`POST /api/entries/{id}/share`), mark read/unread, **text size** (saved on the device, applies to all articles).

**Entity profiles** (`ui/screens/EntityProfileScreen.kt`, `ui/entity/EntityViewModel.kt`) replace the six hard-coded dossier layouts
- **11 types**: threat actor, malware, CVE, technique, tool, vendor, product, country, campaign, mitigation, detection rule (tools, vendors, products, countries and mitigations are new).
- Tabs: **Overview** (badges, aliases, description, key facts, pivots, ATT&CK techniques, detection guidance, rule body, outbound links to MITRE/NVD/Malpedia/etc.), **Articles** (paged, via unified search `threat_actor:"Name"` etc.), **Relationships** (paged `GET /api/entity-relationships`, tap to pivot), **Notes** (entity notes CRUD).
- **Watch / Mute** (`/api/intelligence/watchlist`) for the types the web allows, with a plain explanation of what each does.

**Story threads** (`ui/screens/ThreadScreen.kt`, new)
- Title, outlets/articles/unread, key entities, "What happened" timeline of beats, coverage list (first to report / re-report), related stories, "Mark all read". Opening a thread calls `POST /api/threads/{id}/open`, as the web does.

**Workbench**
- 11 entity lists plus a **Watchlist** tab; "Showing 30 of 1,097"; loads more as you scroll; pull to refresh. One card layout for all types (`WorkbenchItem`).

**Search**
- Autocomplete for field values (`GET /api/search/autocomplete`), **recent searches** (on the device), your **saved searches** (run, long-press to delete, save the current search), tappable **query examples**.
- Results: **did you mean**, the parsed filter chips, "not a field" notice, scope chips (Everything / Articles · N / Entities · N using the server's untrimmed counts), entities grouped by type with direct matches first, **notes** show their title and open their article/entity, articles load more as you scroll.

**Settings** (new): account, server, open the web app, reading text size, clear recent searches, sign out (confirmed), version.

**Share to IntelFeed** (new): sharing a link from a browser to IntelFeed asks for confirmation, then adds it as an article (`POST /api/entries/ingest/url`) with an **Open** action. Only http(s) links are accepted.

**Errors**: snackbars (`UiMessenger`) for action failures, with Retry/Undo where it makes sense; `ui/ErrorText.kt` turns exceptions into short sentences (no more raw exception text such as JSON parser messages).

### Architecture changes (read before editing)

- **`IntelFeedApplication`** (new, registered in the manifest) holds the single `IntelFeedRepository`, `AuthPreferences`, `UserPreferences` and `UiMessenger`, and is Coil's `ImageLoaderFactory`. **There must be one repository per process**: it owns the OkHttp client and the token-refresh lock. `MainActivity` no longer creates them.
- **Entry flag sync**: `IntelFeedRepository.setRead/setStarred/setBookmarked/bulkSet` broadcast an `EntryFlagUpdate` before the request and the reverse on failure (`repository.entryUpdates`). The main, reader, entity and thread ViewModels apply these, so a star in the reader shows in the feed and search lists. Don't update flags locally without going through these methods.
- **Reader, dossier and search result state moved out of `IntelFeedUiState`** into per-screen ViewModels (`ReaderViewModel`, `EntityViewModel`, `ThreadViewModel`).
- Entity types are the `EntityType` enum (`data/model/EntityType.kt`): server key, labels, search field, and whether Watch/Mute is allowed. Use `EntityType.fromKey()` for any type string from the server.
- `ui/entity/EntityPresentation.kt` maps every entity model to `WorkbenchItem` (list rows) and `EntityProfile` (profile screen). Add a type there, not in the screens.
- `ApiJson.json` (`data/network/ApiClient.kt`) is the one JSON configuration; tests use it too.
- New dependencies: `org.jsoup:jsoup:1.21.2` (article HTML) and `mockwebserver` (tests only). Coil and Navigation3, previously unused, are now used.

### API and signature changes (update any callers)

| Where | Before | After |
|---|---|---|
| `IntelFeedViewModel` constructor | `(repository)` via `IntelFeedViewModelFactory` | `(repository, userPreferences, messenger)`; factory **removed**, created with `viewModel { }` |
| `IntelFeedUiState` | `activeEntryId`, `activeEntryDetail`, `readerLoading`, `readerError`, `entryNotes`, `notesLoading`, `noteError`, `activeDossier*`, `dossierLoading`, `dossierError`, `threatActors`, `malwareList`, `cveList`, `ttpList`, `detectionRules`, `campaigns`, `workbenchLoading` for lists | **Removed**. Reader/dossier state is in the per-screen ViewModels; Workbench uses `workbenchItems: List<WorkbenchItem>` + `workbenchTotal/HasMore/NextOffset/LoadingMore`. New: `sessionChecked`, `currentUser`, `feedScrollToTop`, `selectedIds`, `drawerError`, `submittedQuery`, `searchScope`, `searchEntries`, `searchEntriesTotal`, `searchLoadingMore`, `searchSuggestions`, `recentSearches`, `savedSearches` |
| `IntelFeedViewModel` | `openEntry(id)`, `closeReader()`, `openEntityDossier(type, idOrName)`, `closeEntityDossier()`, `toggleRead/Star/Bookmark(id)`, `addNote`, `deleteNote`, `loadNotes`, `loadWorkbenchData(debounceMs)` | `openEntry(entry | id, contextIds)`, `openEntity(ref | typeKey, idOrName, name)`, `openThread`, `navigate`, `goBack`, `replaceTop`; `toggleRead/Star/Bookmark(entry: EntryItem)`, `setRead(id, read)`; notes moved to `ReaderViewModel`; `loadWorkbench(debounceMs)`, `loadMoreWorkbench()`; new selection/bulk, search and share-target functions |
| `WorkbenchTab` | 6 tabs, `label` only | 12 tabs with `type: EntityType?` (Watchlist has none) |
| `FeedFilter` | 5 values | Adds `LAST_24H`, `THIS_WEEK`; each has a `label` |
| `IntelFeedRepository` | `getThreatActors(search, offset)` etc. returned `CursorPage` | Return `OffsetPage` (items, total, hasMore, nextOffset). `getNotes(entryId)` now uses `/api/notes/entry/{id}`; `createNote(entryId, title, body, pinned)`; many new methods |
| `IntelFeedApi` | `getNotes`, `createNote(CreateNoteRequest)` | `getEntryNotes`, `createEntryNote(entryId, NoteRequest)`, `updateNote`; ~40 new endpoints |
| Models | `EntryDetail.threatActors/malware/cves/ttps/countries`, `ThreatActorEntity`-style lists on the detail, `EntryNote.content`, `CreateNoteRequest`, `SearchEntityItem.name` non-null, `Malware.malwareTypes` only | Removed or replaced: `EntryIntel`, `EntryNote.contentMarkdown/contentHtml/displayText`, `NoteRequest`, `SearchEntityItem.displayName` (name, title or "Note on X"), `Malware.malwareType/typeLabel`. Models split into `EntryModels.kt`, `IntelModels.kt`, `SearchModels.kt`, `ThreadModels.kt`, `UserContentModels.kt` |
| Screens | `EntityDossierScreen.kt` | **Deleted**; replaced by `EntityProfileScreen.kt`. `FeedScreen`, `WorkbenchScreen`, `SearchScreen` now take `(uiState, viewModel)`; `FeedScreen` also `onOpenDrawer` |
| `ReaderFontSize` | enum inside `EntryReaderScreen.kt`, `rememberSaveable` | `ui/reader/ReaderFontSize.kt`, persisted in `UserPreferences` |
| `DateUtils` | – | `dayLabel()`, `readingMinutes()`; parses decimal epoch strings |
| `AuthPreferences.kt` | private `Context.dataStore` | `internal`, shared with `UserPreferences` (one DataStore per file) |
| Manifest | – | `android:name=".IntelFeedApplication"`, `launchMode="singleTop"`, `ACTION_SEND text/plain` intent filter |

### Rules for future code

1. Keep **one** `IntelFeedRepository` (get it from `IntelFeedApplication`). Never construct one in a composable.
2. Change read/star/bookmark only through the repository's `setRead/setStarred/setBookmarked/bulkSet`, so every screen stays in sync.
3. Render article HTML with `ArticleHtml` + `ArticleContent`; plain snippets with `HtmlText`. Don't add a WebView for feed content.
4. Load images through Coil's app `ImageLoader` (which uses `imageHttpClient()`). Never attach the session token to other hosts.
5. Before modelling a new endpoint, check its real response (the docs are out of date in places), give every field a default, and add a case to `LiveShapeSerializationTest` or `ApiContractTest`.
6. Model fields that come in more than one form with a flexible serializer (`FlexibleStringSerializer`, `FlexibleTagListSerializer`).
7. Show errors with `UiMessenger` / `ErrorText`, not raw `localizedMessage`.
8. Add entity types in `EntityType` + `EntityPresentation.kt` + `EntityViewModel.resolveProfile`, not as new screen branches.
9. The earlier rules (ServerUrl validation, `ExternalLinks`, `apiCall`/`requireSuccess`, single-flight refresh, cancellable jobs) still apply.

### Verification

- `./gradlew :app:testDebugUnitTest :app:assembleDebug :app:assembleRelease :app:lintDebug` all succeed.
- **52 unit tests, 0 failures** (was 17). New: `LiveShapeSerializationTest` (10, real payloads), `ApiContractTest` (12, MockWebServer: paths and JSON bodies of every write), `ArticleHtmlTest` (7), `DateUtilsExtraTest` (3), `EntityTypeTest` (2). `testEntryDetailWithThreatIntelligence` was replaced by `testEntryDetailMatchesLiveServer` and `testEchoEntryDetail`, because the old payload shape doesn't exist on the server.
- Lint: 0 errors, 21 warnings, all dependency-version notices. The code warnings listed last session (default-locale `String.format`, `LocalClipboardManager`, non-AutoMirrored icons, `ScrollableTabRow`, modifier order) are gone. No Kotlin compiler warnings.
- **Emulator, live server** (existing session): Priority Queue with story rows → story thread → lead article (Why card with 4 signals, 25 linked entities, rich body with inline proxied images, Previous/Next "5 of 6") → Back → tool profile (Overview, Articles · 22, Relationships) → Unread feed (day dividers, signal lines) → Workbench ("Showing 30 of 1,097") → Search (saved searches, recent, 190 results) → drawer (unread per folder). No crashes in the crash buffer.
- Side effects of that test on the user's account: articles opened in the reader were **marked read** (the app does this by design), and opening a story stamped it as seen (`POST /api/threads/{id}/open`), as the web does.
- **Not exercised against the live server** (they would change shared or account data): creating/editing/deleting notes and entity notes, tags, watch/mute, radar feedback, bulk actions and swipe, share links, saved-search create/delete, URL ingest, mark all read. Their request shapes are covered by `ApiContractTest` against the web client's shapes.

### Review items addressed (`ANDROID_APP_IMPLEMENTATION_REVIEW.md`)

- Done: search note titles; search paging; Workbench paging and result counts; all feeds in the drawer; nested categories; story-thread reading; Why details and feedback; tags; similar articles; public share link; rich article rendering; persisted reading preference; real back stack; readable errors instead of raw exception text; delete-note confirmation; scroll to top on filter change; deprecated APIs and locale formatting; Coil and Navigation3 now used; one repository per process.
- Not done (still open): Keystore-encrypted tokens; HTTP/cleartext policy; R8/minification and signing; offline cache; tablet/foldable layouts; string resources/localization; dashboards, reports, rule editing, automation, AI/copilot, admin settings; add-to-campaign from an article; the "Wrong?" link-correction control; daily AI summaries on day dividers (the endpoint is wired in the repository as `getDailySummary` but not shown yet); per-signal feedback persistence (the web also doesn't read back a previous vote).

---

## 2026-09-22 (third session): Inventory gaps, bug fixes in the latest code, security and speed

### Summary

The user asked Claude to compare the app with `INTELFEED_LIVE_SITE_FEATURE_INVENTORY.md` (GPT's walkthrough of the live website), fix what's broken, fill the gaps in priority order, and add security and speed improvements that don't change existing features. This session started from Gemini's latest code (notifications, campaigns, reader pager, grid layout, read aloud, find in article, day briefings), which had no change log, so Claude read the whole app first.

**Each fix below was written into this file as soon as it was finished**, so the list is in the order the work was done (highest priority first). If the session ended early, the "Still to do" list at the end of this section says what's left.

Baseline before any change: `./gradlew :app:testDebugUnitTest :app:assembleDebug` passed, 55 unit tests, 0 failures. A copy of the source from before this session is in Claude's scratchpad (`backup_start/`), not in the project.

### Fix 1: The reader marked articles read that you never opened, and loaded everything twice or three times (high)

- **Problem 1 (wrong data on the account):** the reader is a `HorizontalPager` with `beyondViewportPageCount = 1`, so it also builds the previous and next pages. Each page's `ReaderViewModel` marked its article read as soon as it loaded. Opening one article in Unread marked **three** read, and every swipe marked one more article ahead of you.
- **Problem 2 (speed):** every pre-built neighbour also loaded its linked intelligence (8 requests), notes and similar coverage, even if you never swiped to it.
- **Problem 3 (speed, older bug):** `ReaderViewModel` fetched the linked intelligence *inside* `_state.update { … }`. `update` re-runs its lambda when the state changed in the meantime (notes arriving, the read flag), so the 8 requests were usually sent twice. The server URL lookup had the same pattern.
- **Fix:**
  - `ReaderViewModel` now only loads the article itself when it's created. Auto mark-read and the side panels run from the new `activate()`, at most once per ViewModel.
  - `EntryReaderScreen` calls `activate()` for the page the pager has **settled** on (`pagerState.settledPage`), not for pages it pre-builds, and not while a swipe is half-way.
  - Suspending calls are made before `_state.update { }`, never inside it. (A scan of every `update {}` in the app found no other case.)
  - `IntelFeedViewModel.openEntry(id: String, contextIds)` now defaults `contextIds` to `listOf(id)` instead of `null`. `null` means "walk the feed list", which only makes sense from the feed (the `openEntry(entry: EntryItem)` overload, unchanged). A similar-coverage link, the re-report banner, a search note or the "Open" snackbar after ingesting used to let Previous/Next wander into unrelated feed articles.
- **Files:** `ui/reader/ReaderViewModel.kt` (`load`, new `activate`/`onVisible`), `ui/screens/EntryReaderScreen.kt` (settled-page activation after `activeState`), `ui/IntelFeedViewModel.kt` (`openEntry`).
- **Verified on the emulator (live server, debug HTTP log):** opening the 2nd article in Unread sent one `PUT …/read` (for that article only), one request per linked-intel endpoint, and a plain `GET` for each neighbour. The neighbours were still unread in the list afterwards. Swiping to the next article sent exactly one more `PUT …/read`, for the article swiped to.
- **Rule for future code:** in a pager or any pre-rendered list, never start side effects (mark read, analytics, "opened" stamps) from a ViewModel's `init`; start them when the item is actually shown.

### Fix 2: "Add feed" could silently add a web page as an article on the shared server (high)

- **Problem:** the drawer's Add dialog called `IntelFeedViewModel.addFeedOrIngest`, which tried `POST /api/feeds` and, if that failed **for any reason** (no permission, feed already exists, server error, not a feed), called `POST /api/entries/ingest/url` instead. A failed subscription therefore created an article everyone on the instance can see, without asking.
- **Fix:** a new `ui/components/AddFeedDialog.kt` with two explicit choices, matching the website's Add Feed (checked in the live web bundle):
  - **Subscribe to feed:** type a feed or website address → **Find feed** calls `POST /api/feeds/discover {"url"}`, which only looks and changes nothing → the dialog shows what was found (title, description, RSS/Atom, address; a list to pick from if several) → pick a folder (nested folders shown as "Parent › Child") and a check interval (the web's options: default, 15 min, 30 min, 1 h, 6 h, daily) → **Subscribe** sends `POST /api/feeds {url, category_id?, fetch_interval_minutes?}`. Editing the address clears the preview. The snackbar says "Subscribed to X" with an **Open** action that selects the new feed. A 403 adds "Adding feeds may need an admin account."
  - **Add one article:** the same ingest as before (`ingestSharedUrl`), but only when chosen.
  - Addresses are cleaned by the new `util/WebUrl.normalize` (adds https://, keeps path and query, rejects non-http(s), bare words and spaces).
  - The selected chip and toggle use the app's blue (the theme's secondary colour is green).
- **Server contract:** the live discover endpoint returns **one object** `{url, title, description, feed_type}` (seen on the live server with krebsonsecurity.com); `docs/api-reference.md` describes `{"feeds": [{url, title, type}]}`. `IntelFeedRepository.parseDiscoveredFeeds` accepts both. `CreateFeedRequest` now leaves unset optional fields out of the JSON (`@EncodeDefault(NEVER)`), like the web, instead of sending `"category_id": null`.
- **Files:** `ui/components/AddFeedDialog.kt` (new), `util/WebUrl.kt` (new), `ui/screens/FeedDrawer.kt` (old dialog removed; new parameters), `Navigation.kt`, `ui/IntelFeedViewModel.kt`, `data/model/EntryModels.kt` (`CreateFeedRequest`, new `DiscoveredFeed`), `data/network/IntelFeedApi.kt` (`discoverFeed`), `data/repository/IntelFeedRepository.kt` (`createFeed(…, fetchIntervalMinutes)`, `discoverFeeds`, `parseDiscoveredFeeds`).
- **API changes:** `IntelFeedViewModel.addFeedOrIngest(url, categoryId)` is **removed**. Use `discoverFeeds(url, onResult)`, `subscribeToFeed(feed, categoryId, fetchIntervalMinutes)` and `ingestSharedUrl(url)`. `FeedDrawerSheet`'s `onAddFeedOrIngest` is replaced by `onDiscoverFeeds`, `onSubscribe`, `onAddArticle` (the Add button is hidden when `onDiscoverFeeds` is null).
- **Tests:** new `test/.../data/AddFeedContractTest.kt` (6): subscribe body with and without optional fields, discover path/body, both discover response shapes, nothing-found, and `WebUrl.normalize`.
- **Verified on the emulator:** Find feed for `krebsonsecurity.com` showed "Krebs on Security · RSS · https://krebsonsecurity.com/feed/" with folder and interval choices; the dialog was cancelled and the log shows no `POST /api/feeds`. Subscribing and adding an article were **not** submitted (they would change the shared server).

### Fix 3: Notifications — taps ignored while the app was open, priority alerts that could never fire, polling with notifications blocked (high)

- **Problems (all in Gemini's notification code):**
  1. Tapping an alert while the app was already running did nothing: `MainActivity` only read the tap's extras in a `LaunchedEffect(isLoggedIn)`, which doesn't run again for `onNewIntent`.
  2. Priority alerts required `priorityScore >= 85`, but scores run from about 0 to 10 (Radar threshold ≈ 1.75, top of the queue today 6.6). They could never fire.
  3. A Priority Queue **story** row has the id `thread:<slug>`, so an alert for one would have opened a non-existent article.
  4. The worker polled the server every 15 minutes (campaigns, every saved search, the queue) even when Android wasn't allowing the app to post notifications. On Android 13+ that's the default until the user grants the permission, which the app only asked for from Settings.
  5. The worker's `catch (_: Exception)` also swallowed coroutine cancellation.
  6. `MainActivity` is exported (it's the launcher), so any app could start it with route extras. Values weren't checked.
  7. Settings showed "Background Intel Alerts" as on (the default) while Android blocked them, and "Send test notification" asked for permission and posted at the same moment, so the first test never showed but the snackbar said it was sent.
- **Fix:**
  - `IntelNotificationHelper` has a `Route` type (`Entry`, `Thread`, `Campaign`), `routeFrom(intent)` which checks ids against the server's formats (`[A-Za-z0-9-]`, 64 chars for ids, 200 for slugs) and `clearRoute(intent)`. New extras: `EXTRA_ROUTE_THREAD_SLUG`, `EXTRA_ROUTE_THREAD_TITLE`. `postNotification(…, threadSlug, threadTitle)` added. New `canPostNotifications(context)` (Android 13+ permission and the app's system switch).
  - `MainActivity` reads the route in `onCreate` (only when `savedInstanceState == null`, so rotation doesn't reopen it) **and** in `onNewIntent`, keeps it in `pendingRoute`, and navigates once signed in. The old `handleNotificationIntent` is removed.
  - Worker: returns early without any network calls when `canPostNotifications` is false; priority alerts use `PRIORITY_ALERT_SCORE = 8.0` (the same "critical" band as the red score badge); story rows open the story; `CancellationException` is rethrown.
  - Settings: the switch shows on only when the preference is on **and** Android allows notifications (re-checked on resume); the subtitle says what the alert checks, or warns in amber when Android is blocking them; the test notification is sent after the permission is granted, or explains that notifications are off.
- **Files:** `notifications/IntelNotificationHelper.kt`, `notifications/IntelNotificationWorker.kt`, `MainActivity.kt`, `ui/screens/SettingsScreen.kt`.
- **Verified on the emulator:** with the app open, `am start … --es route_entry_id <read article id>` (the same intent a notification sends) opened that article on top of the current screen, with no Previous/Next bar and no mark-read call (it was already read). `--es route_entry_id "../../api/x"` was ignored with no request sent. The test notification posted (`dumpsys notification` shows id 9999 on channel `intel_alerts`). The Settings section rendered with the new text. A real priority alert wasn't triggered: no item on the live queue scores 8 or more right now.
- **Product decision to confirm:** the priority-alert cut-off is 8.0. Change `IntelNotificationWorker.PRIORITY_ALERT_SCORE` if alerts should be more or less frequent.

### Fix 4: Read aloud was silent on most articles (medium)

- **Problem:** `TextToSpeech.speak()` rejects text longer than `getMaxSpeechInputLength()` (4,000 characters): it returns `ERROR` and says nothing. The reader passed the whole article, so anything over roughly 600 words was silent while the button showed "stop". The reader also bound to the speech engine every time an article opened, even if Read aloud was never used.
- **Fix:**
  - New `util/SpeechText.chunk(text, max = 3800)` splits the text at paragraph breaks, then sentence ends, then spaces (a single over-long "word" is cut). Nothing is dropped.
  - New `ui/reader/ArticleSpeaker` wraps the engine: it starts on the first tap, queues the chunks (`QUEUE_FLUSH` then `QUEUE_ADD`), tracks the last chunk's utterance id so "speaking" ends when the whole article is done (not after the first chunk), posts engine callbacks to the main thread, and shows a toast if no engine is available.
  - `EntryReaderScreen` uses `ArticleSpeaker` instead of its inline `TextToSpeech`; it's shut down when the reader closes and stops when you swipe to another article, as before. It reads the translated title when there is one.
- **Files:** `util/SpeechText.kt` (new), `ui/reader/ArticleSpeaker.kt` (new), `ui/screens/EntryReaderScreen.kt`.
- **Tests:** new `test/.../util/SpeechTextTest.kt` (5): short text, empty text, a ~22,000-character article split under the limit with every word kept in order, sentence splitting, over-long word.
- **Verified on the emulator:** on "Exploits and vulnerabilities in Q2 2026" (3,195 words, already read), Read aloud bound to Google TTS only when tapped, the engine logged a synthesis request, the button switched to "Stop reading aloud", and tapping it again returned it to "Read aloud".

### Fix 5: Day dividers — wrong chips, wrong day, unformatted briefings (medium)

- **Problems (in Gemini's day dividers):**
  1. The topic chips were guessed in the app from story key entities, CVE numbers in titles, and **tags**. Every tag chip opened a **threat actor** profile named after the tag (e.g. "ransomware"), which usually failed with "not found".
  2. The day's key for the AI briefing was the **UTC** date while the divider label ("Today") is the local date, so for part of every day outside UTC the briefing button fetched the wrong day.
  3. The briefing was shown as raw Markdown (`## TL;DR`, `**…**`, `[title](/?entry=…)`), and its article links didn't work.
  4. When no briefing existed the button stayed "AI briefing" and tapping it did nothing; a failed load looked the same.
- **Fix (matches the website's day header, read from the live web bundle):**
  - Chips come from `GET /api/entries/day-intel?since=&before=` (the local day's bounds in UTC, as the web computes them) with the list's filters (`feed_id`, `category_id`, `is_starred`, `is_bookmarked`, `dedup=true`). They show, in the web's order: "N actively exploited", a newly tracked actor/malware (★), the top technique, sector, CVE (with KEV and CVSS), actor, malware, product and country, each with real ids, so a tap opens the right profile. The row scrolls sideways instead of wrapping. Chips load when a divider first scrolls into view, and again after a refresh or a scope change.
  - The briefing (`GET /api/entries/daily-summary`) is fetched for the **local** day with the same filters, and rendered with the article renderer (headings, lists, bold, links) via the new `util/MarkdownText`. Links of the form `<server>/?entry=<id>` open the article **in the app** (`util/InAppLinks.entryId`, which only accepts links on the signed-in server); other links open in the browser.
  - The button shows "Loading…", "AI briefing"/"Hide briefing", "No briefing" (tapping explains that briefings are generated on the website and the app never spends AI tokens), or "Retry briefing" after a failure. The footer says when it was generated and that reading it uses no AI tokens. The app still **never** generates or regenerates a briefing (no `POST /daily-summary`).
  - Day data is tied to the list scope: it's cleared on a scope change, on pull-to-refresh and on sign-out, and responses for a previous scope are dropped (`dayDataGeneration`).
  - Day row keys are now `day:<yyyy-MM-dd>` with a guard against repeats (a repeated key crashes `LazyColumn`).
- **Files:** `data/model/UserContentModels.kt` (new `DayIntel`, `DayTopEntity`, `DaySignals`, `DayNewEntity`), `data/network/IntelFeedApi.kt` (`getDayIntel`; `getDailySummary` takes the filters), `data/repository/IntelFeedRepository.kt` (new `DayScope`, `getDayIntel`, `getDailySummary(dayKey, scope)`), `util/DateUtils.kt` (`localDayKey`, `dayBounds`; `isoDayKey` is kept but unused), `util/MarkdownText.kt` (new), `util/InAppLinks.kt` (new), `ui/IntelFeedViewModel.kt` (`loadDayIntel`, `loadDailySummary` rewritten, `resetDayData`; state `dayIntel`, `dailySummaryErrors`), `ui/components/EntryCards.kt` (`DayHeader` rewritten, new `DayChipView`), `ui/screens/FeedScreen.kt` (`DayRow`, `buildFeedRows`; the guessing code `extractTopicalChips` is removed).
- **API changes:** `DayHeader(label, dayKey, dayIntel, dayIntelKnown, onLoadDayIntel, dailySummary, summaryChecked, summaryLoading, summaryFailed, onRequestSummary, serverUrl, onOpenLink, onEntityClick)` replaces the old signature (`topicalChips`, `onEntityClick(type, id, name)`). `FeedRow.Day` no longer has `topicalChips`. `getDailySummary(dayKey)` → `getDailySummary(dayKey, scope = DayScope())`.
- **Tests:** new `util/DayDividerTest.kt` (8: local day key vs UTC, day bounds incl. a 25-hour DST day, the live day-intel payload, a quiet day, briefing Markdown → blocks, inline edge cases incl. `javascript:` links dropped and snake_case, in-app link host check) and `data/DayIntelContractTest.kt` (2: query parameters). `ApiContractTest.dailySummaryCanBeNull` now expects `&dedup=true`, which the web sends. **76 unit tests, 0 failures.**
- **Verified on the emulator (live server):** Unread showed "Today" with "30 actively exploited" and "ttp T1036.005 Match Legitimate Resource Name or Location" (request `day-intel?since=2026-09-22T04:00:00.000Z&before=2026-09-23T03:59:59.999Z&dedup=true`, the emulator is on US Eastern time); Today's briefing showed "No briefing"; Yesterday's briefing rendered with headings and paragraphs; its "Mind the (Patch) Gap, Part 2" link opened that article in the app (it was already read, so nothing was marked); the technique chip opened `ttps/by-technique/T1036.005`; after pull-to-refresh the chips were fetched again. (That last point was a bug in the first version of this fix, found and fixed during the test: the divider stays on screen, so its load effect is now keyed on whether the day's data is present.)

### Fix 6: Smaller bugs in campaigns and search filters (medium/low)

1. **The search filter sheet would crash on Android 7.x.** Its Apply button used `java.time.LocalDate`, which only exists from Android 8 (API 26); the app's `minSdk` is 24 and core-library desugaring isn't enabled. Replaced with `Calendar`/`SimpleDateFormat` (`daysAgo()` in `SearchScreen.kt`). There's no other `java.time` use in the app.
2. **The filter sheet read any date filter as "Past 7d".** Opening it on a query with `date:>=` (from the 24h or 30d preset, a saved search, or typed by hand) preselected 7 days, and Apply replaced the original range. It now works out which preset the date matches (`timeRangeOf`), and a date that isn't a preset appears as its own "Since yyyy-MM-dd" choice, kept on Apply.
3. **Adding several selected articles to a campaign sent one request per article** and could half-succeed (some added, then "Failed to attach"). It now uses the web's bulk route, `POST /api/campaigns/{id}/entries/bulk {"entry_ids": […]}`, in one request (a single article still uses `POST /api/campaigns/{id}/entries`). New `IntelFeedRepository.attachEntriesToCampaign(campaignId, entryIds)`, `IntelFeedApi.attachEntriesToCampaign`, model `EntryIdsRequest`.
4. **The campaign picker showed raw exception text** (`localizedMessage`); it now uses `ErrorText`. A campaign the article is already in (✓ Added) can no longer be tapped to post it again.
5. **A campaign profile's Articles tab didn't page.** It always fetched page 1 and reported the page size as the campaign's article count. It now follows `next_cursor` (new `PagedSection.nextCursor`) and uses the server's total, falling back to the campaign's own count.
6. **Lint:** moving the notification permission check into `canPostNotifications` (fix 3) hid it from lint's `MissingPermission` check; `notify()` now also catches `SecurityException` (the permission can be revoked at any time). `FeedDrawerSheet`'s `modifier` is the first optional parameter again (`ModifierParameter` warning).
- **Checked, not changed:** `CreateCampaignRequest` sends `status: "active"` and `tlp_marking: "TLP:GREEN"`. These match the defaults of the website's own New Campaign form, so the app isn't downgrading a marking.
- **Files:** `ui/screens/SearchScreen.kt`, `ui/components/CampaignPickerSheet.kt`, `ui/entity/EntityViewModel.kt`, `data/repository/IntelFeedRepository.kt`, `data/network/IntelFeedApi.kt`, `data/model/IntelModels.kt`, `notifications/IntelNotificationHelper.kt`, `ui/screens/FeedDrawer.kt`.
- **Verified:** `lintDebug` has 0 errors (only dependency-version notices remain). On the emulator, the campaign "Operation Sentinel" (opened through the notification route) loads its articles with `GET /api/entries?campaign_id=…&limit=30` and its tab says "Articles · 2". Adding to a campaign was **not** exercised (it changes shared data); the bulk request shape comes from the live web bundle.

### Fix 7 (inventory P0): Unread counts on every view, and the missing Watched view

- **Gap:** the inventory's first P0 list asks for the quick views (Unread, Priority Queue, Last 24h, This Week, **Watched**, Bookmarked, Starred) as distinct destinations **with accurate counts**. The app had no counts on views, and no Watched view at all.
- **Added (same requests as the live web sidebar, read from its bundle):**
  - **Watched** view: `FeedFilter.WATCHED` → `GET /api/entries?watched=true` (articles about entities on your watchlist, read and unread, like the web). It's in the drawer and the filter chips (eye icon), with its own empty state that explains how to watch something.
  - **Unread counts** in the drawer next to each view: `GET /api/entries/count?is_read=false&dedup=true` plus the view's filter (`since` for 24h/7d rounded down to the hour, `watched`, `is_starred`, `is_bookmarked`), all in parallel. The Priority Queue count is `GET /api/entries/priority-unread-count` plus open stories with unread articles (`GET /api/threads?status=open&limit=40`), exactly as the web adds them. A zero or unknown count shows no badge.
  - The toolbar subtitle uses the server count: "35 unread" on Unread; "… · 3 unread" on the other views (unless a feed or folder narrows the list, where it counts what's loaded, as before).
  - Counts load at sign-in, on pull-to-refresh, after mark-all-read and bulk actions, and when the drawer opens if they're over a minute old. Reading or un-reading an article in the app adjusts the Unread count straight away.
  - The entry **list** doesn't send `dedup`: the server's default is already `dedup=true` (API docs), so lists are unchanged.
- **Files:** `data/repository/IntelFeedRepository.kt` (`FeedFilter.WATCHED`, new `ViewCounts`, `getViewCounts()`, `getEntries` sends `watched`), `data/network/IntelFeedApi.kt` (`getEntries(watched)`, `countEntries`, `getPriorityUnreadCount`), `data/model/EntryModels.kt` (`EntryCount`, `PriorityUnreadCount`), `ui/IntelFeedViewModel.kt` (state `viewCounts`, `loadViewCounts(force)`, Unread adjusted in `applyEntryUpdate`), `ui/screens/FeedDrawer.kt` (badges, Watched icon), `ui/screens/FeedScreen.kt` (Watched chip, empty state, subtitle), `Navigation.kt` (refresh counts when the drawer opens).
- **Note for Gemini:** `FeedFilter` has a new value, so every exhaustive `when (filter)` needs a `WATCHED` branch.
- **Tests:** new `data/ViewCountsContractTest.kt` (4). **80 unit tests, 0 failures.**
- **Verified on the emulator (live server):** all eight count requests returned 200 (the unread ones take 4–6 s on the server, in parallel, without blocking anything); the drawer showed Priority Queue 9 (7 stories + 2 articles, matching the queue), Unread 35 (matching the list's own total), Last 24 hours 33, This week 35, Watched 3. The Watched view loaded with `watched=true` and showed "30+ articles · 3 unread".

### Fix 8 (inventory P0): Saved searches as drawer destinations, with counts

- **Gap:** the inventory says saved searches are navigational destinations in the web sidebar (with unread/total counts), "not merely search history". In the app they were only on the Search tab's home screen.
- **Added:**
  - A **Saved searches** section in the feeds drawer, between the views and the folders: each row shows the name, the query (when it differs from the name) and its total ("46 articles"), with the unread count as a badge (`unread_count`/`total_count` from `GET /api/saved-searches`).
  - Tapping one does what the web does (its `useOpenSavedSearch` loads the search and goes to `/search`): the drawer closes, the **Search** tab opens and runs the query in the search's saved scope (`filters.scope`: `everything` → Everything, `workbench` → Entities, `feeds` → Articles). The Search tab's own saved-search list now also applies the saved scope (`IntelFeedViewModel.openSavedSearch`). Deleting stays a long-press on the Search tab.
  - Saved searches (and their counts) are reloaded together with the view counts (fix 7).
- **Files:** `data/model/SearchModels.kt` (`SavedSearch.filters`, new `SavedSearchFilters`), `ui/IntelFeedViewModel.kt` (`openSavedSearch`; saved searches refreshed in `loadViewCounts`), `ui/screens/FeedDrawer.kt` (section + `SavedSearchItem`; new optional parameter `onOpenSavedSearch`), `ui/screens/SearchScreen.kt`, `Navigation.kt`.
- **Tests:** `ViewCountsContractTest.savedSearchesDecodeWithTheirScope` (the live payload, one with `"filters": {}` and one with a scope). **81 unit tests, 0 failures.**
- **Verified on the emulator:** the drawer lists `"device code phishing"` (190 articles, 3 unread) and "Warp Panda" (46 articles); tapping Warp Panda opened Search and ran it (`POST /api/search/unified`, 13 s on the server) with "Articles · 46", matching the saved total.

### Fix 9 (inventory P0): Feed details when one feed is selected, and a correct empty message

- **Gap:** the inventory notes that the web's single-feed view shows the feed's type, unread count, last fetch age and polling cadence; the sidebar shows curation labels ("Selective — security-relevant articles only", "Known entities only — …") and a ⚠ for failing feeds. The app only showed the feed name.
- **Added:**
  - `FeedSource` now reads `fetch_interval_minutes`, `last_error`, `intel_extraction_mode` and `auto_extract_on_ingest` (already in the live `GET /api/feeds` payload), and has `curationLabel` (the web's exact rules and wording, including "no mode counts as selective") and `typeLabel` ("RSS", "GitHub repo", …).
  - The scope banner above the list, for a single feed: "RSS · 0 unread · fetched 7m ago · checked every 30 min" (+ "muted"/"paused" when relevant), the curation label, and, when fetching fails, "⚠ The last N fetches failed: <last error>". The drawer's ⚠ now has a spoken label ("Fetch errors").
  - **Wording bug fixed:** with a feed or folder selected while the Priority Queue view was active, an empty list said "Nothing urgent right now — no unread article clears the priority threshold", but that view shows the scope's unread articles (the queue can't be narrowed on the server). It now says "All caught up — No unread articles in "<feed>"."
- **Files:** `data/model/EntryModels.kt` (`FeedSource`), `ui/screens/FeedScreen.kt` (`ScopeBanner`, `pollInterval`, `FeedEmptyState`), `ui/screens/FeedDrawer.kt`.
- **Tests:** new `data/FeedDetailsTest.kt` (3: the web's curation rules, the live feed payload, type labels). **84 unit tests, 0 failures.**
- **Verified on the emulator:** selecting "Hacker Combat" showed "RSS · 0 unread · fetched 7m ago · checked every 30 min", "Known entities only — match against existing database", "⚠ The last 4534 fetches failed", and the empty list said "No unread articles in "Hacker Combat"."

### Fix 10 (inventory P0): Keep your place — back from an article, between tabs, after swiping

- **Gap / bugs:** the inventory's first P0 item is "preserve source context and list position across queue/view → list → reader → dossier → back". Four problems:
  1. **Back from an article or profile scrolled the list to the top.** Navigation3 re-creates the Home screen when you come back, and three "scroll to top" effects ran again on re-creation: the feed's (after any filter/feed change during the session), the search results' (always), and the Workbench list's (always).
  2. **Switching tabs lost the feed's position.** Feed, Workbench and Search were swapped by a plain `when`, so each tab's scroll state was thrown away when another tab was shown.
  3. **After swiping through articles in the reader, Back returned to where you started**, not the article you ended on, which could be many screens further down.
  4. **Auto mark-read wasn't visible**: the inventory asks to "explain whether opening an article auto-marks it read; expose that preference or provide clear feedback".
- **Fix:**
  1. Each scroll-to-top effect remembers (with `rememberSaveable`) the value it last handled — `feedScrollToTop`, the submitted query, the Workbench tab — and only scrolls when it really changes (`FeedScreen`, `SearchScreen.SearchResults`, `WorkbenchScreen`).
  2. `HomeShell` wraps the tabs in a `SaveableStateHolder` keyed by tab, so each keeps its scroll position and saved UI state while hidden.
  3. When the reader walks the feed list (`Route.Reader.contextIds == null`), it reports the page it settles on (`onSettledEntry` → `IntelFeedViewModel.setFeedFocus`). Back on the feed, if that article isn't fully on screen, the list scrolls to it (one row above, so its day divider shows), then clears the focus (`feedFocusEntryId`, list and grid).
  4. The reader shows the read state as a tappable chip before the tags: "Unread · mark read", "Read · mark unread", or **"Marked read on open · undo"** when the auto-mark-read setting just marked it (`ReaderUiState.autoMarkedRead`). The setting itself is still in Settings.
- **Files:** `Navigation.kt`, `ui/screens/FeedScreen.kt`, `ui/screens/SearchScreen.kt`, `ui/screens/WorkbenchScreen.kt`, `ui/screens/EntryReaderScreen.kt` (new optional `onSettledEntry`; `ReaderBody` takes `onToggleRead`), `ui/reader/ReaderViewModel.kt`, `ui/IntelFeedViewModel.kt` (`feedFocusEntryId`, `setFeedFocus`, `clearFeedFocus`).
- **Rule for future code:** any screen under Navigation3 is re-created on Back. Don't put one-shot actions (scroll to top, show a dialog, mark something) in a `LaunchedEffect` keyed only on current state; remember what was already handled with `rememberSaveable`, or trigger them from the event itself.
- **Verified on the emulator:** in the feed "Cyber News Group" (All articles, nothing unread, so nothing was marked): scrolled down, Feed → Search → Feed kept the same article on screen; opened article 7 of 21, swiped to 13 of 21 (0 mark-read requests; chip "Read · mark unread"), Back showed that 13th article ("Hackers attack Iranian apps…") under its "Mar 3" divider; in Workbench, scrolled down, opened a profile, Back kept the same row on screen. **84 unit tests, 0 failures.**

### Fix 11 (inventory P0): Shared IntelFeed article links open the article

- **Gap:** the inventory asks for deep links to a specific article. Sharing an IntelFeed article link (`https://<server>/?entry=<id>`, the web's article URL, also used in AI briefings) to the app offered to **ingest it as a new article**.
- **Fix:** `MainActivity` checks a shared link with `InAppLinks.entryId(url, serverUrl)` (fix 5); a link to an article **on the signed-in server** opens that article in the reader. Any other link still asks "Add to IntelFeed?" as before. No new intent filter or exported entry point was added.
- **Files:** `MainActivity.kt`.
- **Verified on the emulator:** sharing "Look at this https://intelfeed.cc/?entry=3fd1fd56-…" opened "Exploits and vulnerabilities in Q2 2026" (an already-read article) with no prompt; sharing `https://example.com/some-article` still showed "Add to IntelFeed?", which was cancelled (no ingest request sent).

### Fix 12 (security): Session tokens encrypted at rest with an Android Keystore key

- **Problem:** the DataStore file stored the access token and the 7-day refresh token in plain text (listed as a known issue since the first session). Backups were already excluded, but on a rooted or compromised device, or from a forensic copy of app data, the refresh token gave a week of access to the account.
- **Fix:**
  - New `data/local/TokenCipher`: AES-256-GCM with a key generated in the **Android Keystore** (alias `intelfeed_session_tokens`; it can't be exported from the device). Stored form `v1:<hex iv>:<hex ciphertext>`, with a fresh random IV each time.
  - `AuthPreferences` encrypts in `saveAuthTokens` and decrypts in the `accessToken`, `refreshToken` and `isLoggedIn` flows. The last decrypted value is cached, because the auth interceptor reads the token for every request and each Keystore decrypt is a binder call.
  - **Existing sessions are migrated without signing out:** plain values from older versions are still read, and `AuthPreferences.encryptStoredTokens()` re-saves them encrypted at app start (`IntelFeedApplication`, on a background scope). It only replaces a value that hasn't changed in the meantime.
  - **Can't lock anyone out or crash:** if the Keystore can't give a key, tokens are stored as before; if a stored token can't be decrypted (key removed or invalidated), the session counts as signed out and the login screen shows.
  - Server URL, username and reading preferences stay plain (not secret).
- **Files:** `data/local/TokenCipher.kt` (new), `data/local/AuthPreferences.kt` (constructor takes a `cipher`, defaulting to `TokenCipher.androidKeystore()`; new `encryptStoredTokens()`), `IntelFeedApplication.kt`.
- **Rule for future code:** never write a token to DataStore except through `AuthPreferences.saveAuthTokens`, and never log or display token values.
- **Tests:** new `data/TokenCipherTest.kt` (5, with a software AES key): round trip, fresh IV, legacy plain value read as is, no key → kept rather than lost, wrong key or tampered value → null. **89 unit tests, 0 failures.**
- **Verified on the emulator** (installed over the existing plain-text session; token values were counted, never printed): before launch the DataStore file had 2 JWT-looking strings; after launch it had 0, and 2 `v1:` values; the app stayed signed in and all 15 requests returned 200. After a force-stop and cold start it was still signed in, 15/15 requests returned 200, and the crash log was empty. **Not exercised:** a fresh sign-in and a token refresh (both go through `saveAuthTokens`, which now encrypts). They need the user's password or waiting for the access token to expire.

### Fix 13 (speed): Shared connections, more parallel requests, faster date parsing

- **Images share the API's connection pool.** `ApiClient.imageHttpClient()` is now built from the API client (`newBuilder()`, interceptors removed, own `Dispatcher`), so proxied images from the IntelFeed server reuse the open HTTP/2 connection instead of a new TLS handshake. Images keep their own request queue, so a screen full of thumbnails can't delay API calls. The token is still only sent to the server's own origin.
- **Up to 16 parallel API requests per host** (OkHttp's default is 5). The app starts ~13 requests at once (feed, folders, eight view counts, Workbench, saved searches), and some take 4–10 s on the server, so the feed could queue behind the counts. The server speaks HTTP/2 (checked with `curl --http2`), so this adds no connections.
- **Date parsing** (`DateUtils.parseDate`, run for every card on every redraw) caches results (up to 1,024 strings), reuses one set of formatters per thread, and uses `parse(text, ParsePosition)`, which returns null instead of throwing. It used to create up to 8 `SimpleDateFormat`s per call and throw a `ParseException` per pattern that missed. Results are unchanged (all date tests pass).
- **Files:** `data/network/ApiClient.kt`, `util/DateUtils.kt`.
- **Verified:** 89 unit tests, 0 failures; on the emulator, an article with proxied images and the feed load normally (26/26 requests returned 200).
- **Checked, not a bug:** in "Exploits and vulnerabilities in Q2 2026", several chart captions show without charts. A temporary debug log (removed) showed the feed's HTML only contains 2 of the images (the hero and one chart), so the parser is rendering everything it receives. Same result with the old image client.

### State at the end of this session

- `./gradlew :app:testDebugUnitTest :app:assembleDebug` succeeds; **89 unit tests, 0 failures** (55 at the start). `lintDebug`: 0 errors (last run after fix 6; only dependency-version notices).
- The debug build is installed on `emulator-5554`, signed in; its tokens are now stored encrypted.
- Side effects on the live account from testing: a few articles were marked read by opening them in the reader (as designed); one test notification was posted on the emulator. No feeds, articles, notes, tags, campaigns or saved searches were created, changed or deleted.

### Still to do (not started, in suggested order)

**From the inventory (P1):**
1. **Hide read + sort** in the feed toolbar (the web's "Hide Read" toggle and newest/oldest sort; `GET /api/entries` takes `sort=newest|oldest`). Remember the choice in `UserPreferences`.
2. **Intel cues on cards** like the web: `POST /api/entries/intel-counts` with a JSON array of up to 100 entry ids returns per-entry `pir_matches`, `actors`/`actor_count`, `malware`/`malware_count`, `cves`, `cve_max_severity`, `ttps`, `rules`, `notes`, `detection_opportunity`, `has_detection_gap`, `has_high_risk_cve`. Verify the exact response shape read-only before modelling it (it's a POST but doesn't change anything).
3. **Mark a day read** from its divider (the web offers it), with a confirmation.
4. **Tappable tags** on cards and in the reader that run a `tag:"name"` search.
5. **Search:** a "Has notes" filter (`is:noted`) and a sort choice (`sort:newest|oldest|relevance`) in the filter sheet; feed and tag facets.
6. **Auto-read on scroll** (the web's "Auto-read" toggle), off by default because it marks articles read in bulk.
7. **Profile timeline tab** (the inventory's P2): `GET /api/intelligence/timeline/{type}/{id}` and `GET /api/engine/entities/{type}/{id}/whats-new` (both seen on the live server in the second session).

**Security / quality:**
8. **R8/minification for release builds** (needs keep rules for kotlinx.serialization and Retrofit, then a full test on a device).
9. **HTTP (cleartext) servers:** `ServerUrl` accepts `http://`, but Android blocks cleartext by default (targetSdk 36), so such a server fails with a vague network error. Either say so on the login screen or add a network security config.
10. **Not exercised against the live server** (they change shared data): subscribing to a feed, adding an article, bulk add to campaign, sign-in and token refresh with the new encryption. Their request shapes are covered by unit tests and the web bundle.

**Deliberately left to the website** (per the inventory's own P2 advice): dashboards, reports, requirements, automation, glossary, ransomware, Telegram mentions, the ATT&CK matrix, AI generation/Copilot, admin settings, the extra Add Feed tabs (GitHub, scraper, Bluesky, Telegram, OPML), and "Wrong?" entity corrections.

---

## 2026-09-23 (fourth session): Working through the "Still to do" list

Continues the third session's list, in its order. Each item is logged as soon as it's done.

### Item 1: "Hide read" and newest/oldest sort for the feed

- **Gap:** the web toolbar has **Hide Read** and a sort order; the app had neither.
- **Added:** two options in the feed's ⋮ menu, saved on the device (`UserPreferences.feedHideRead`, `feedSort`):
  - **Hide read articles** (checkbox): date-ordered views (Last 24h, This week, Watched, All, Starred, Bookmarked) request `is_read=false`. Not offered on Unread (already unread-only) or the Priority Queue.
  - **Show oldest first / newest first**: `GET /api/entries?sort=oldest|newest`. Not offered on the unscoped Priority Queue, which is ranked. Day dividers work in either order.
  - Changing either reloads the list. The subtitle says "30+ unread" and "oldest first" when they're on; an empty list explains "Everything in this view is read. Turn off "Hide read articles"…".
- **Files:** `data/local/UserPreferences.kt`, `data/repository/IntelFeedRepository.kt` (`getEntries(…, hideRead, sort)`), `ui/IntelFeedViewModel.kt` (state `feedHideRead`, `feedSort`; `setFeedHideRead`, `setFeedSort`), `ui/screens/FeedScreen.kt` (`ListOptions`, menu items, subtitle, empty state).
- **Verified on the emulator:** in Last 24 hours, Hide read sent `…/api/entries?is_read=false&since=…&sort=newest` and the subtitle became "30+ unread"; oldest first sent `sort=oldest`, the list started with the 22-hour-old articles and the subtitle read "30+ unread · oldest first". Both were switched back off afterwards ("30+ articles · 48 unread").

### Item 2: Intel cues on article cards (the web list's badges)

- **Gap:** the inventory lists card cues the web shows — PIR matches, extracted actors/malware, CVEs/KEV, TTPs, detection opportunity — "without crowding cards". The app showed only the ranking signals.
- **Server contract (checked on the live server with a temporary debug-only log, since removed):** `POST /api/entries/intel-counts` with a bare JSON array of entry ids (the web sends batches of up to 100) returns `{ "<entry id>": { ttps, cves, rules, notes, ai_results, total, has_detection_gap, detection_opportunity ("actionable_gap"), has_high_risk_cve, has_kev_cve, high_value, pir_matches: [{id, title, priority, category, match_type, matched_on, relevance}], actors: [names], actor_count, malware: [names], malware_count, cve_max_severity } }`. Entries with nothing extracted are left out. It only reads.
- **Added:** one request per loaded page (feed and search results), then a row of small cues under the snippet, in the web's order: **PIR ×N** (red if any matched requirement is critical), the lead **actor/malware** "+N", **N CVEs** coloured by highest severity with "· KEV", **N TTPs**, **Detection gap**, **N rules**, **N notes**. Screen readers get one sentence (e.g. "Matches 2 intelligence requirements: …"). Hidden in compact density; not on grid cards. Cues are fetched again on pull-to-refresh, because extraction can finish after an article first appears.
- **Files:** `data/model/EntryModels.kt` (`EntryIntelCounts`, `PirMatch`), `data/network/IntelFeedApi.kt` (`getIntelCounts`), `data/repository/IntelFeedRepository.kt` (`getIntelCounts(ids)`, batches of 100), `ui/IntelFeedViewModel.kt` (state `intelCounts`, `loadIntelCounts`), `ui/components/EntryCards.kt` (`EntryCard(intel = …)`, `intelCues`, `IntelCueRow`), `ui/screens/FeedScreen.kt`, `ui/screens/SearchScreen.kt`.
- **Tests:** new `data/IntelCuesTest.kt` (3: the live payload, the cue rules, the request body is a bare array). **92 unit tests, 0 failures.**
- **Verified on the emulator:** Unread sent two `POST /api/entries/intel-counts` (200, ~400 ms, one per page); cards showed e.g. "13 CVEs" (critical, red) + "Detection gap", and "PIR".

### Item 3: Mark a day read from its divider

- **Gap:** the web's day header can mark that day read; the app couldn't.
- **Added:** a ✓✓ button on a day divider when the loaded articles under it include unread ones. It asks first ("Mark Today as read? Every unread article published on this day in all of your feeds / in "<feed>" will be marked as read, including ones not loaded yet. This can't be undone."), then sends what the web sends: `POST /api/entries/mark-all-read {feed_id?, category_id?, since, before}` with the local day's bounds. The list, drawer counts and view counts reload afterwards.
- `MarkAllReadRequest` gained optional `since`/`before`, left out of the JSON when unset, so the plain "mark all read" request is unchanged.
- **Files:** `data/model/EntryModels.kt`, `data/repository/IntelFeedRepository.kt` (`markDayRead`), `ui/IntelFeedViewModel.kt` (`markDayRead(dayKey, label)`), `ui/screens/FeedScreen.kt` (`FeedRow.Day.unread`, confirmation in `DayRow`), `ui/components/EntryCards.kt` (`DayHeader(onMarkDayRead = …)`).
- **Tests:** `DayIntelContractTest.markDayReadSendsTheDayBoundsAndMarkAllDoesNot`. **93 unit tests, 0 failures.**
- **Verified on the emulator:** the button appears on "Today" in Unread and opens the confirmation shown above; it was **cancelled** (no `mark-all-read` request was sent), because confirming would mark a whole day of real articles read.

### Item 4: Tappable tags — and the reader now shows an article's tags

- **Added:** tapping a tag on a feed card, grid card, search result or in the reader runs `tag:<name>` on the Search tab, scoped to Articles (`IntelFeedViewModel.searchTag`; names with spaces are quoted). From the reader it first returns to the home screen, as the web goes to its search page. Tags on cards aren't tappable while multi-selecting.
- **Bug found while testing (reader):** the reader took an article's tags from the `tags` field of `GET /api/entries/{id}`, which is **empty** on the live server for articles that do have tags (seen on an article tagged `morning-brief` in search results; the reader showed only "Add tag"). The web loads them from `GET /api/tags/entries/{id}`; the reader now does too, when the article is on screen. A tag the user adds or removes before that load finishes isn't overwritten.
- **Files:** `ui/IntelFeedViewModel.kt` (`searchTag`), `ui/components/EntryCards.kt` (`EntryCard`/`EntryGridCard(onTagClick = …)`), `ui/screens/FeedScreen.kt`, `ui/screens/SearchScreen.kt`, `ui/screens/EntryReaderScreen.kt` (new optional `onSearchTag`; `ReaderBody(onTagClick)`), `ui/reader/ReaderViewModel.kt` (tags from `getEntryTags`), `Navigation.kt`.
- **Verified on the emulator:** a `#morning-brief` chip on a search result ran `tag:morning-brief` (the server parsed it as "tag: morning-brief"); opening that article, the reader called `GET /api/tags/entries/acf335fa-…` (200) and showed `#morning-brief` + "Edit tags" (before the fix: only "Add tag"); tapping it closed the reader and ran the tag search. No mark-read requests (the article was already read). **93 unit tests, 0 failures.**

### Item 5: More search filters (notes, sort, feeds, tags)

- **Added to the search filter sheet** (field names from `docs/query-language.md`):
  - **Has analyst notes** → `is:noted`.
  - **Sort**: Best match (default), Newest, Oldest, Highest score (`sort:newest|oldest|radar`; for radar the sheet notes that the server ignores keywords). A sort the sheet doesn't offer, typed by hand, is kept unless another is chosen.
  - **Feeds**: pick one or more feeds from your feed list (type to filter) → `feed:"Name"` each.
  - **Tags**: comma-separated → `tag:x` each (an article must have all).
  - Existing tokens are read back when the sheet opens, so Apply never drops part of the query. New `util/SearchTokens` reads and rewrites `field:value` tokens and **leaves negated ones (`-tag:x`, `NOT feed:x`) alone** so their meaning can't flip. The filter button lights up for these fields too.
- **Files:** `util/SearchTokens.kt` (new), `ui/screens/SearchScreen.kt` (`SearchFilterSheet(feeds = …)`, `SortChoice`).
- **Tests:** new `util/SearchTokensTest.kt` (5). **98 unit tests, 0 failures.**
- **Verified on the emulator:** on `tag:morning-brief`, the sheet showed "morning-brief" in Tags; choosing Newest and the feed "Cyber News Group" and applying gave a query the server parsed as "sort: newest", "feed: Cyber News Group", "tag: morning-brief" (5 articles).

### Updated to-do list (user request, 2026-09-23)

The user asked for three features, modelled on the website, ahead of the rest of the list:
- **A. Tracked keywords:** add keyword phrases like the web sidebar's Keywords section, see matching articles, and **highlight keyword matches in article text**.
- **B. Entity links inside article text:** on the web, names of known entities (e.g. "ShinyHunters") are highlighted in the article and open that entity's page; do the same in the reader.
- **C. Keyword notifications:** when a new article contains a tracked keyword (e.g. "donkey"), notify the phone.

New order: A → B → C, then the rest (6 auto-read on scroll, 7 profile timeline tab, 8 R8, 9 cleartext message, 10 live-testing the untested writes).

### B (user request): Entity names highlighted in article text, tap to open the profile

- **How the web does it** (read from the current live web bundle, `EntryReader*.js`): the reader takes the entities linked to the article (the same per-article endpoints the app already calls), and for each uses its `matched_names` (the exact phrases the server's linker found in that article) or, failing that, its name and aliases; CVE ids; technique ids and names. It marks whole-word matches (`(?<!\w)term(?!\w)`) in the text, and a click opens the entity.
- **Added:**
  - `matched_names` is now read on threat actors, malware, tools, vendors, products and countries (`IntelModels.kt`, field `matchedNames`; only the per-article endpoints send it).
  - New `util/ArticleLinker` marks the phrases in the parsed article: whole words, any case, longest phrase first, never inside links or code, phrases under 3 characters skipped (they matched ordinary words like "US"). New span kinds `ENTITY` and `KEYWORD` (`ArticleHtml.Span` now also carries `entityType`/`entityId`/`entityName`).
  - `ui/reader/ArticleTerms.entityTerms(intel)` builds the phrase list the web's way. The reader applies it off the main thread once the linked intelligence has loaded (the plain text shows until then).
  - `ArticleContent` draws entity names tinted in their type's colour (the same colours as the intel chips); a tap opens the profile. It also takes `onKeywordClick` for tracked keywords (next item).
  - **Settings › Reading › "Highlight entities in articles"** (on by default) turns it off (`UserPreferences.highlightEntities`).
- **Files:** `util/ArticleLinker.kt` (new), `ui/reader/ArticleTerms.kt` (new), `util/ArticleHtml.kt`, `ui/components/ArticleContent.kt`, `ui/screens/EntryReaderScreen.kt`, `ui/reader/ReaderViewModel.kt`, `data/local/UserPreferences.kt`, `ui/screens/SettingsScreen.kt`, `data/model/IntelModels.kt`.
- **Tests:** new `util/ArticleLinkerTest.kt` (6: whole words in any case, longest phrase wins, links/code untouched, short and duplicate phrases dropped, special characters matched literally, no terms → unchanged). **104 unit tests, 0 failures.**
- **Verified on the emulator:** in "Exploits and vulnerabilities in Q2 2026" the CVE ids (red), Microsoft and Windows (blue), and WinRAR (tool) were marked, while the article's own "NTFS Streams" link stayed a normal link; tapping "WinRAR" opened its tool profile (`GET /api/tools/18892b65-…`).

### A (user request): Tracked keywords, highlighted in articles

- **How the web does it (checked in the current live bundle):** the web's old sidebar "Keywords" section is gone (only its collapsed-state setting remains in `uiStore`). Keyword matching now lives in **Intelligence Requirements** (`/api/requirements`: `title, description, priority, category, status, keywords[], expires_at, min_relevance, linked_entities`). The server matches every incoming article against them, and articles show "PIR matches" with `match_type: "keyword"` and `matched_on: "<keyword>"` (via `POST /api/entries/intel-counts`). Requirements are **shared by everyone on the server**.
- **Decision:** your own keywords are kept **on the device** (`UserPreferences.trackedKeywords`, up to 50), so adding one never changes shared server data. Requirement keywords that matched an article are shown and highlighted alongside them. If server-side keywords are wanted later, the app could create a Requirement instead (`POST /api/requirements` with `keywords`); not done because it affects all users.
- **Added:**
  - A **Keywords** section in the feeds drawer: "+ Add" opens "Track a keyword" (explains highlighting and alerts); tapping a keyword searches for it as a phrase on the Search tab (`searchKeyword`); ✕ stops tracking after a confirmation, with Undo.
  - **Highlighting in the reader:** tracked keywords, plus the keywords that made the article match a requirement, are marked in amber (whole words, any case; `ui/reader/ArticleTerms.keywordTerms`, `ArticleLinker` KEYWORD spans). Tapping one searches for it. On the same phrase an entity link wins over a keyword highlight.
  - **"Matches your intelligence requirements"** card in the reader (the web's PIR Matches): each matched requirement with its priority and why it matched ("keyword: zero-day · medium relevance").
- **Files:** `data/local/UserPreferences.kt` (`trackedKeywords`, `addTrackedKeyword`, `removeTrackedKeyword`), `ui/IntelFeedViewModel.kt` (`addKeyword`, `removeKeyword`, `searchKeyword`; state `trackedKeywords`), `ui/screens/FeedDrawer.kt` (section, dialogs, `KeywordItem`; new parameters `onKeywordSearch`, `onAddKeyword`, `onRemoveKeyword`), `ui/reader/ReaderViewModel.kt` (`trackedKeywords`, `pirMatches` from intel-counts), `ui/reader/ArticleTerms.kt`, `ui/screens/EntryReaderScreen.kt` (`PirMatchesCard`, new optional `onSearchKeyword`), `Navigation.kt`.
- **Verified on the emulator:** added "vulnerabilities" from the drawer; in "Exploits and vulnerabilities in Q2 2026" every whole-word "vulnerabilities" was highlighted in amber next to the entity links (Kaspersky, GitHub, OpenClaw); the requirements card listed "Vulnerability Exploitation & Weaponization" (Critical, keyword: zero-day) and "C2 Frameworks & Post-Exploitation Tooling" (High, keyword: c2 framework). **104 unit tests, 0 failures.** (The test keyword "vulnerabilities" is still tracked on the emulator; remove it from the drawer if unwanted.)

### C (user request): Notifications for tracked keywords

- **Added to the background check** (`IntelNotificationWorker`, every 15 minutes when "Background Intel Alerts" is on and Android allows notifications): for each tracked keyword it searches `"<keyword>" is:unread date:>=<2 days ago> sort:newest` (20 results; up to 4 searches at once, since each takes several seconds on the server and a worker run is limited to 10 minutes) and notifies about articles **not seen on an earlier check**. Tapping the notification opens the article (one match) or the keyword search (several).
  - New keywords don't flood: a keyword's first check only records its current matches (`KeywordAlerts.newIds` with no history returns nothing).
  - It tracks seen article ids instead of comparing publish times, because feeds are polled every 30 minutes and new articles often have publish times older than the last check. Seen ids are stored per keyword (`UserPreferences.getKeywordSeenIds`/`setKeywordSeenIds`, 200 per keyword), and dropped when a keyword is removed. Already-read articles never alert.
  - New notification route `EXTRA_ROUTE_KEYWORD` → `Route.Keyword` (validated: at most 100 characters, no control characters) → `IntelFeedViewModel.searchKeyword`.
  - The existing saved-search alert title changed from "Keyword Alert: …" to "Saved search: …" so the two kinds aren't confused. The Settings subtitle now mentions tracked keywords.
- **Files:** `notifications/KeywordAlerts.kt` (new), `notifications/IntelNotificationWorker.kt` (`checkKeywords`), `notifications/IntelNotificationHelper.kt`, `MainActivity.kt`, `data/local/UserPreferences.kt`, `ui/screens/SettingsScreen.kt`.
- **Tests:** new `util/KeywordAlertsTest.kt` (3). **107 unit tests, 0 failures.**
- **Verified on the emulator:** "Check for updates now" ran the keyword search for "vulnerabilities" (`POST /api/search/unified`, 200 in 8.8 s) after the saved-search check; the seen ids were saved and, as designed for a first check, no notification was posted. `am start … --es route_keyword vulnerabilities` (the intent a keyword alert sends) opened Search with "vulnerabilities". **Not yet seen end to end:** an actual keyword notification, which needs a new unread article mentioning the keyword to arrive between two checks.

### State at the end of the fourth session

- `./gradlew :app:testDebugUnitTest :app:assembleDebug :app:lintDebug` succeed: **107 unit tests, 0 failures**; lint 0 errors (only dependency-version notices).
- The debug build is installed on `emulator-5554`, signed in. The emulator has one tracked keyword, "vulnerabilities", added for testing (remove it from the drawer's Keywords section if unwanted). Hide read and oldest-first were switched back off after testing.
- No shared server data was created or changed in this session (no feeds, articles, notes, tags, campaigns, requirements or saved searches; the "mark day read" confirmation was cancelled). Reading test articles only touched already-read ones.

### Still to do

1. **Auto-read on scroll** (the web's "Auto-read" toggle), off by default because it marks articles read in bulk.
2. **Profile timeline tab**: `GET /api/intelligence/timeline/{type}/{id}` and `GET /api/engine/entities/{type}/{id}/whats-new` (both seen on the live server).
3. **R8/minification for release builds** (keep rules for kotlinx.serialization and Retrofit, then a full device test).
4. **HTTP (cleartext) servers**: `ServerUrl` accepts `http://` but Android blocks cleartext (targetSdk 36); explain it on the login screen or add a network security config.
5. **Live-test the untested writes**: subscribing to a feed, adding an article, bulk add to campaign, mark a day read, sign-in and token refresh with encryption, and a real keyword notification end to end.
6. **Optional, needs a decision:** server-side keywords as Intelligence Requirements (`POST /api/requirements` with `keywords`). They'd be matched by the server and visible to everyone on the instance, unlike the device-only keywords.

---

## 2026-09-23 (fifth session): Finishing the list, keywords first

The user asked to finish the remaining list, keyword functionality first. Each item is logged when done.

### Keyword alerts tested end to end, and three fixes from the test

- **End-to-end result:** with the keyword "BIG-IP" tracked, the article "Hackers Exploiting F5 BIG-IP OAuth Server 0-day Flaw to Gain Remote Code Execution" (made a new unread match by marking it unread) produced the notification **"Keyword: BIG-IP — Hackers Exploiting F5 BIG-IP OAuth Server 0-day Flaw…"** on the next check. The article was marked read again afterwards. (It had been read before the test; the only account change was flipping it unread and back.)
- **Fix 1 — too few results per check:** the check looked at the 20 newest matches. For a common word ("vulnerabilities") newer matches filled all 20, so an older new match was never seen. Now `KeywordAlerts.RESULTS_PER_CHECK = 50`. (On the test emulator this caused one grouped "30 new articles mention "vulnerabilities"" alert, because matches 21–50 had never been recorded. Real users never had the 20-result version.)
- **Fix 2 — removing a keyword kept its history** until the next check, so removing and re-adding it straight away silently reused the old seen list. `UserPreferences.removeTrackedKeyword` now also drops that keyword's history.
- **Fix 3 — alerts for already-read articles:** the server's search index lags behind read state. An article read two minutes earlier was still returned by `is:unread` (seen in the app's own search: `"BIG-IP" is:unread` listed it). The worker now confirms each new match with `GET /api/entries/{id}` (`is_read`, a plain read) before alerting, for up to 10 per keyword and check.
- **Android behaviour to know:** with several IntelFeed alerts showing, Android bundles them under an automatic group summary; tapping the summary opens the app normally (Android's own launch intent), while tapping an individual alert follows its route. The route itself was verified with the identical intent extras (`am start … --es route_entry_id …` / `route_keyword`).
- **Files:** `notifications/KeywordAlerts.kt`, `notifications/IntelNotificationWorker.kt`, `data/local/UserPreferences.kt`.
- **107 unit tests, 0 failures.**

### Server-side keywords: Intelligence Requirements screen, and an opt-in when adding a keyword

The website's keyword matching is its **Intelligence Requirements** (shared by everyone on the server; the server tags every new article that matches a requirement's keywords). The app now shows them and can add one, while tracked keywords stay on the device by default.

- **New screen, "Intelligence requirements"** (drawer → Keywords → **Server requirements**; `Route.Requirements`): every requirement from `GET /api/requirements`, active first, then by priority (critical → low), with priority pill, category, match count ("4,801 matches"), when it last matched, description and keyword chips. Keywords you also track on the device are green. Tap a card to expand it: all keywords plus **recent matches** from `GET /api/requirements/{id}/matches` (title, which keyword matched, relevance, time). Tapping a match opens the article, with next/previous across the matches. Tapping a keyword chip searches for it. Pull to refresh.
- **"Track a keyword" dialog:** new checkbox **"Also add as a server requirement"**, off by default (a requirement is visible to everyone on the server, so it's never created silently). When ticked, the app first checks whether an existing requirement already lists that keyword (then it just says so), otherwise it sends `POST /api/requirements {title, priority:"medium", category:"operational", keywords:[keyword]}` — the website form's defaults; description is left out when empty. A server refusal (for example a read-only account) is shown as a message; the device keyword is still added. The dialog text no longer says "on this device only".
- **Live shapes checked read-only** on the server first: the list is `{"items":[{id, title, description, priority, status, category, keywords[], match_count, last_matched_at, auto_match, …}]}`; matches are `{"items":[{requirement_id, entry_id, match_type, matched_on, matched_at, relevance, entry_title, entry_url, entry_published_at}]}`. The create body comes from the current web bundle's requirement form.
- **Files:** `ui/screens/RequirementsScreen.kt` (new: `RequirementsViewModel` + screen), `ui/navigation/Routes.kt`, `Navigation.kt`, `ui/screens/FeedDrawer.kt`, `ui/IntelFeedViewModel.kt` (`addKeyword(keyword, alsoOnServer)`, `openRequirements`), `data/network/IntelFeedApi.kt`, `data/repository/IntelFeedRepository.kt`, `data/model/UserContentModels.kt` (`Requirement`, `RequirementMatch`, `CreateRequirementRequest`).
- **Tests:** new `data/RequirementsContractTest.kt` (4: list shape, matches shape and paging, create body with web defaults and no empty description, sort order). **111 unit tests, 0 failures.**
- **Verified on the emulator (live server, read-only):** the screen lists the server's requirements (e.g. "Edge Device & Network Infrastructure Exploitation", Critical, tactical, 4,801 matches); expanding it loaded recent matches with their reasons ("keyword: sd-wan · medium relevance"); tapping one opened the article ("2 of 20"). The auto "marked read on open" of that test article was undone. The checkbox was toggled and the dialog **cancelled** — **no requirement was created on the server** (that write is covered by the contract test only).

### Auto-read on scroll (the web toolbar's "Auto-read")

- **What the web does** (current bundle): the list toolbar's **Auto-read** (`markReadOnScroll` in its UI store, "Marks articles read as they scroll past you") marks an article read once you move on from it. The app already had "Auto-mark as read on open"; it now also has the list half.
- **New option "Auto-read on scroll"**, **off by default** (a fling can pass many articles at once): in the feed's ⋮ menu (with a check mark, next to "Hide read articles") and in Settings → Reading. Saved on the device (`UserPreferences.feedAutoRead`, key `feed_auto_read`).
- **How it works** (`AutoReadOnScroll` in `FeedScreen.kt`, used by both the list and the grid): an unread article is marked read when it goes off the top of the list **because of the user's own drag** (and the fling after it). Only rows that were on screen and then passed count. Jumps made by the app (Back to top, returning from an article to where you were, a new filter) and scrolling up never mark anything. Nothing is marked while selecting articles. Story rows and day dividers are skipped. Ids are sent in one `POST /api/entries/bulk-action {action:"read"}` when the scroll stops (or every 25). The cards dim at once and unread counts update (the existing optimistic update, reverted with a message if the request fails). No message on each scroll.
- **Files:** `ui/screens/FeedScreen.kt` (`AutoReadOnScroll`, menu item), `ui/IntelFeedViewModel.kt` (`feedAutoRead`, `setFeedAutoRead`, `markScrolledPastRead`), `data/local/UserPreferences.kt`, `ui/screens/SettingsScreen.kt`.
- **Verified on the emulator (live server):** with Auto-read on in All articles, a slow drag that moved one card off the top sent a single `bulk-action` (70-byte body = one id); that card (CERT Polska) lost its unread dot and the subtitle went from 30 to 29 unread. Scrolling back up sent nothing; dragging while an article was selected sent nothing. The test article was **marked unread again** afterwards (back to 30), and Auto-read was switched **off** again (Settings shows it off).
- `./gradlew :app:testDebugUnitTest :app:lintDebug`: **111 unit tests, 0 failures**; lint 0 errors (only dependency-version notices). (The scroll gating depends on Compose's drag events, so it was tested on the device rather than with a unit test.)

### Profile "Timeline" tab (the website profile's activity view)

- **New tab on entity profiles, "Timeline"** (second, after Overview; every type except detection rules), loaded only when opened:
  - **Mentions chart:** bars per day (per week for "All time") from `GET /api/entities/{type}/{id}/mentions-timeseries?window=`, with total articles, number of feeds, the change against the previous window ("↓ 37% vs the previous 90 days", from `previous_total`), the peak, and 7 days / 30 days / 90 days / All time chips (the website also has 24h and 60d). Switching windows cancels the previous request.
  - **What's new:** signals from `GET /api/engine/entities/{type}/{id}/whats-new?scoped=true` ("Scoop", "New pairing", …) with the article title and the reason; tap opens the article.
  - **Stories:** the entity's story threads from `GET /api/entities/{type}/{id}/story-threads?limit=10&status=any` (latest beat, article/source counts, status, last update); tap opens the story.
  - **Key events:** from `GET /api/intelligence/timeline/{type}/{id}`, grouped by day, newest first, 40 at a time ("Show more events"). Articles are left out (the Articles tab has them), as are "Related to …" events (the website also hides those). Each row has a pill ("Uses", "Exploits", "Targets", "Correlation") in the linked entity's colour; tapping opens that entity's profile (named from the event title, e.g. “Click2Shell”), or the article, or the link.
- Path type names follow the website's profile URLs (`EntityType.timelinePath`: weaknesses are `cwe`). Each part fails on its own with a quiet message, so a type the server doesn't support can't break the profile.
- A busy actor's timeline is large (ShinyHunters: 1,880 events, 571 non-article), so filtering and sorting run off the main thread.
- **Live shapes checked read-only** with a temporary debug-only probe (since removed; `grep TEMP-PROBE` finds nothing).
- **Files:** `data/model/TimelineModels.kt` (new), `ui/entity/TimelinePresentation.kt` (new), `ui/screens/EntityTimelineTab.kt` (new), `ui/entity/EntityViewModel.kt` (`TimelineUiState`, `loadTimeline`, `setMentionsWindow`, `showMoreEvents`), `ui/screens/EntityProfileScreen.kt` (tab, `onOpenThread`), `Navigation.kt`, `data/network/IntelFeedApi.kt`, `data/repository/IntelFeedRepository.kt`, `data/model/EntityType.kt` (`timelinePath`).
- **Tests:** new `data/EntityTimelineContractTest.kt` (6: the four endpoint paths and live shapes, key-event filtering/order, labels, entity targets, trend, path names).
- **Verified on the emulator (live server, read-only):** ShinyHunters → Timeline showed "386 articles in 90 days · 70 feeds", "↓ 37% vs the previous 90 days", the bar chart with Jun 26 / Peak 14 · Jul 27 / Sep 23, two What's new signals (Scoop, New pairing) and the stories ("ShinyHunters Claims FBI Data Theft", 8 articles). A layout bug found in the test (date labels drawn over the bars) was fixed and rechecked. The key-events list was not scrolled to on the device; its logic is covered by the tests.

### State at the end of the fifth session

- `./gradlew :app:testDebugUnitTest :app:assembleDebug :app:lintDebug` succeed: **117 unit tests, 0 failures**; lint 0 errors (only dependency-version notices). No temporary probe code is left.
- The debug build is installed on `emulator-5554`, signed in. Test leftovers on the **emulator only**: the tracked keyword "BIG-IP" (remove it from the drawer's Keywords section if unwanted). Auto-read on scroll is back off.
- Account/server changes in this session: none left behind. The test article marked read by opening it and the one marked read by auto-read were both marked unread again. **No requirement, feed, note, tag or campaign was created.**

### Still to do

1. **Key events on a device:** scroll the Timeline tab to its Key events and tap one of each kind (relationship → profile, correlation → article). Also open a weakness profile to confirm the timeline paths work for that type.
2. **Live-test the untested writes** (ask first, shared data): subscribing to a feed, adding an article, bulk add to campaign, mark a day read, creating a server requirement from "Track a keyword", sign-in and token refresh with encryption.

---

## 2026-09-23: Speed, performance, UI caching, ProGuard rules, and bug fixes

### Summary

Focused on speed, rendering performance, list fling/scroll smoothness, network security for self-hosted instances, ProGuard/R8 release readiness, and search display bug fixes.

### Verification

- `./gradlew :app:testDebugUnitTest :app:lintDebug :app:assembleDebug :app:assembleRelease` succeed.
- **119 unit tests, 0 failures** (2 new tests added in `LiveShapeSerializationTest` for CVE and technique ID serialization & fallback).
- Lint: **0 errors**.
- Debug build installed and verified live on `emulator-5554`:
  - Priority Queue stream loaded and scrolled smoothly in both List and Grid views.
  - CVE search ("CVE") returned formatted cards without "Untitled" fallback bug.
  - Article reader opened with full formatting and linked intelligence.
  - Entity profile and Timeline tab for `CVE-2026-7813` loaded EPSS facts, mentions, and key events immediately.
  - No server mutations or destructive calls were made.

### Performance & Polish Improvements

#### 1. Coil Image Memory & Disk Caching (`IntelFeedApplication.kt`)
- Configured custom Coil `ImageLoader` in `IntelFeedApplication`:
  - **Memory cache:** Allocates up to 25% of available JVM heap with strong reference tracking.
  - **Disk cache:** Configured 50 MB persistent cache in `cacheDir/image_cache`.
  - Ensures feed card hero images, outlet favicons, and entity avatars do not trigger redundant network fetches or GC churn during rapid list scrolling.

#### 2. HTML Snippet LRU Cache (`HtmlText.kt`)
- Added a synchronized access-order `LinkedHashMap(512)` LRU cache to `HtmlText.toSnippet()` and `toPlainText()`.
- Previously, flinging through long feeds caused repeated regex parsing and `HtmlCompat.fromHtml` calls on the main thread for identical snippets. The cache provides instant sub-millisecond retrieval during list recycling.
- Pure JVM `LinkedHashMap` implementation ensures tests run unmocked without `android.util.LruCache` stubs.

#### 3. CVE & Entity Search "Untitled" Fix (`SearchModels.kt`, `LiveShapeSerializationTest.kt`)
- **Problem:** In unified search results, vulnerabilities (such as `CVE-2026-352739` or `CVE-2026-18297`) displayed "Untitled" because the backend sends `cve_id` instead of `title` or `name` in entity search results.
- **Fix:**
  - Added `@SerialName("cve_id") val cveId: String? = null` and `@SerialName("technique_id") val techniqueId: String? = null` to `SearchEntityItem`.
  - Updated `SearchEntityItem.displayName` fallback chain: `title` -> `name` -> `cveId` -> `techniqueId` -> `entityName` -> `id` (if non-blank) -> `"Untitled"`.
  - Added unit test coverage in `LiveShapeSerializationTest.kt`. Live verified on emulator showing properly formatted CVE headers.

#### 4. Cleartext / Local HTTP Support for Self-Hosted Instances
- **Problem:** Target SDK 36 blocks cleartext HTTP by default, preventing users from connecting to self-hosted instances on local LANs (`http://192.168.x.x`).
- **Fix:**
  - Added `network_security_config.xml` (`cleartextTrafficPermitted="true"` for base config).
  - Wired into `AndroidManifest.xml` via `android:networkSecurityConfig="@xml/network_security_config"`.
  - Enhanced `ErrorText.kt` with descriptive diagnostics for SSL handshake failures, cleartext traffic errors, and timeout conditions.

#### 5. Compose Recycling & Allocation Hoisting
- **`FeedScreen.kt`:** Added explicit `contentType` to `items` in both `FeedList` and `FeedGrid`, cleanly separating day divider headers, story cards, entry cards, and list-end/loading states so Compose can reuse slot tables rather than recreating them.
- **`SearchScreen.kt`:** Added `contentType` across all search items; memoized `entityGroups` computation with `remember(items)`.
- **`WorkbenchScreen.kt`:** Hoisted `NumberFormat.getIntegerInstance()` out of per-item composables into `remember`; added `contentType = "workbench_card"`.
- **`EntityProfileScreen.kt`:** Added `contentType` to article, relationship, and note items; hoisted `itemIds` list allocation.
- **`ThreadScreen.kt`:** Hoisted `sortedBeats` sorting logic before the `LazyColumn` and added `contentType`.
- **`RequirementsScreen.kt`:** Added `contentType = "requirement_card"`.
- **`IntelFeedViewModel.kt`:** Optimized `loadFeed` to avoid allocating an empty `Set` wrapper when `selectedIds` is empty.
- **`ArticleContent.kt`:** Routed link clicks through a stable `MarkHandlers` class to prevent recreating annotated strings when callbacks change.

#### 6. ProGuard / R8 Release Rules (`proguard-rules.pro`)
- Added comprehensive ProGuard rules to ensure minified release builds do not strip serialized model fields or reflection-based network adapters:
  - Kotlinx Serialization (`@Serializable` companion objects, serializers, generated fields).
  - Retrofit & OkHttp interface methods, parameter annotations, and keep attributes.
  - WorkManager worker constructors (`ListenableWorker`).
  - jsoup and Coil internal components.
- Verified with successful `:app:assembleRelease`.

### Files Modified & Added

- `IntelFeedApplication.kt`: Coil memory and disk cache configuration.
- `util/HtmlText.kt`: Synchronized LRU cache for snippet parsing.
- `data/model/SearchModels.kt`: `cve_id` and `technique_id` support and `displayName` fallback.
- `res/xml/network_security_config.xml`: Network security configuration for cleartext support.
- `AndroidManifest.xml`: Configured `networkSecurityConfig`.
- `ui/ErrorText.kt`: Cleartext and SSL diagnostics.
- `ui/screens/FeedScreen.kt`: `contentType` in list and grid views.
- `ui/screens/SearchScreen.kt`: `contentType` and memoized entity grouping.
- `ui/screens/WorkbenchScreen.kt`: `contentType` and hoisted `NumberFormat`.
- `ui/screens/EntityProfileScreen.kt`: `contentType` and hoisted allocations.
- `ui/screens/ThreadScreen.kt`: `contentType` and hoisted sort.
- `ui/screens/RequirementsScreen.kt`: `contentType`.
- `ui/IntelFeedViewModel.kt`: Allocation optimization in `loadFeed`.
- `ui/components/ArticleContent.kt`: Stable link handler routing.
- `app/proguard-rules.pro`: Release minification keep rules.
- `data/LiveShapeSerializationTest.kt`: Unit tests for CVE and technique ID serialization.

---

## 2026-09-23: Security hardening, zero-latency in-memory auth caching, intent sanitization, and bug fixes

### Summary

Carried out a deep security audit and performance optimization pass across networking, intent handling, inter-thread data access, and UI rendering. Eliminated thread-blocking disk I/O in OkHttp interceptors via volatile in-memory caching, hardened network TLS policies against cleartext downgrade for the official production server, secured incoming share intents against path traversal / URI permission replay, fixed search highlight infinite loop risk in article reader, and bounded in-memory LRU cache sizes.

### Verification

- `./gradlew :app:testDebugUnitTest :app:lintDebug :app:assembleDebug :app:assembleRelease` all succeed.
- **135 unit tests pass, 0 failures, 0 errors** (16 new tests added: 8 in `ShareIntentSanitizerTest`, 8 in `InAppLinksTest`).
- Lint: **0 errors**.
- Debug build installed and verified live on `emulator-5554`:
  - Priority Queue stream and images loaded smoothly with zero thread blocking.
  - Share intent from external app (`android.intent.action.SEND`) verified with safe sanitized URLs ("Add to IntelFeed?" dialog properly launched).
  - Malicious / hostile share intent containing `FLAG_GRANT_READ_URI_PERMISSION` was immediately rejected and denied.
  - Search query ("ShinyHunters") executed cleanly across threat actors, vulnerabilities, rules, and 493 articles.
  - Article reader opened "How three techniques are behind ShinyHunters", verifying PIR requirement indicators, entity linking, and content highlighting without freezing or ANRs.
  - Preserved read-only session; no server mutations or destructive actions performed.

### Security Hardening & Optimizations

#### 1. Zero-Latency In-Memory Auth & Server Caching (`AuthPreferences.kt`, `ApiClient.kt`, `IntelFeedRepository.kt`)
- **Problem:** `ApiClient.kt` interceptors (`authInterceptor` and `imageHttpClient`) were calling `runBlocking { authPreferences.accessToken.first() }` and `runBlocking { authPreferences.serverUrl.first() }` on every HTTP network request and Coil image fetch. On Android, `DataStore.data.first()` reads from disk on every invocation, blocking background and IO threads with thread contention and latency spikes.
- **Fix:**
  - Added `@Volatile var cachedServerUrl: String` and `@Volatile var cachedAccessToken: String?` in `AuthPreferences`.
  - Initialized with synchronous reads, and launched long-running coroutines in `CoroutineScope(Dispatchers.IO + SupervisorJob())` collecting `serverUrl` and `accessToken` to keep the volatile references up to date in real time.
  - Fixed property initialization order: placed the collector `init` block after property definitions to eliminate `NullPointerException` during class instantiation.
  - Added synchronous `getCachedServerUrl(): String` and `getCachedAccessToken(): String?`.
  - Updated `authInterceptor`, `imageHttpClient`, and `IntelFeedRepository` (`getApi()`, `currentServerUrl()`) to read the volatile cached values.

#### 2. Domain-Specific TLS Enforcement (`network_security_config.xml`)
- **Problem:** Allowing cleartext HTTP globally for self-hosted instances opened up MITM / traffic sniffing risks if user traffic to the official cloud domain (`intelfeed.cc`) was downgraded to HTTP.
- **Fix:**
  - Configured `<domain-config cleartextTrafficPermitted="false">` for `intelfeed.cc` with `includeSubdomains="true"`, enforcing TLS and system + user trust anchors.
  - Retained `<base-config cleartextTrafficPermitted="true">` for local self-hosted setups (e.g. `http://192.168.x.x`).

#### 3. Share Intent Sanitization & Replay Protection (`ShareIntentSanitizer.kt`, `MainActivity.kt`)
- **Problem:** `MainActivity.handleShareIntent` read raw `Intent.EXTRA_TEXT` and `Intent.data` without validating length, scheme, or URI permission flags. A hostile third-party app could pass excessive payloads, non-HTTP schemes (`file://`, `javascript://`), embedded credentials (`http://user:pass@evil.com`), or URI grant flags (`FLAG_GRANT_READ_URI_PERMISSION`). Additionally, if `savedInstanceState != null` or on configuration change, unconsumed extras could replay the share dialog.
- **Fix:**
  - Created `util/ShareIntentSanitizer.kt`:
    - Rejects intents with URI permission grant flags (`FLAG_GRANT_READ_URI_PERMISSION`, `FLAG_GRANT_WRITE_URI_PERMISSION`, `FLAG_GRANT_PERSISTABLE_URI_PERMISSION`, `FLAG_GRANT_PREFIX_URI_PERMISSION`).
    - Enforces maximum URL length (4096 chars).
    - Strips whitespace, control characters, and trailing punctuation (`.,;:!?)]}>`).
    - Rejects URLs with embedded user credentials (`userInfo != null`).
    - Enforces strict `http` or `https` schemes.
  - Integrated into `MainActivity.handleShareIntent(intent)`.
  - Added extras removal (`intent.removeExtra(Intent.EXTRA_TEXT)` and `intent.removeExtra(Intent.EXTRA_STREAM)`) once consumed to prevent replay upon configuration changes or activity recreation.
  - Added 8 unit tests in `ShareIntentSanitizerTest.kt`.

#### 4. Protocol Downgrade Protection in In-App Links (`InAppLinks.kt`)
- **Problem:** `InAppLinks.matchesServer` matched URL host and port against the server URL, but did not enforce matching schemes. A link with `http://intelfeed.cc/entries/123` would be treated as an in-app link even if the configured server was `https://intelfeed.cc`.
- **Fix:**
  - Added `link.scheme.equals(server.scheme, ignoreCase = true)` check in `InAppLinks.matchesServer`.
  - Added 8 unit tests in `InAppLinksTest.kt`.

#### 5. Search Highlight Infinite Loop Fix (`ArticleContent.kt`)
- **Problem:** In `appendArticleHtml`, search query highlighting loop used `indexOf(q, startIndex, ignoreCase = true)`. If `q` was empty or regex edge cases occurred, `q.length` being 0 would result in `nextMatch == startIndex`, producing an infinite loop freezing the UI thread.
- **Fix:**
  - Added guard check `if (q.isNotEmpty())`.
  - Ensured `startIndex = (nextMatch + q.length).coerceAtLeast(nextMatch + 1)` and enforced bounds checking against string length.

#### 6. Memory Bounding in HTML Cache (`HtmlText.kt`)
- **Problem:** `HtmlText` LRU cache held up to 512 parsed strings. If full article HTML bodies or massive paragraphs were passed into snippet functions, large objects could be retained in the LRU cache.
- **Fix:**
  - Bounded caching to strings `<= 4096` characters. Larger strings are parsed directly without polluting the LRU cache.

#### 7. Input Sanitization in Recent Searches (`UserPreferences.kt`)
- **Problem:** `addRecentSearch` concatenated history using delimiter `\u001F`. If a query contained `\u001F` or was arbitrarily long, it could corrupt recent search storage in DataStore.
- **Fix:**
  - Stripped `\u001F` delimiter and enforced a 100-character max limit on recent search entries.

### Files Modified & Added

- `data/local/AuthPreferences.kt`: Volatile in-memory cache and synchronous accessors.
- `data/network/ApiClient.kt`: Zero-latency in-memory auth header and server URL resolution.
- `data/repository/IntelFeedRepository.kt`: Switched to cached server URL in `getApi()` and `currentServerUrl()`.
- `res/xml/network_security_config.xml`: Strict TLS enforcement for `intelfeed.cc`.
- `util/ShareIntentSanitizer.kt` (NEW): Intent sanitization and permission rejection utility.
- `MainActivity.kt`: Integrated `ShareIntentSanitizer` and intent extra cleanup.
- `util/InAppLinks.kt`: Scheme matching for in-app links.
- `ui/components/ArticleContent.kt`: Fixed search highlight loop bounds.
- `util/HtmlText.kt`: Cache size bounding.
- `data/local/UserPreferences.kt`: Recent search sanitization.
- `test/.../util/ShareIntentSanitizerTest.kt` (NEW): 8 unit tests for share intent sanitizer.
- `test/.../util/InAppLinksTest.kt` (NEW): 8 unit tests for in-app link matching.

---

## 2026-09-23: Saved searches deletion, read/unread feed purge, and server tag removal

### Summary

Resolved three core workflow areas requested by the user:
1. Enabled deletion of saved searches directly from the Feeds navigation drawer and the Search tab with deletion confirmation dialogs.
2. Fixed read/unread feed disappearance bugs so that read articles are automatically purged when returning from the reader or switching back to the feed tab in unread/priority views (`FeedFilter.UNREAD`, `FeedFilter.PRIORITY_QUEUE`, `feedHideRead = true`). Preserved reader horizontal pager stability by snapshotting sibling IDs so swiping between articles never encounters index shifts or out-of-bounds exceptions. Added automatic pagination when the current feed page is completely read and purged.
3. Implemented full server tag deletion via `DELETE /api/tags/{tagId}` in Retrofit API, repository, and ViewModel. Added "Manage server tags" UI in Settings with live search, affected article count display, and confirmation dialogs. Also enabled long-press deletion of tags from the article reader's tag picker sheet.

### Verification

- `./gradlew testDebugUnitTest` succeeds: all unit tests pass (including new `ReadUnreadPurgeTest` and `ApiContractTest.deleteTagUsesDeleteWithPath`).
- `./gradlew assembleDebug` succeeds without errors.
- Installed onto physical device (Google Pixel 9 Pro) via `adb install -r`.

### Files Modified & Added

- `data/network/IntelFeedApi.kt`: Added `@DELETE("api/tags/{tagId}") suspend fun deleteTag(...)`.
- `data/repository/IntelFeedRepository.kt`: Added `suspend fun deleteTag(tagId: String): Result<Unit>`.
- `ui/IntelFeedViewModel.kt`: Added `deleteTag`, `shouldHideRead`, `purgeReadEntriesIfHiding`, and updated `goBack`, `setAppTab`, `openEntry`, and `undoBulk`.
- `ui/reader/ReaderViewModel.kt`: Added `deleteTag(tag: TagEntity)`.
- `ui/screens/FeedDrawer.kt`: Added delete icon button and long-click on saved searches with confirmation dialog.
- `ui/screens/SearchScreen.kt`: Added delete icon button for saved searches.
- `ui/screens/FeedScreen.kt`: Auto-load next page when feed becomes empty after read entries are purged.
- `ui/screens/SettingsScreen.kt`: Added "Tags" section and `TagManagerSheet` with search, article count, and deletion.
- `ui/screens/EntryReaderScreen.kt`: Supported tag deletion with confirmation dialog on long-press in `TagPickerSheet`.
- `ui/components/Common.kt`: Supported `onLongClick` in `Pill` via `Modifier.combinedClickable`.
- `Navigation.kt`: Wired `onDeleteSavedSearch` in drawer and passed repository to `SettingsScreen`.
- `test/.../data/ApiContractTest.kt`: Added contract test for `deleteTag`.
- `test/.../ui/ReadUnreadPurgeTest.kt` (NEW): Unit tests for feed read hiding and tag entity.




---

## 2026-09-23 (sixth session): Strict review of the GPT/Codex changes, security and bug fixes

### Summary

A review of the whole app after the Codex session (see `codex_changes.md`), for security, bugs, speed and efficiency. Codex's changes held up: the private notification route activity, the immutable PendingIntent, the share-intent sanitizer, the TLS config, and the guards against late token refreshes are all correct. This session fixes 8 problems (one security issue, six bugs, two efficiency issues) and lists what was found but not changed.

### Verification

- `./gradlew :app:testDebugUnitTest :app:assembleDebug :app:lintDebug` succeeds. 156 unit tests pass (151 before, 5 new). Lint: 0 errors.
- The new bulk-update test was run against the old `tryEmit` code and failed (updates were lost). It passes with the fix.
- Nothing was run on a device or emulator. No live-server requests were made.

### Fixes

#### 1. Security: article images could make authenticated requests to any API path
- **Problem:** `ApiClient.imageHttpClient()` attached the bearer token to every image request on the server's origin. Article HTML comes from arbitrary RSS feeds, so `<img src="/api/…">` or `<img src="https://<server>/api/…">` made the app send an authenticated GET to any API path.
- **Fix:** The image client now sends the token only to `<server path>/api/proxy/…` (the server's image proxy, the only authenticated image source). The API client now also checks the request's origin (scheme, host, port) against the stored server before attaching the token, so an API instance built for an old address never sends it anywhere else. The parsed server URL is cached (`sessionServer()`), so this costs no extra parsing per request.
- **Files:** `data/network/ApiClient.kt`. Tests: `ApiClientSecurityTest.apiSendsTokenOnlyToTheSignedInServer`, `imageClientSendsTokenOnlyToTheImageProxy`.

#### 2. Signing out reset the feed settings until the app restarted
- **Problem:** `IntelFeedViewModel.resetSession()` rebuilt the UI state with defaults and kept only `recentSearches`. The preference flows are `distinctUntilChanged` and don't emit again, so after a logout or an expired session the app showed the list layout, expanded density, Hide Read off, newest-first order, auto-read off and no tracked keywords, whatever was saved. The feed also loaded with the wrong Hide Read and sort, and the first layout toggle did nothing.
- **Fix:** `resetSession()` keeps `trackedKeywords`, `feedDensity`, `feedLayout`, `feedHideRead`, `feedSort` and `feedAutoRead`.
- **File:** `ui/IntelFeedViewModel.kt` (`resetSession`).

#### 3. Large bulk actions lost some flag updates
- **Problem:** `IntelFeedRepository.bulkSet` and `changeFlags` used `tryEmit` on a SharedFlow with a 256-update buffer. The collectors run on the main thread, like the emitter, so "Select all → Mark read" on more than 256 articles dropped the rest. Those articles still looked unread, and the Unread count was wrong.
- **Fix:** Both functions use `emit` (they are already `suspend`). Every collector is synchronous, so this can't deadlock.
- **File:** `data/repository/IntelFeedRepository.kt`. Test: `ReadStatusUpdateTest.bulkUpdateOfManyArticlesDeliversEveryUpdate`.

#### 4. Alerts repeated every 15 minutes after a partial failure
- **Problem:** Codex made the worker keep `lastNotificationSyncMs` in place when any request failed. Campaign, saved-search and priority alerts had no other deduplication, so while one source kept failing (one campaign's entries, one saved search), every alert in the window was posted again on each run, including ones the user had dismissed.
- **Fix:** The worker records each alert it posts: `e:<entry id>` for articles, `t:<slug>:<last update>` for stories. An article alerts once across all three sources and all runs. The keys are saved in a `finally` block with `NonCancellable`, so a failure partway through a run doesn't lose them. The last-sync behavior is unchanged.
- **New API:** `UserPreferences.getNotifiedAlertKeys(): Set<String>` and `addNotifiedAlertKeys(keys: Collection<String>)` (key `notified_alert_keys`, 500 most recent).
- **Files:** `notifications/IntelNotificationWorker.kt`, `data/local/UserPreferences.kt`.

#### 5. Campaign, saved-search and priority alerts missed most new articles
- **Problem:** An article counted as new only if its **publish** time was after the last check (15 minutes earlier). Feeds are polled and enrichment runs after ingest, so most articles reach the server well after their publish time. They were never alerted.
- **Fix:** New `notifications/AlertTiming.arrivedAtMs(entry)`, the later of `published_at` and `created_at` (ingest time). The worker uses it for all three sources. Deduplication (fix 4) keeps the wider window from repeating alerts.
- **Files:** `notifications/AlertTiming.kt` (new), `notifications/IntelNotificationWorker.kt`. Test: `AlertTimingTest` (new).

#### 6. Workbench: an older search's results could replace a newer one
- **Problem:** `loadMoreWorkbench()` assigned its job to `workbenchJob`. If it started during the 350 ms search debounce (a short list is always "near the end"), the pending search job was orphaned. Later keystrokes no longer cancelled it, and its results could land last.
- **Fix:** Loading more pages uses its own `workbenchMoreJob`. `loadWorkbench()` cancels both jobs, and loading more does nothing while a first page is pending.
- **File:** `ui/IntelFeedViewModel.kt`.

#### 7. Smaller bugs in `IntelFeedViewModel`
- A confirmed star or bookmark removed the article from `pendingReadIds`, so a pending read could be purged before it was confirmed, and a failed read then couldn't restore the card. Now only read-state updates settle a pending read.
- `deleteSavedSearch` removed the search by data-class equality. The list is refreshed with new unread counts, so the search on screen often didn't match: it wasn't removed right away, and a failure added a duplicate. It now works by id.

#### 8. Efficiency
- `loadCategoriesAndFeeds()` loads categories and feeds in parallel. The feed list (up to 1000 feeds) used to wait for the categories.
- `DateUtils.localDayKey` reuses a thread-local `SimpleDateFormat`. The feed builds a day key for every card, on the main thread, each time the list changes (every read or star), and it used to create a new formatter for each card.

### Found but not changed (recommended next)

1. **Reader memory (medium):** The reader pager creates a `ReaderViewModel` for each article swiped through, keyed in the reader's ViewModelStore. None is cleared until the reader closes, and each keeps the full article plus five flow collectors. Hold per-page state in a composition-scoped holder (at most 3 alive with `beyondViewportPageCount = 1`), with a small detail cache in the repository.
2. **Release build (medium):** `isMinifyEnabled = false`, and `proguard-rules.pro` keeps all of OkHttp, Retrofit, Coil and jsoup. The release APK isn't shrunk or optimized. Enable R8 and drop the blanket library keeps (the libraries ship consumer rules), then test the release build on a device, because serialization models depend on the keep rules.
3. **Plain-HTTP servers (low–medium, security):** The base network config allows cleartext and user-installed CAs for self-hosted servers. That's deliberate, but signing in to an `http://` address sends the password and tokens unencrypted with no warning. Show a warning on the login screen for non-local `http://` addresses.
4. **Keystore fallback (low, security):** If the Keystore can't provide a key, `TokenCipher.encrypt` stores tokens in plain text without telling anyone. Consider logging the failure in debug builds, or refusing to persist the refresh token in that case.
5. **Shared DataStore file (low):** Keyword seen-ids (up to 200 per keyword × 50 keywords) and the new alert keys live in the same preferences file as the auth tokens, so every settings write rewrites all of it. Move alert state to its own DataStore file.
6. **Keyword checks (low):** Each check fetches full article bodies (`GET /api/entries/{id}`, up to 10 per keyword every 15 minutes) only to read `is_read`.
7. **Worker scheduling (low):** The periodic worker is scheduled even when signed out or with alerts off. It returns early, but it still wakes the process every 15 minutes. Cancel it on logout or when alerts are turned off, and schedule it again at sign-in or when they're turned on.
8. **Smaller items:** `formatRelativeTime` formats dates older than a week in UTC, so the day can differ from the local-time day dividers. A notification route waiting for sign-in is lost on rotation (`MainActivity.pendingRoute` is activity state). Summaries longer than 4096 characters are parsed with `fromHtml` on the main thread each time a card comes back into view. `ArticleContent` renders every block in a plain `Column`, so all images in a long article (and in the neighbouring pages) load when it opens. Find-in-article rebuilds every paragraph's `AnnotatedString` on the main thread on each keystroke.

### API and signature changes

- `UserPreferences`: new `getNotifiedAlertKeys()` and `addNotifiedAlertKeys(keys)`.
- New `notifications/AlertTiming` object (`arrivedAtMs(entry: EntryItem): Long`).
- `ApiClient`: new private `sessionServer()` and `HttpUrl.isSameOrigin(server)`. The image client now authenticates only `/api/proxy/…` on the server.

### Rules for future code

- Only the image proxy gets the token from the image client. If the server adds another authenticated image path, add it to the image client's check in `ApiClient`. Don't widen it to the whole origin.
- Use `emit`, not `tryEmit`, for `entryUpdates` from suspend code.
- Every state field loaded from `UserPreferences` must be carried over in `resetSession()`.
- Background alerts must go through the worker's `firstAlert(key)`, so each one is posted only once.

### Follow-up in the same session: keyword alerts and notifications, end to end

The user asked to make sure keyword notifications work and alert on new articles. The whole path was traced: adding a keyword, scheduling, the search query, baseline and deduplication, posting, and tap routing. The server query (`"<keyword>" date:>=<2 days ago> sort:newest`) matches `docs/query-language.md`: phrase match, `date:` on published_at, `sort:newest` = published_at descending. The problems and their fixes:

#### 9. Keyword alerts could repeat after an interrupted run
- **Problem:** Keyword seen-ids were saved only at the end of `checkKeywords`. WorkManager stops a run when the network drops, after 10 minutes, or when "Check for updates now" replaces it. A stopped run had already posted its alerts but hadn't recorded them, so they were posted again on the next run.
- **Fix:** The seen-ids are saved in a `finally` block with `NonCancellable`.

#### 10. Overlapping runs posted duplicate alerts
- **Problem:** The periodic check and the one-off check ("Check for updates now") could run at the same time. Each read the same saved state, posted the same alerts, and overwrote the other's saved state.
- **Fix:** `IntelNotificationWorker.doWork()` holds a process-wide `Mutex` (`runLock`), so runs are serialized. A second run waits for the first rather than being skipped.

#### 11. Keywords were checked last
- **Problem:** Campaigns (up to 11 requests), saved searches (one slow search each) and the priority queue ran first, one request at a time. On a slow server, a run could hit the 10-minute limit before any keyword was checked. Within each batch of 4 keywords, the up to 10 detail lookups per keyword also ran one after another.
- **Fix:** Keywords are checked first. Each keyword's detail lookups run inside its own `async`, so the 4 keywords in a batch look up in parallel (still one at a time within a keyword, to spare the server).

#### 12. A new keyword silently absorbed articles until its first check
- **Problem:** A keyword's first check records current matches as a baseline without alerting. That check waited for the next periodic run (up to 15 minutes, longer in Doze), so every article that arrived after the keyword was added but before that run was absorbed and never alerted.
- **Fix:** `IntelFeedApplication` watches `trackedKeywords` and calls `triggerImmediateSync` whenever a keyword is added, from any screen, so the baseline is taken right away.

#### 13. An unopened alert was overwritten with a smaller count
- **Problem:** Each keyword has one notification id. Say "3 new articles mention X" is still in the shade and a later run finds one more article. The alert was replaced with just that one article, and its tap opened only that article.
- **Fix:** New `IntelNotificationHelper.isShowing(context, id)`. When the keyword's alert is still showing, the new one says "N more new articles mention …" and opens the keyword search.

#### 14. Tapping a multi-article alert showed relevance-ranked results
- **Problem:** The tap ran the plain phrase search, which is relevance-ordered, so the new articles could appear below older ones.
- **Fix:** `IntelFeedViewModel.searchKeyword(keyword, newestFirst = false)` gained the `newestFirst` flag. The notification route passes `true`, which adds `sort:newest`. Highlight and drawer taps are unchanged.

#### 15. One alert per article across all sources
- Keyword alerts now record `e:<entry id>` in the shared alert keys (fix 4). An article already alerted by a keyword, campaign, saved search or the priority queue doesn't alert again from another source. Two keywords matching the same new article produce one alert.

#### 16. Switching accounts set off a burst of stale alerts
- **Problem:** Keyword baselines, alert keys and the last-check time are device preferences and survive sign-out. After signing in as a different user or to a different server, the old baselines didn't match, so each keyword's new matches all looked new (up to 10 alerts per keyword).
- **Fix:** New `UserPreferences.claimAlertState(owner)`. The worker calls it at the start of each run, under its lock, with `"<server>|<username lowercased>"`. When the owner changes, the alert state is dropped, so the new account starts with fresh baselines. State from before this change is adopted, not dropped. Sign-out also clears the app's notifications from the shade (`Navigation.kt`, `onLogout`), so a leftover tap can't open the previous account's article.

#### 17. A notification tap waiting for sign-in was lost on rotation
- **Problem:** `MainActivity.takeNotificationRoute()` moved the route out of the application object into activity state, which is lost when the activity is re-created.
- **Fix:** The route stays in `IntelFeedApplication.pendingNotificationRoute` until it's handled, and is cleared when the `LaunchedEffect` acts on it.

#### Keyword decision logic is now unit-tested
- `KeywordAlerts.toLookUp(current, seen)` returns the new matches to look up (at most `MAX_LOOKUPS = 10`, newest first). `KeywordAlerts.evaluate(current, seen, readState, alreadyAlerted)` returns `Outcome(seen, alert)`. The worker uses both; the behavior is the same as before plus the `alreadyAlerted` rule. `KeywordAlertsTest` has 5 new tests: first check sets a baseline, new unread vs. read matches, a failed lookup is retried, matches beyond the cap wait for the next check, and an article another alert covered.

#### Verification
- `./gradlew :app:testDebugUnitTest :app:assembleDebug :app:lintDebug` succeeds. 161 unit tests pass, and lint reports 0 errors (24 warnings, unchanged). `:app:compileDebugAndroidTestKotlin` succeeds.
- **Not verified on a device:** No emulator or device was connected, and an end-to-end keyword alert needs a signed-in session. To check it: sign in on the emulator, track a keyword (this starts the baseline check immediately), wait until an article matching it is ingested, then use Settings › Check for updates now. Expect one "Keyword: …" alert. Tapping it opens the article, or the newest-first search when there are several.

#### Limits that remain (by design or needing server work)
- WorkManager's minimum period is 15 minutes, and Doze or App Standby can defer runs by hours for an app that isn't used often. Real-time alerts need server push (FCM).
- The keyword search covers articles *published* in the last 2 days (`date:` filters on published_at), so an article ingested today with an older publish date never alerts.
- The alert channel's importance is DEFAULT: sound, no heads-up banner. A channel's importance can't be raised after it's created; the only way is a new channel id, or the user can change it in Android settings.
- Each keyword check fetches up to 10 full article details only to read `is_read`, because the search index's read flag lags. A lighter server endpoint would help.

#### Files
`notifications/IntelNotificationWorker.kt` (rewritten), `notifications/KeywordAlerts.kt`, `notifications/IntelNotificationHelper.kt` (`isShowing`), `data/local/UserPreferences.kt` (`claimAlertState`, key `alert_state_owner`), `IntelFeedApplication.kt`, `MainActivity.kt`, `ui/IntelFeedViewModel.kt` (`searchKeyword`), `Navigation.kt`, `test/.../util/KeywordAlertsTest.kt`.

#### Device verification (emulator `medium_phone`, signed in to intelfeed.cc as the user)
The new debug build was installed over the existing app, keeping its data. The user signed in themselves. Each test step and its result:
- **Adding a keyword** (`vulnerability`, device-only, the server-requirement box unchecked) started a check right away. The scheduled check started at the same moment. The run lock serialized them: the second waited for the first to finish (12:49:01 → 12:49:21 → 12:49:38). The baseline of 50 matches was saved with no alert. `alert_state_owner` = `https://intelfeed.cc|kurt`.
- **Simulated new matches:** with the app stopped, three baseline ids in the DataStore file were replaced on the device with same-length dummy ids. The file was backed up on the device first and never left the emulator. The next "Check for updates now" looked up exactly those 3 articles, found them unread, and posted *"Keyword: vulnerability — 3 new articles mention "vulnerability" · …"*.
- **Repeat check:** it ran the search, made no lookups, and posted no new alert.
- **A real new article** that arrived after the baseline ("MikroTrick Chain Let Attackers Take Over MikroTik Routers…") was alerted on the next check, together with two more simulated ones.
- **Still showing:** with that alert left unopened, the app's process was killed (a kill keeps notifications, `force-stop` doesn't) and one more id was swapped. The alert was updated in place to *"1 more new article mentions "vulnerability" · CVE-2026-94127: …"*.
- **Tapping the alert** opened the Search tab with `"vulnerability" sort:newest`, newest first, with the alerted articles at the top.
- **Fixed during testing:** the still-showing message said "1 more new article mention"; it now reads "mentions" (`IntelNotificationWorker.postKeywordAlert`).
- **Clean-up:** the test keyword was removed through the drawer (its seen-ids went with it), and the backup file on the device was deleted. Five dummy ids from the test remain in no list: they were dropped when the keyword was removed.
- **Observed:** the server's keyword search takes 8–15 s per query (`POST /api/search/unified`). Article detail lookups take ~0.2 s.

---

## 2026-09-23 (seventh session): Continuing development after the review

The user signed in on the emulator and asked to keep developing. Work follows the "Found but not changed" list from the sixth session, highest value first. Each item is logged when done and verified.

### 1. Startup sent `/api/auth/me` and `/api/saved-searches` twice
- **Seen in the device log:** every sign-in and every launch requested both twice.
  - The sign-in fetched the user, and the data load that starts when the tokens are saved fetched it again.
  - The data load called `loadSavedSearches()` right next to `loadViewCounts(force = true)`, which already refreshes the saved searches.
- **Fix:**
  - `IntelFeedRepository.loadCurrentUser()` holds a `Mutex` and returns the loaded user if there is one. `login()` clears the previous user first (an expired session never went through `logout()`), then uses `loadCurrentUser()`, so the sign-in and the data load share one request.
  - The `isLoggedIn` handler in `IntelFeedViewModel` no longer calls `loadSavedSearches()` itself.
- **Verified on the emulator:** a cold start now sends each of its 15 requests once.
- **Files:** `data/repository/IntelFeedRepository.kt`, `ui/IntelFeedViewModel.kt`.

### 2. The reader kept every article you swiped through in memory
- **Problem:** every `ReaderViewModel` lived in the reader's back-stack store, so reading through a long list kept one per article until the reader closed. Each held the full article, its side panels and five live subscriptions (user, three preferences, flag updates), and every DataStore write and flag change was processed by all of them.
- **Fix:**
  - New `ui/reader/ReaderPages` (a ViewModel in the reader's store) gives each article its own `ViewModelStore`. `EntryReaderScreen` gets every ReaderViewModel through the new private `readerViewModel(pages, entryId, app)`.
  - When the pager settles, `pages.retainOnly(...)` clears every article more than two pages away (the pager composes one either side). An article you come back to is loaded again.
  - The auto mark-read "once" rule moved from a per-ViewModel flag to `ReaderPages.autoReadIds`, shared by the reader's pages. Re-creating a page's ViewModel therefore can't mark an article read again after you marked it unread by hand.
- **API:** `ReaderViewModel` gained a last constructor parameter, `autoReadIds: MutableSet<String> = HashSet()`.
- **Verified on the emulator:** in All articles, "Auto-mark as read on open" was switched off for the test (no read state changed on the server), then switched back on.
  - Swiping 5 articles forward loaded each article once.
  - Swiping 5 back reloaded only the 3 articles more than two pages away; the nearer ones were still in memory.
  - No crashes, and the reader displays normally.
- **Files:** `ui/reader/ReaderPages.kt` (new), `ui/reader/ReaderViewModel.kt`, `ui/screens/EntryReaderScreen.kt`.
- 161 unit tests pass.

### 3. The background check is scheduled only while signed in with alerts on
- **Problem:** `IntelFeedApplication.onCreate` always scheduled the 15-minute periodic check. Signed out, or with alerts switched off in the app, it still woke the app every 15 minutes just to return.
- **Fix:** The application watches `isLoggedIn` and `notificationsEnabled` together. It schedules the check when both are true (`schedulePeriodicSync`, KEEP) and cancels it otherwise (new `IntelNotificationHelper.cancelPeriodicSync`). Android's own notification permission isn't observable, so the worker still checks it on each run.
- **Verified on the emulator:** with alerts on there was 1 WorkManager job in `dumpsys jobscheduler`. With alerts switched off in Settings there were 0, and switching them back on restored 1. The switch was left on, as the user had it.
- **Files:** `IntelFeedApplication.kt`, `notifications/IntelNotificationHelper.kt`.

### 4. Warning for unencrypted (http://) servers on the sign-in screen
- **Problem:** Signing in to an `http://` address sent the password and session tokens as plain text, with no warning. Cleartext is deliberately allowed for self-hosted servers.
- **Fix:** New `ServerUrl.isCleartext(raw)`: true for a usable address that normalizes to `http://`. A bare host means https, so it isn't flagged. When it's true, the sign-in screen shows an amber line under the server field: "Not encrypted (http). Your password and session can be read by anyone on the network path. Use https unless this server is on a network you trust." Signing in isn't blocked.
- **Test:** `ServerUrlTest.cleartextAddressesAreFlagged`.
- **Not checked on the device:** the user is signed in, and signing out would need them to sign in again.
- **Files:** `data/network/ServerUrl.kt`, `ui/screens/LoginScreen.kt`.

### 5. Dates older than a week showed the UTC day
- **Problem:** `DateUtils.formatRelativeTime` formatted older dates ("Sep 3") in UTC, while the day dividers use local time. For part of every day outside UTC, a card could show a different day from its divider.
- **Fix:** Timestamps are now formatted in the device's time zone (new `zone` parameter, defaulting to the device's). A bare `yyyy-MM-dd` is a calendar day parsed as UTC midnight, so it stays in UTC; in the local zone it would move to the day before.
- **Test:** `DateUtilsExtraTest.olderTimestampShowsItsLocalDayButABareDateDoesNotMove`.
- **File:** `util/DateUtils.kt`.
- 163 unit tests pass. Lint: 0 errors, 24 warnings (as before).

### 6. R8 turned on for release builds (14.9 MB → 2.7 MB), tested on the emulator
- **Change:**
  - `app/build.gradle.kts` release: `isMinifyEnabled = true`, `isShrinkResources = true`.
  - `proguard-rules.pro` rewritten. The blanket `-keep class okhttp3.** / retrofit2.** / coil.** / org.jsoup.** { *; }` rules are gone; they stopped R8 from shrinking those libraries, which ship their own consumer rules.
  - Kept: the JSON models (`data.model.**`), the `IntelFeedApi` interface, the worker's constructor, and generic signatures and annotations for Retrofit. Added `-dontwarn` for jsoup's optional re2j, plus line numbers in stack traces.
- **Crash found on the device and fixed:** the first minified build crashed at startup with `NoSuchMethodException: androidx.work.impl.WorkDatabase_Impl.<init>`. R8 had removed the constructor of WorkManager's Room database, which is created by reflection (work-runtime 2.10.0). Fix: `-keep class * extends androidx.room.RoomDatabase { <init>(); }`.
- **How it was tested:** the unsigned release APK was aligned and signed in the scratchpad with the local debug key (`~/.android/debug.keystore`). The build config's signing is unchanged. That copy was installed over the debug build, keeping the data.
- **Smoke test of the minified build on the live server:** no crashes (crash buffer empty). Auto-mark-read was off during the test, so no read state changed; it was switched back on afterwards.
  - The existing session decrypted, and the Priority Queue loaded with intel badges.
  - The All articles reader showed the article, requirement matches, linked intelligence, the jsoup-parsed body with entity highlights, and an image.
  - `threat_actor:APT29` search, the APT29 profile and its Timeline tab (chart, What's new, Stories), and the Workbench list all worked.
  - "Check for updates now" ran the worker with result SUCCESS.
- **After the test:** the debug build was reinstalled for development.
- **Still needed for a store release:** a real signing config. There's none in the build; release APKs come out unsigned.

### 7. Find in article: debounced, and the match count now matches the highlights
- **Problems:**
  - Each keystroke rebuilt every paragraph's `AnnotatedString` on the main thread, which was slow on long articles.
  - The "N matches" count searched `detail.contentText`, which many articles don't have (the reader renders `contentHtml`), so it could say "0 matches" while matches were highlighted. It also counted the untrimmed query and the title, neither of which the highlights use.
- **Fix (`EntryReaderScreen`):**
  - `appliedFind` takes the trimmed query 250 ms after typing stops; clearing applies at once. The highlights use it.
  - While the find bar is open, the paragraph and list-item texts are parsed once per article off the main thread with the same `articleBlocks` the reader renders (`findTexts`), and the count is taken from them.
- **Verified on the emulator:** "the" in the Bleeping Computer article showed "49 matches", with the matches highlighted in the text.

### 8. Feed card snippets no longer parse long summaries on the main thread
- **Problem:** Some feeds put the whole article in the summary. `HtmlText.toSnippet` doesn't cache values over 4096 characters, so such a summary was parsed in full with `fromHtml`, on the main thread, every time its card came back into view.
- **Fix:** A long value is cut to its first 4096 characters before parsing (`HtmlText.cutForSnippet`), which is far more than a card's 2–3 lines. The cut avoids ending inside a tag, and drops an unclosed `<script>`/`<style>` whose closing tag was cut off (`fromHtml` would show its code). Every snippet is now cached.
- **Test:** new `util/HtmlSnippetTest` (3 tests).
- **Files:** `util/HtmlText.kt`, `ui/screens/EntryReaderScreen.kt`.
- 166 unit tests pass. Lint: 0 errors, 24 warnings (as before).

### 9. Weakness (CWE) profiles: Timeline, Articles, Relationships and Notes were broken
Found while checking the fifth session's open item (Timeline key events and weakness profiles on a device). The key events themselves work: on APT29 they're grouped by day with Uses/Correlation pills, a relationship event opens that entity's profile (InstallFix), and "Show more events" pages 361 → 321 left.
- **Problem 1 (wrong id):**
  - Weakness profiles are opened by their public id (`CWE-416`), like CVEs and techniques. Unlike those, `Cwe.toProfile()` didn't set `serverId` to the row id.
  - The timeline endpoints got `CWE-416`: mentions-timeseries and story-threads returned 400, and whats-new returned 422 ("The server rejected the request." on the chart).
  - The Articles tab searched `cwe:"CWE-416: Use After Free"` (the display title) and showed **0**, while the Workbench row said 263 articles.
- **Fix 1:** `Cwe.toProfile()` sets `serverId = id` (the UUID, which is what the website's profile route uses) and `searchName = cweId`.
- **Problem 2 (wrong type name):** the app's type key for weaknesses was `"weakness"`. The server's canonical slug is `"cwe"` (`docs/data-model.md`: every `entity_type` column stores `cwe`; the website's routes, cascade and profile config use `cwe` too). So `GET /api/entity-relationships?entity_type=…` and `GET /api/entity-notes?entity_type=…` never matched, and a note added in the app would have been stored under a type the website doesn't show.
- **Fix 2:** `EntityType.WEAKNESS.key = "cwe"`. `fromKey` still accepts "weakness", and `timelinePath` is now simply `key` (null for rules).
- **Verified on the emulator, CWE-416:**
  - The Articles tab shows **263**, and the chart shows "19 articles in 90 days · 2 feeds".
  - All four timeline requests return 200 with the UUID.
  - Relationships and Notes send `entity_type=cwe&entity_id=<uuid>` (200). This weakness has no relationships or notes on the server, so both show their empty states.
- **Tests:** new `ui/WeaknessProfileTest` (3 tests: server id, article query, type name).
- **Files:** `ui/entity/EntityPresentation.kt`, `data/model/EntityType.kt`.
- 169 unit tests pass.

### 10. Every profile type swept for rejected requests
Because weaknesses had an id/type mismatch, a scripted, read-only sweep opened the first item of every Workbench tab, then its Timeline and Articles tabs, and flagged any 4xx/5xx response. **No errors** for malware (Elise), CVEs, techniques, observables, tools, vendors, products, countries, campaigns or mitigations; each had 6–7 successful requests and a sensible article count. Threat actors (APT29) had been checked by hand. Detection rules have no timeline.

### State at the end of this part of the session
- `./gradlew :app:testDebugUnitTest :app:assembleDebug :app:lintDebug` succeeds. **169 unit tests, 0 failures.** Lint: 0 errors, 24 warnings (dependency versions, plus the deliberate self-hosted network config).
- The release build is minified. It was tested on the emulator with a local debug-key signature; a real signing config is still needed for distribution.
- **Emulator:** the debug build is installed and signed in. Settings are as the user had them: auto-mark-read on, alerts on, no tracked keywords (the test keyword was removed).
- **No server data was created or changed.** No articles were marked read: auto-mark-read was switched off whenever test articles were opened.
- **Remaining, low priority:**
  - Move the alert state (keyword seen-ids, alert keys) to its own DataStore file.
  - Keyword checks fetch full article details only to read `is_read`; this needs a lighter server endpoint.
  - The Keystore fallback stores tokens in plain text when the device has no usable Keystore. This is a deliberate design choice.
  - Dependency upgrades (OkHttp 5, Retrofit 3, work-runtime 2.11): the user's call.
  - Live tests of shared-data writes (subscribe to a feed, add an article, bulk add to campaign, mark a day read, create a server requirement) need the user's go-ahead.

### Deployed to the shared APK and the user's phone (13:50)
- `../IntelFeed.apk` (the Android Development folder) was replaced with the current debug build (`app-debug.apk`, 24.0 MB, SHA-256 `2c06ec6e…8638`). It's the same variant and debug signing key as the file it replaced (the 11:09 build from the Codex session), which is kept in the session scratchpad.
- Installed on the user's Pixel 9 Pro over USB with `adb install -r`, over the 11:06 build, so the data was kept. The app launched without crashes and the saved session was still there.
- This build has every change in this entry (security and alert fixes, reader memory, weakness profiles, R8 rules). R8 only applies to release builds, so this debug APK isn't shrunk.

### 11. Swiping a feed card set off an endless star/unstar (or read/unread) loop
- **Reported by the user:** the feed's swipe-left gesture "breaks the app".
- **Reproduced on the emulator:** one left swipe on a card in All articles sent **328** `POST /api/entries/bulk-action` requests in 10 seconds (164 star, 164 unstar, about 16 a second). The card stayed stuck in its swiped position until the loop happened to stop. The right swipe (read/unread) has the same loop.
- **Cause:**
  - Material3 1.4.0's `SwipeToDismissBox` runs `LaunchedEffect(state.settledValue, onDismiss) { if (settledValue != Settled) onDismiss(dismissDirection) }`. This was read from the class bytecode in the Gradle cache.
  - `SwipeableEntry` passed a new `onDismiss` lambda on every recomposition, and every star or read toggle re-renders the card with the updated entry.
  - Each toggle therefore restarted the effect while the row was still swiped, so `onDismiss` ran again and flipped the flag back.
  - Every call also launched a new `state.reset()`, which cancelled the previous spring-back, so the row stayed swiped and the loop kept going.
- **Fix (`FeedScreen.kt`, `SwipeableEntry`):**
  - `onDismiss` is created once per row (`remember(state, scope)`) and calls the latest actions through `rememberUpdatedState`.
  - An `AtomicBoolean` lets each swipe act once: it's set when the action runs and cleared when `reset()` finishes or is cancelled (a new drag cancels it, so a second swipe still works).
- **Verified on the emulator:** 4 swipes, 1 request each: left sent star, left again sent unstar, right sent `PUT …/unread`, right again sent `PUT …/read`. The card sprang back each time, with no crashes. The test article ended as it started (read, not starred). After the loop, the article had also ended unstarred, its original state.
- **Note for the user:** on builds before this fix, any swipe could leave an article's star or read state flipped the wrong way, because the loop's final state was essentially random. The Starred view shows any articles that ended up starred by mistake.
- No automated test covers this: it depends on Compose gesture timing, so it was tested on the device. 169 unit tests pass; lint reports 0 errors.
- `../IntelFeed.apk` was updated with this build (18:13). The phone wasn't connected, so it still has the 13:51 build with the loop.

---

## 2026-09-23 (eighth session): Exploratory bug hunt on the emulator

The user asked for about five minutes of hands-on exploration of the app on the emulator, followed by documenting and fixing what turned up. Nothing that changes the account was used: no starring, notes, tags, campaigns, share links or mark-all-read. Every article was already read, so opening them changed nothing.

### Areas covered
- **Feed:** Priority Queue, Starred, All articles, list and grid, the overflow menu, Hide read, day dividers.
- **Drawer:** counts, folders, a single feed, including one with fetch errors.
- **Reader:** Next/Previous, landscape and back, read aloud, text size, tag picker, More menu, similar coverage.
- **Search:** no results, malformed input, the filter sheet round trip, paging through four pages.
- **Workbench:** typing search, Watchlist.
- **Failures:** a real server outage (the API returned 502 for every request for a few minutes) and airplane mode.

### Found and fixed

| # | Bug | Severity | Fix |
|---|-----|----------|-----|
| 1 | **A feed opened from the drawer could look empty with no way to see its articles.** It inherits the current view, and after launch that's the Priority Queue (unread only inside a feed). The chips then show nothing selected and tapping one leaves the feed, so a fully read feed showed "All caught up". | Medium | New `IntelFeedViewModel.setScopedFilter(filter)` changes the view while keeping the feed or folder. The scope banner has a **Show all / Unread only** toggle, and the scoped "All caught up" state has a **Show all articles** button. (`FeedScreen.ScopeBanner`, `FeedEmptyState`) |
| 2 | **Search filters found nothing after an unclosed quote.** The filter sheet appends its tokens to the typed text, so `"ransomware` + Past 7d became one phrase, `"ransomware date:>=… is:starred`, with 0 results. | Low | New `SearchTokens.closeOpenQuote()` closes the quote before the tokens are added. After the fix the same steps give `"ransomware" date:>=2026-09-16`, 390 articles. Test: `SearchTokensTest.unclosedQuoteIsClosedBeforeFiltersAreAppended`. |
| 3 | **The reader's Previous/Next bar was 80 dp**, Material's fixed `BottomAppBar` height, for one row of text buttons. In landscape the top bar and this bar left about half the screen for the article. | Low | Replaced with a 56 dp `Surface` + `Row` that still pads for the navigation bar. |
| 4 | **Pull-to-refresh did nothing on the feed's full-screen error** (seen during the 502 outage). The error state was a plain `Box`, which can't be pulled; the empty state had already been made scrollable for this reason. | Low | The error state is wrapped in a `LazyColumn` (`fillParentMaxSize`). Verified in airplane mode: pulling on "Can't reach the server…" sends the requests again. |

The swipe loop (star/unstar flooding) was also found this session and is logged above as item 11.

### Checked and working (no change)
- A cold start with every article read shows "Nothing urgent right now", and the drawer hides zero counts.
- In Starred with Hide read on, the empty state explains itself. Rotation keeps the article and page, read aloud starts and stops, and the text size, tag picker and More menu work. Similar coverage opens the article, and Back returns to the list position ("2 of 4").
- Search: no results shows a helpful message, and suggestions appear for a dangling `threat_actor:`. The filter sheet re-reads Past 24h and Starred from the query and removes them cleanly. Four more pages of "ransomware" loaded. Workbench search typed one letter at a time sends one request for the final text. The Watchlist lists ShinyHunters.
- **Server outage (502) and offline:** the feed shows "The server had a problem (502). Try again shortly." or "Can't reach the server…", both with Try again, which works. The drawer keeps the folders it already had.

### Noted, not changed
- **Day chips in Starred show the same totals as All articles** ("30 actively exploited" for 2 starred articles). The app sends `is_starred=true`, as the website does, so the totals come from the server.
- **Grid cards without an image have an empty 36 dp gradient header.** This is by design (`EntryGridCard`), not a failed image.

### Verification
- `./gradlew :app:testDebugUnitTest :app:assembleDebug :app:lintDebug` succeeds: 170 unit tests pass, and lint reports 0 errors (24 warnings, as before). Each fix was checked on the emulator as described above.
- `../IntelFeed.apk` was updated with this build (18:43); the 18:13 APK is kept in the scratchpad. The phone wasn't connected.
- **Files:** `ui/IntelFeedViewModel.kt`, `ui/screens/FeedScreen.kt`, `ui/screens/SearchScreen.kt`, `util/SearchTokens.kt`, `ui/screens/EntryReaderScreen.kt`, `test/.../util/SearchTokensTest.kt`.

---

## 2026-09-23 (ninth session): Second exploratory bug hunt (untested areas, read-only)

The user (an admin on the server) asked for another hands-on pass over areas not tested before, without changing any setting that could affect the app or server. Nothing on the server was changed:
- Nothing was submitted, deleted, starred, tagged, watched or muted.
- The tag delete dialog and the share dialog were cancelled.
- Only already-read articles were opened.
- The only settings changed were the emulator's system font scale (1.0 → 1.3 → 1.0) and screen rotation, neither of which is an app or server setting.
- Story threads weren't opened: opening one stamps it as seen on the server.

### Areas covered
- **Feed:** selection mode (select all, the ⋮ menu, Back to exit), the day-divider chips (count chip, CVE chip → profile), the AI briefing (a single GET, never generates).
- **Profiles:** CVE Overview, Relationships (CVE → UNC5174 → its profile), Notes (view only).
- **Other screens:** Server requirements (list and expand), Settings (view only), the server tag manager (filter, delete dialog opened and cancelled).
- **Drawer:** Add feed dialog (validation only, cancelled), feed search.
- **Search:** the Entities scope.
- **Intents and lifecycle:** sharing a web link into the app, sharing an IntelFeed article link, rotation with the share dialog open, Android killing the process in the background, 1.3× system font.

### Found and fixed

| # | Bug | Severity | Fix |
|---|-----|----------|-----|
| 1 | **Coming back after Android killed the process reopened the app on the Priority Queue.** The open article, the rest of the back stack, and the feed's view and feed/folder were all lost. They were only in memory, so returning after a while in another app (e.g. the browser via "Open original") lost your place. | Medium | `Route` and its subclasses are `@Serializable`. New `RouteCodec` encodes the back stack to one string, with class discriminator `"route"` because `Route.Entity` has a `type` property. `IntelFeedViewModel` takes a `SavedStateHandle` (`createSavedStateHandle()` in `MainActivity`) and restores the stack, tab, view and feed/folder before the first load, then keeps them saved (a `snapshotFlow` on the stack plus the UI state). Saved state that can't be read is ignored, and encoding never throws. Keep rules were added for the routes. Verified in **both debug and the minified release build**: Starred → article, background, `am kill`, relaunch → the same article ("1 of 4"), and Back → Starred (4 articles). Test: new `ui/RouteCodecTest` (2 tests). |
| 2 | **Rotating with "Add to IntelFeed?" open dismissed the dialog and lost the shared link.** The link was only Activity state. | Low | `MainActivity.onSaveInstanceState` keeps the validated link (`pending_shared_url`), and `onCreate` restores it on re-creation. Verified: the dialog stays through landscape and back, and Cancel still closes it. |
| 3 | **Drawer "Find a feed" results appeared under the keyboard.** The search box sits below the views, keywords and saved searches, and the whole top of the drawer was one list item, so it couldn't be scrolled to. | Low | The folders header and search box are now their own list item (index 1). Typing scrolls to it, and the list has `imePadding()`. Checked on the emulator, whose keyboard is a small floating bar; the full-keyboard case follows from the insets. |

### Checked and working (no change)
- **Feed and profiles:**
  - Selection mode: "1 selected", the bulk bar, Select all → "30 selected", Back exits.
  - The CVE day chip opens the CVE profile.
  - CVE Overview facts and links; Relationships ("exploited by UNC5174 · Possible · 1 source") open the actor.
  - Notes shows "Notes are visible to everyone on your server".
  - The AI briefing loads and renders its Markdown.
- **Admin screens:**
  - Server requirements expand to all their keywords.
  - The tag manager filter is case-insensitive, and the delete confirmation says the tag is removed from the server and its articles; Cancel sends no request.
  - Add feed shows "That doesn't look like a web address." and "Find feed" stays disabled until the address is valid.
- **Links, search and display:**
  - A shared web link opens "Add to IntelFeed?" with trailing punctuation trimmed.
  - A shared `https://intelfeed.cc/?entry=<id>` opens the article directly.
  - Search Entities groups vendors, products and detection rules.
  - At 1.3× font, the feed, Workbench and cards lay out properly; the day-chip row scrolls sideways to reach the rest.
- **Saved state:** every `rememberSaveable` value is Bundle-safe (enums, strings, sets), so saving state can't crash the app.

### Noted, not changed
- **The "N actively exploited" day chip isn't tappable** (it has no entity), but it looks like the tappable chips. It could open a search for that day's KEV articles; that's a product decision.
- **Server data (for the admin):** the product **FortiGate**'s description is the Wikipedia text for *frigate* (a warship), and Fortinet's alias is "FortiClient". Both come from the server's automatic enrichment.
- **CVE profiles have no "Weaknesses" tab** like the website's (`/api/cves/{id}/weaknesses`). That's a parity gap, not a bug.

### Verification
- `./gradlew :app:testDebugUnitTest :app:assembleDebug :app:assembleRelease :app:lintDebug` succeeds: 172 unit tests pass, and lint reports 0 errors (24 warnings, as before). Two warnings from the `SavedStateHandle()` default argument were removed by making the parameter required.
- **Files:** `ui/navigation/Routes.kt` (serializable routes, `RouteCodec`), `ui/IntelFeedViewModel.kt` (saved state), `MainActivity.kt` (saved state handle, shared link), `ui/screens/FeedDrawer.kt`, `app/proguard-rules.pro` (route keep rules), `test/.../ui/RouteCodecTest.kt`.
- `../IntelFeed.apk` was updated with this build (22:13); the 18:43 APK is kept in the scratchpad. The phone wasn't connected. The emulator has the debug build again.

### Installed on the user's phone (2026-09-24 08:52)
- The current build (`../IntelFeed.apk`, SHA-256 `7e6d8274…0a85`, identical to `app-debug.apk`) was installed on the Pixel 9 Pro over USB (`adb install -r`), replacing the 2026-09-23 13:51 build that still had the swipe loop. The app data was kept.
- The app launched without crashes and the saved session was still there.

---

## 2026-09-24 (tenth session): Third exploratory bug hunt (read-only), plus speed fixes

The user asked for the same kind of pass as the eighth and ninth sessions: use the app on the emulator without changing anything on the server, then fix bugs and make security and performance changes. Nothing on the server was changed. Only already-read articles were opened, story threads weren't opened, and selection mode was used only to count cards (no bulk action). Local-only changes (grid/list layout, screen rotation) were put back afterwards.

### 1. Landscape: the tab screens left about a sixth of the screen for content
- **Seen on the emulator:** in landscape (about 411 dp tall), the Feed's top bar and view chips plus the 80 dp bottom navigation bar left roughly 70 dp for articles, less than one card. The Workbench (search box, type tabs, count line) was worse.
- **Fix (`Navigation.kt`, `HomeShell`):** when the window is under 480 dp tall (Material's compact height, i.e. a phone in landscape), the Feed / Workbench / Search tabs are a `NavigationRail` on the left instead of the bottom `NavigationBar`. The rail takes the start-side insets (`safeDrawing`, so a camera cutout is covered) and the tab content consumes them. As with the bottom bar, the rail is hidden in selection mode. Portrait is unchanged.
- New private helpers: `AppTab.presentation()` (label, icon, accent colour, shared by the bar and the rail) and `isShortWindow()` (`LocalWindowInfo.containerSize`, no new dependency).
- **Verified on the emulator:** in landscape the Feed shows a whole story card and the Workbench a whole actor card; switching tabs from the rail works. In portrait the bottom bar looks and works as before.

### 2. Observables showed "OBSERVABLE" for every value and always an "IOC" badge
- **Seen on the emulator:** every Workbench observable row said `OBSERVABLE`, every profile said "Observable (OBSERVABLE)" with "Type: OBSERVABLE", and every one had an "IOC" badge.
- **Cause:** `ObservableItem` was modelled on guessed fields (`type`, `is_ioc`, `tlp`). The server's observable ledger uses `kind` (ipv4, domain, url, sha256, cmdline, registry, script…), confirmed by `docs/data-model.md` (identity is `(kind, value)`) and by the website bundle (Workbench columns `kind`, `infra_tag`, `current_confidence`; profile badges and provenance panel). So `type` always fell back to its default `"observable"` and `is_ioc` to `true`.
- **Fix:**
  - `data/model/IntelModels.kt`: `ObservableItem` now has `kind`, `role`, `label`, `current_confidence`, `status`, `infra_tag`, `created_via` and `evidence`. **Removed:** `type`, `isIoc`, `tlp` (none exist on the server).
  - `ui/entity/EntityPresentation.kt`: the row subtitle is the kind (e.g. `DOMAIN · role: c2`), and the profile subtitle is "Observable · DOMAIN". Badges follow the web: "Confidence N%" (green ≥ 50%, amber ≥ 15%), the status when it isn't `active`, and "Dual-use" for `infra_tag`. The profile's Key facts show Kind, Label, Role, First/Last seen, Captured by, Infrastructure and Evidence when present.
  - `IntelFeedApi.getObservables` / `IntelFeedRepository.getObservables`: the unused `type` filter parameter is now `kind`, the web's filter name.
- **Tests:** new `ui/ObservableProfileTest` (2). `IntelFeedSerializationTest.testObservableDeserialization` now uses the real shape.
- **Verified on the emulator:** the Observables tab shows `DOMAIN` / `REGISTRY` with "Confidence 85%"; webhook.site's profile shows "Observable · DOMAIN", Kind DOMAIN, and "Captured by: ttp observable".

### 3. Profile Timeline said "→ 0% vs the previous 90 days"
- **Seen:** webhook.site's Timeline had 1 article in each 90-day window and showed "→ 0% vs the previous 90 days". When the previous window had none, no trend was shown at all.
- **Fix:** new `TimelinePresentation.trendLine(mentions, windowLabel)` (and `Trend(up, text)`), worded like the web profile: nothing when the change is 0% or there's no previous window; "↑ New: none in the previous 90 days" when the previous window had 0 and this one has some; and ">999%" for huge jumps. `EntityTimelineTab.MentionsCard` uses it. `trendPercent` is unchanged.
- **Test:** `EntityTimelineContractTest.trendLineMatchesTheWebWording`.
- **Verified:** webhook.site's Timeline no longer shows a trend line.

### 4. Speed: the Priority Queue's drawer count made two requests one after the other
- **Seen in the request log:** `GET /api/threads?status=open&limit=40` was only sent after `GET /api/entries/priority-unread-count` returned (1–2 s on the live server), so the Priority Queue badge took both times added together, at every launch, refresh and drawer open (when older than a minute).
- **Fix (`IntelFeedRepository.getViewCounts`):** both requests start together (`async` each); the total is still the entry count plus stories with unread articles, and still null when the entry count fails.
- **Verified:** both requests now leave in the same millisecond; after launch the count was ready in 2.3 s instead of about 4.4 s. The drawer shows the same number as before (23).

### 5. Speed: "Load more" in Search re-downloaded every entity group
- **Cause:** each further page of search results asked for up to 200 entities (25 per type), which the app ignores after page one (the entity groups come from page one).
- **Fix (`IntelFeedRepository.searchUnified`):** pages after the first send `entity_limit=1, entity_group_limit=1`, as profile article lists and the alert worker already do.
- **Verified on the emulator ("ransomware"):** the first page took 7.8 s and the next one 2.6 s. The Everything view still shows the entity groups (Malware · 60, Entities · 200) after paging.

### 6. Workbench: failed loads were silent, and a failed search showed the unfiltered list as its result
- **Seen on the emulator (airplane mode):**
  - Tapping Refresh with a list on screen did nothing visible.
  - Typing "lockbit" left "Showing 30 of 1,100" with Qilin, ShinyHunters… under the search text, as if they were the results.
- **Cause:** `WorkbenchScreen` only shows `workbenchError` when the list is empty, and `loadWorkbench` kept the previous list on failure.
- **Fix (`IntelFeedViewModel.loadWorkbench`):** a new private `workbenchItemsKey` remembers the tab and search the list was loaded for. When a load fails:
  - For the list already on screen (Refresh), the list is kept and a snackbar says "Couldn't refresh the Workbench. …" with **Retry**.
  - For a new search, the list is cleared, so the full-screen error with **Try again** appears.
- **Verified on the emulator:** offline Refresh shows the snackbar and keeps the list. Offline "lockbit" shows "Couldn't load this / Try again". Back online, Try again shows LockBit (1 item).

### 7. "Mark all as read" in the Priority Queue marked every unread article on the server read
- **Found by comparing with the website:** the web's toolbar "Mark all read" sends `POST /api/entries/mark-all-read` with `{radar_only: true}` in its Priority Queue view, and `{feed_id, category_id}` in the others. The app always sent only `feed_id` / `category_id`, so in the Priority Queue (the app's default view) it marked **all** unread articles read: 91 at the time of testing, against about 19 items in the queue. The dialog did warn "Every unread article in all of your feeds", but that isn't what the Priority Queue's button does on the web.
- **Fix:**
  - `MarkAllReadRequest` has a new `radarOnly` (`radar_only`), which is left out of the JSON unless set.
  - `IntelFeedRepository.markAllRead(feedId, categoryId, priorityOnly = false)`: `priorityOnly` sends `{radar_only: true}` only.
  - `IntelFeedViewModel.markAllAsRead` passes `priorityOnly` for the unscoped Priority Queue (new private `IntelFeedUiState.isPriorityQueueList()`). Inside a feed or folder, that view is plain unread articles, so it still sends the feed/folder.
  - `FeedScreen`'s dialog now says, in the Priority Queue: "Every article in the Priority Queue will be marked as read. Other unread articles stay unread."
- **Test:** `DayIntelContractTest.priorityQueueMarkAllSendsRadarOnly`. The existing test also checks that plain mark-all doesn't send `radar_only`.
- **Not exercised on the live server** (it would change the account): the dialog was opened and cancelled on the emulator, and no request was sent. `radar_only` isn't in `docs/api-reference.md`; the evidence is the website bundle (`useEntries` `mark-all-read` mutation, called with `e===\`radar\`?{radar_only:!0}:{feed_id,category_id}`). If the server ignored the field, the result would be the same as before this change.

### Checked and working (no change)
- **Workbench:** every type tab, paging (offsets 30/60/90 load as you scroll), and search shared across tabs (e.g. "webhook" in Observables, then Tools).
- **Profiles:** technique profile (platforms, data sources, detection text, articles with "Load more"), observable Timeline, Articles and Relationships. In landscape the profile header scrolls away properly.
- **Views:** Watched, Unread (loads every page to the end), grid view, and the drawer counts.
- **Reader:** a read article from Watched shows its PIR matches, linked intelligence and highlighted entities. Only its neighbour's detail is prefetched; nothing is marked read.
- **Search:** `cve.kev:true cve.epss:>0.5` (3,449 articles, 200 CVEs), Show more → Entities scope, and "Showing 25 of 200" at the end.
- **Offline (airplane mode):** Search and profiles show "Couldn't load this / Try again".
- **Accessibility:** feed-card buttons have labels (Star, Bookmark, More actions).
- **Matches the website:** mark-day-read (feed/folder plus the day's bounds), "mark all above" (bulk read of the unread ids above), and marking a story read (bulk read of its unread members).
- **Entry lists and dedup:** the app's lists don't send `dedup`, unlike the web; the server's default is already `dedup=true`, as found in the third session. Unread loaded 90 cards against a count of 91, with no duplicates seen.

### Noted, not changed
- ~~Search entity groups stop at 25 per type~~: fixed below (item 8).
- **Observables have Timeline and Notes tabs in the app**, but only Overview and Relationships on the web. They work (webhook.site: 1 article in 90 days), so they were left.
- **Country chips mix codes and names** (UNC5221 shows "CN", others "China"/"Russia"). This comes from the server's data.
- **In landscape the Feed's top bar and view chips stay pinned** (about a third of the height). With the rail, a card and a half fit. Collapsing them on scroll would be the next step if landscape matters.
- **A technique's article count differs** between the Workbench list (T1190: 1,798, the server's `article_count`) and its Articles tab (1,136, the unified-search total). Both numbers come from the server.

### Verification
- `./gradlew :app:testDebugUnitTest :app:assembleDebug :app:assembleRelease :app:lintDebug` succeeds: 176 unit tests pass (4 new), and lint reports 0 errors (24 warnings, as before, none in the changed files). Each fix was checked on the emulator as described above, except item 7, which writes to the account.
- `../IntelFeed.apk` was updated with this build (09:33, SHA-256 `8090c6ac…25d5`); the 2026-09-23 22:13 APK is kept in the session scratchpad. The emulator has this build. The phone still has the 2026-09-23 22:13 build (installed this morning).
- **Files:** `Navigation.kt`, `data/model/IntelModels.kt`, `data/model/EntryModels.kt`, `data/network/IntelFeedApi.kt`, `data/repository/IntelFeedRepository.kt`, `ui/IntelFeedViewModel.kt`, `ui/entity/EntityPresentation.kt`, `ui/entity/TimelinePresentation.kt`, `ui/screens/EntityTimelineTab.kt`, `ui/screens/FeedScreen.kt`. **Tests:** new `ui/ObservableProfileTest.kt`; updated `data/EntityTimelineContractTest.kt`, `data/DayIntelContractTest.kt`, `data/IntelFeedSerializationTest.kt`.

### 8. Search listed at most 25 entities of each type (user request)
- **Before:** `UnifiedSearchRequest` asked for `entity_group_limit=25`, so the Entities view ended with "Showing 25 of 200. Narrow the search to see others." even though the server had already matched all 200 (`entity_limit=200`). The website's search page asks for `entity_limit=200, entity_group_limit=500`.
- **Fix (`data/model/SearchModels.kt`):** the default `entityGroupLimit` is now 500, the web's value, so each type lists everything the server matched, up to 200 entities in total. The Everything view still shows 4 per type with "Show more"; the Entities view lists them all. Later pages keep sending 1/1 (item 5), and profile article lists and the alert worker are unchanged.
- **Test:** `IntelFeedSerializationTest.unifiedSearchAsksForEveryEntityOfAType`.
- **Verified on the emulator:**
  - `cve.kev:true cve.epss:>0.5` now lists all 200 CVEs, with no "Showing 25 of 200" note. The request took 2.0 s (1.8 s before).
  - "ransomware" lists Malware 60, Detection rules 66, Threat actors 51 and Vulnerabilities 23 in full (= 200). The same search on a temporary build with the old limit showed "Showing 25 of 51/60/66".
- **Testing note:** an early run seemed to show a type missing with the bigger limit. That was a measurement error: fast flings scrolled past group headers between UI dumps. With slow drags, every group is there. `docs/api-reference.md` confirms the per-type limit is applied after the counts and only trims rows.
- `../IntelFeed.apk` was updated with this build (10:00, SHA-256 `c6772b54…18b4`). 177 unit tests pass and lint reports 0 errors (24 warnings).

### Installed on the user's phone (2026-09-24 10:02)
- The current build (`../IntelFeed.apk`, SHA-256 `c6772b54…18b4`, with all eight items of this session) was installed on the Pixel 9 Pro over USB (`adb install -r`), replacing the 2026-09-23 22:13 build. The app data was kept.
- The app launched without crashes, the saved session was still there (14 requests returned 200, none 401/403), and there were no crash entries in logcat.

## 2026-09-24 (11:25): App icon now matches the website

- **Before:** the launcher icon was Android Studio's template (a white Android robot on a green grid).
- **Now:** it's the IntelFeed logo from the website, an orange (`#F78166`) hexagon network with an RSS symbol on the site's dark background (`#0D1117`). The source is `https://intelfeed.cc/favicon.svg`; `icon-512.png` and `manifest.webmanifest` on the site use the same design and colours.
- **Files:**
  - `res/drawable/ic_launcher_foreground.xml`: rewritten as a vector conversion of the site's SVG (24×24 viewBox in a group scaled 2.5× and moved 24dp, so the logo sits inside the 66dp safe zone of the 108dp canvas). The hexagram lines keep the SVG's 0.6 opacity (`strokeAlpha`). Circles are written as two arcs each.
  - `res/drawable/ic_launcher_background.xml`: now a flat `#0D1117` fill (the grid lines are gone).
  - `res/mipmap-anydpi-v26/ic_launcher*.xml`: unchanged. They still use the foreground as the `monochrome` layer, so themed icons (Android 13+) show the logo shape.
  - `res/mipmap-{mdpi…xxxhdpi}/ic_launcher.webp` and `ic_launcher_round.webp`: regenerated (lossless WebP) for Android 7.x (minSdk 24 predates adaptive icons): a dark rounded square or circle with the logo, rendered from the site SVG.
- The originals are kept in the session scratchpad (`orig_icons/`). Gemini: if the site's logo changes, re-convert `favicon.svg` the same way rather than using Image Asset Studio's default padding, which makes the logo smaller than on the site.
- **Verified:** `:app:assembleDebug :app:lintDebug` succeed (lint: 0 errors, 24 warnings, as before). On the emulator the launcher icon shows the site logo on a dark circle.
- **Build problem, not caused by this change:** since this morning, builds inside the Google Drive folder fail at `:app:packageDebugResources` with `Operation not permitted`. Google Drive now refuses `clonefile` (`cp -c` fails for any file there, not only the icons), and Gradle's copy step uses it. The build above was run from a copy of the project outside Drive (session scratchpad). **Fixed at 11:40, see "Builds work in the Drive folder again" below. Keep building in the Drive folder.**
- `../IntelFeed.apk` was updated with this build (11:27, SHA-256 `0278fa58…4d07`, 22.6 MB). Same variant (debug) and same debug signing certificate (`8377fdc7…9fd9`) as the 10:00 file, which is kept in the session scratchpad as `IntelFeed-2026-09-24-1000.apk`. The source copy used for the build was checked with `rsync --checksum` and matches the Drive project. It's 1.4 MB smaller than the 10:00 APK because it's a clean build without leftover intermediates in `build/`.
- **Installed on the Pixel 9 Pro (11:27)** over USB (`adb install -r`), replacing the 10:00 build. The app data was kept. The app launched with no crash entries in logcat. The first 16 requests got 401 because the access token had expired (the app was last opened at 10:02). Each one was refreshed and retried, and all of them returned 200, so the session was kept.

## 2026-09-24 (11:40): Builds work in the Drive folder again

- **Problem:** Gradle failed at `:app:packageDebugResources` with `Operation not permitted` (see the icon entry above). The cause was a per-file state: 85 files in the project (build scripts, `gradlew`, the wrapper jar, docs, and 19 files in `app/src`) refused `clonefile`, which Gradle uses to copy files, while about 100 others allowed it. No flag, extended attribute, ACL, open handle or Google Drive File Provider setting separates the two groups, and the system log records nothing. Earlier builds only worked because Gradle didn't need to copy those files again. A file that is deleted and written again can be cloned. A file rewritten in place without deleting it first keeps the problem.
- **Fix:** each of the 85 files was deleted and rewritten with the same bytes, permissions (`gradlew` stays executable) and modification time. SHA-256 was checked before and after for every file, and all matched. **No file content changed.** Backups are in the session scratchpad (`recreate_backup/`). `.DS_Store` files were left alone. Google Drive may treat these files as new, so their Drive version history might start again from today.
- **Verified in the Drive folder:** all 85 files can be cloned again. `./gradlew :app:testDebugUnitTest :app:assembleDebug :app:lintDebug` succeeds: 177 unit tests pass, and lint reports 0 errors (24 warnings, as before). The APK built in Drive has the same files and checksums as the 11:27 `../IntelFeed.apk` now on the phone, so neither was replaced.
- **If it comes back** (`Operation not permitted` from a copy or merge task): run `cp -c <file> /tmp/x` on the files to find the ones that fail, then delete and rewrite those files the same way. Don't move the build out of the Drive folder.

## 2026-09-24 (12:15): Bug fixes and quality-of-life enhancements

### Summary

Addressed all bugs discovered during live emulation and static analysis, followed by prioritized quality-of-life (QoL) enhancements. Prioritized high-impact bugs first (deserialization crash, HTML entity escaping, AI prompt leakage), followed by high-leverage user experience improvements (Find in article auto-focus, tappable KEV chip, long-press copy across panels and profiles, and resilient fallback entity profiles).

### Bug Fixes

#### 1. Crash on `/api/malware/{id}` when `associated_actors` contains bare strings (high)
- **Problem:** When viewing malware profiles on the live server (e.g. `CLOSEDQUORUM`), the server returned bare strings in `associated_actors` (`["Cisco Talos"]`) instead of objects (`[{"actor_id": "...", "name": "..."}]`). This caused `kotlinx.serialization` to throw `SerializationException: Expected JsonObject, got "Cisco Talos"` when calling `/api/malware/{id}`.
- **Fix:**
  - In `data/model/IntelModels.kt`, added `FlexibleAssociatedActorListSerializer` which handles both polymorphic shapes (`List<AssociatedActor>` objects and bare `List<String>`, mapping strings into `AssociatedActor(id = s, name = s)`).
  - Also added `FlexibleStringListSerializer` to tolerate both bare string lists and object arrays containing string fields.
  - Applied `@Serializable(with = FlexibleAssociatedActorListSerializer::class)` and `@Serializable(with = FlexibleStringListSerializer::class)` across `Malware`, `ThreatActor`, `Vendor`, `Product`, and `Tool`.
  - Added unit test coverage in `data/LiveShapeSerializationTest.kt`.
- **Verified:** Tested on emulator (`emulator-5554`) by opening `CLOSEDQUORUM`. The malware profile loaded without crashes, cleanly displaying "Used by Cisco Talos" in associated actors.

#### 2. HTML entity encoding in Requirements match cards and entity descriptions (medium)
- **Problem:** In Requirements match results and certain entity descriptions, HTML entities were displayed as raw entity literals (e.g. `SASE Converges Network &amp; Security...`, `&quot;`, `&#39;`).
- **Fix:**
  - In `ui/screens/RequirementsScreen.kt`, wrapped `requirement.title`, `requirement.description`, `m.entryTitle`, and `m.matchedOn` in `HtmlText.toPlainText(...)`.
  - In `util/HtmlText.kt`, added fallback unescaping logic in `toPlainText` so JVM unit tests run cleanly without requiring Android `HtmlCompat` mocking.
- **Verified:** Tested on emulator: Requirements matches now display decoded text (`&` instead of `&amp;`).

#### 3. Server AI prompt leakage in entity descriptions (medium)
- **Problem:** Certain backend entity descriptions (such as for `Apple macOS Sequoia`) contained internal LLM generation instructions and markup tags (e.g., `</new_description>`, `<parameter name="reason">...`).
- **Fix:**
  - In `util/HtmlText.kt`, added `HtmlText.cleanAiArtifacts(text: String?): String?` which cleans trailing LLM closure tokens and parameter tags.
  - In `ui/entity/EntityPresentation.kt`, wrapped all description mapping logic in `toWorkbenchItem()` and `toProfile()` with `HtmlText.cleanAiArtifacts(...)`.
  - Added unit tests in `util/HtmlSnippetTest.kt` verifying sanitization behavior.
- **Verified:** Entity workbench items and profile headers now display clean prose without prompt residue.

### Quality-of-Life Enhancements

#### 1. Auto-focus keyboard on "Find in article" in Reader screen
- **Problem:** Tapping "Find in article" from the reader overflow menu opened the search toolbar, but required an extra tap to focus the input field and summon the soft keyboard.
- **Fix:**
  - In `ui/screens/EntryReaderScreen.kt`, integrated `FocusRequester` and `LocalSoftwareKeyboardController`.
  - When `showFindInArticle` becomes true, a `LaunchedEffect` requests focus and invokes `keyboardController?.show()`.
- **Verified:** Tested on emulator: Tapping "Find in article" immediately focuses the search field and activates the keyboard; tapping close dismisses both.

#### 2. Tappable "Actively Exploited" Day Summary Chip in Feed
- **Problem:** Feed day headers summarize activity (e.g., "15 actively exploited"), but the chip was static text rather than an actionable filter.
- **Fix:**
  - In `ui/IntelFeedViewModel.kt`, added `searchKev()` which switches to the Search tab and executes a search for `cve.kev:true`.
  - In `ui/components/EntryCards.kt`, updated `DayChip`, `dayChips`, `DayHeader`, and `DayChipView` to accept `onSearchKev: (() -> Unit)? = null` and style the KEV chip with an interactive tap indication.
  - In `ui/screens/FeedScreen.kt`, connected `onSearchKev = { viewModel.searchKev() }`.
- **Verified:** Tested on emulator: Tapping "15 actively exploited" under the "Today" header immediately switched to Search and displayed 4,991 actively exploited CVE articles.

#### 3. Long-press to copy identifier / IOC / entity name / key facts
- **Problem:** Users could not easily copy entity names, CVE identifiers, observable IOCs, or key technical metadata from reader panels or profile headers.
- **Fix:**
  - In `ui/screens/EntryReaderScreen.kt`, added `onLongClick = { Clipboard.copy(context, chip.name, "Copied ${chip.name}") }` to `IntelPanel` chips.
  - In `ui/components/Common.kt`, added `onLongClick: (() -> Unit)? = null` to `FactRow` so any technical metadata row (e.g. CVSS, EPSS, hash, URL) can be copied on long-press.
  - In `ui/screens/EntityProfileScreen.kt`, added `onLongClick` to chips in profile chip groups (Aliases, Target Sectors, Target Countries, Associated Entities).
- **Verified:** Long-pressing chips and fact rows shows a haptic feedback toast and copies the string directly to the Android clipboard.

#### 4. Graceful fallback entity profile when backend returns 404
- **Problem:** When tapping an entity referenced in an article or observable where the standalone profile endpoint returned 404 / `NoSuchElementException`, the app showed a full-page error with no way to access the entity's related articles.
- **Fix:**
  - In `ui/entity/EntityViewModel.kt`, caught `NoSuchElementException` during `load()` and generated a fallback `EntityProfile(id, name, kind)`.
  - Automatically triggered `loadArticles(reset = true)` so users can still read articles referencing the entity even if a full biographical profile is missing on the server.
- **Verified:** Verified entity fallback lifecycle and error resilience in unit tests and model flow.

### Robustness Fixes
- Wrapped `Log.e(...)` in `IntelFeedRepository.apiCall` with `runCatching` to prevent `Method e in android.util.Log not mocked` exceptions during JVM unit test suites without Android framework mocking.

### Verification
- `./gradlew :app:testDebugUnitTest`: 179 tests completed, 0 failed (including new tests in `LiveShapeSerializationTest` and `HtmlSnippetTest`).
- `./gradlew :app:lintDebug`: 0 errors.
- `./gradlew :app:assembleDebug`: BUILD SUCCESSFUL.
- Updated `../IntelFeed.apk` with the latest build (23.3 MB, SHA-256 `ee1df5d1…f00a`).
- Installed and verified live on Android 16 emulator (`emulator-5554`).
- **Installed on Pixel 9 Pro (12:26):** Uploaded via `adb install -r`, launched with `cc.intelfeed.app/com.example.intelfeed.MainActivity`. Existing session was preserved (all API requests returned 200, zero crashes/errors).

---

## 2026-09-24: On-Device Article Translation with Google ML Kit

### Summary

Foreign-language articles (such as Ukrainian threat actor Telegram channels under the `CLOSEDQUORUM` malware profile) can now be translated directly on-device using Google ML Kit (`com.google.mlkit:translate` and `language-id`).

This works across **all Android devices** (Pixel, Samsung, Motorola, Xiaomi, etc.) running Android 7.0+ (API 24+), downloading small, official Google NMT models (~30 MB per language) directly through Google Play Services / ML Kit for fast, offline-capable translation without sending article content to third-party translation APIs.

### Key Changes

#### 1. ML Kit Translation & Language Identification Dependencies
- Added `mlkitTranslate = "17.0.3"` and `mlkitLanguageId = "17.0.6"` to `gradle/libs.versions.toml`.
- Added `implementation(libs.mlkit.translate)` and `implementation(libs.mlkit.language.id)` to `app/build.gradle.kts`.

#### 2. Core Translation Engine (`util/ArticleTranslator.kt`)
- `ArticleTranslator.identifyLanguage(text)`: Automatically detects source language using ML Kit's on-device language identification model.
- `ArticleTranslator.translateArticle(title, blocks, serverUrl)`:
  - Preserves HTML blocks (`ArticleHtml.Block`) so code snippets (`Block.Code`), images (`Block.Image`), and blockquotes (`Block.Quote`) retain their structure and formatting.
  - Translates paragraph text and plain text representation.
  - Caches translated articles in a thread-safe LRU `LinkedHashMap` (20 articles) to avoid redundant model executions and allow instantaneous toggling.
- `ArticleTranslator.translateText(text)`: Translates raw text (used for Text-to-Speech audio reading).
- `ArticleHtml.parseBlocks(detail, serverUrl)`: Exposed block parsing as a reusable helper in `ArticleHtml.kt`.

#### 3. Reader Integration & Controls (`ReaderViewModel.kt` & `EntryReaderScreen.kt`)
- **Reader State:** Added `translation: ArticleTranslation?`, `isTranslating: Boolean`, `showOriginal: Boolean`, and `translationError: String?` to `ReaderUiState`.
- **TopAppBar Action:** Added a dedicated Translate icon button with loading feedback.
- **Overflow Menu:** Added "Translate to English" / "Show original" menu options.
- **Translation Status Pill:** Displays `Translated from <Language> · Show original` (or `Show English translation`), allowing one-tap switching between original and translated article versions.
- **Find in Article:** Searches across translated blocks when translation is active.
- **Text-to-Speech (TTS):** When viewing translated text, TTS reads the translated English text instead of the foreign original.
- **Entity Linking:** Preserves entity tag overlays (`ArticleLinker.annotate`), so threat actor, malware, tool, and CVE chips remain interactive in the translated text.

#### 4. Settings & Preferences (`UserPreferences.kt` & `SettingsScreen.kt`)
- Added `KEY_AUTO_TRANSLATE` to DataStore in `data/local/UserPreferences.kt`.
- Added `autoTranslate: Flow<Boolean>` and `setAutoTranslate(Boolean)`.
- Added "Auto-translate foreign articles" toggle in `ui/screens/SettingsScreen.kt` under Reading preferences. When enabled, non-English articles automatically trigger on-device translation as soon as the reader screen opens.

#### 5. Unit Tests (`ArticleTranslatorTest.kt`)
- Created unit tests verifying language identification handling, block translation structure preservation, LRU caching behavior, and plain text extraction.
- Total test suite: 185 tests passing (0 failures).

### Verification
- `./gradlew :app:testDebugUnitTest`: 185 passed, 0 failed.
- `./gradlew :app:lintDebug`: 0 errors.
- `./gradlew :app:assembleDebug`: BUILD SUCCESSFUL.
- Updated root debug APK: `../IntelFeed.apk` (92.4 MB).
- **Live Emulator Test (`emulator-5554`):**
  - Navigated to `CLOSEDQUORUM` malware profile.
  - Opened article #2 (`@itarmyofukraine2022`, Ukrainian title: `"У шкідливого ПЗ CLOSEDQUORUM з'явилися рада директорів. Людей туди ще не набрали"`).
  - Tapped the Translate button in the top bar.
  - ML Kit downloaded the Ukrainian-to-English NMT model and translated the title to `"In harmful software, the Board of Directors appeared. People have not taken."` and translated the article body.
  - Tapped the status pill (`Translated from Ukrainian · Show original`) and verified instant toggling between Ukrainian and English.
- **Installed on Pixel 9 Pro (12:50):** Uploaded via `adb install -r`, launched with `cc.intelfeed.app/com.example.intelfeed.MainActivity`. Existing session was preserved (all API requests returned 200, zero crashes/errors).

---

## 2026-09-24: Customizable Target Translation Language in Settings

### Summary

Added user-selectable translation target language in Settings. The Translate button and auto-translate feature now translate foreign articles directly into the user's chosen language (supporting 50+ languages via on-device ML Kit, e.g. English, Spanish, French, German, Japanese, Chinese, Ukrainian, Arabic, etc.).

### Key Changes

#### 1. Preferences & Persistence (`UserPreferences.kt`)
- Added `KEY_TRANSLATE_TARGET_LANG` (`"translate_target_lang"`) to DataStore.
- Added `translateTargetLanguage: Flow<String>` (default `"en"`) and `suspend fun setTranslateTargetLanguage(code: String)`.

#### 2. Translation Engine & Multi-Language Caching (`ArticleTranslator.kt`)
- Added `SupportedLanguage(code, displayName, nativeName)`.
- Added `ArticleTranslator.getSupportedLanguages()`: returns all ML Kit supported languages sorted alphabetically by English name, with native names in parentheses (e.g. `Spanish (Español)`, `German (Deutsch)`, `Japanese (日本語)`).
- Updated `TranslationResult` to include `targetLanguageCode: String` and `targetLanguageName: String`.
- Partitioned translation cache by `"$entryId:$targetLang"` so translating an article into different languages caches both results without collisions.
- Updated `translateArticle` to accept `targetLang`, resolve via `TranslateLanguage.fromLanguageTag`, verify that `sourceLang != targetCode`, and translate directly to the target language.

#### 3. Reader Integration (`ReaderViewModel.kt` & `EntryReaderScreen.kt`)
- Added `targetLanguage` and `targetLanguageName` to `ReaderUiState`.
- `ReaderViewModel` collects `userPreferences.translateTargetLanguage` and passes it to `ArticleTranslator.translateArticle`.
- TopAppBar Translate button dynamically reflects the target language (e.g. `Translate to Spanish`, `Show Spanish translation`).
- Status pill updates to `Translated from <Source> · Show original` and toggles to `Show <Target> translation`.
- Overflow dropdown updates to `Translate to <Target>` / `Show <Target> translation`.

#### 4. Settings UI (`SettingsScreen.kt`)
- Added **"Translation target language"** under Reading preferences, showing the active language name (e.g., "Translate articles into English" or "Translate articles into Spanish").
- Tapping opens a modern `LanguagePickerSheet` with a live search filter (`OutlinedTextField`), radio button indicators, and "Selected" badges.
- Updated "Auto-translate foreign articles" description to dynamically include the target language name.

### Verification
- `./gradlew :app:testDebugUnitTest`: 187 unit tests passed, 0 failed (added `getSupportedLanguagesReturnsSortedList` and `translationCacheSeparatesTargetLanguages` in `ArticleTranslatorTest.kt`).
- `./gradlew :app:lintDebug`: 0 errors.
- `./gradlew :app:assembleDebug`: BUILD SUCCESSFUL.
- Updated root debug APK: `../IntelFeed.apk` (88 MB, SHA-256 `bc862a225c0852386e21b989102956c13e9a32c9a5cb23eab066c460b2e2cba0`).
- **Live Emulator Test (`emulator-5554`):**
  - Opened Settings ➔ Translation target language ➔ Searched "Span" ➔ Selected "Spanish (Español)".
  - Verified Settings updated: `"Translate articles into Spanish"`.
  - Navigated to `CLOSEDQUORUM` malware profile ➔ opened Ukrainian article #2.
  - Translate button displayed tooltip: `"Translate to Spanish"`.
  - Tapped Translate: ML Kit downloaded Spanish NMT model and translated Ukrainian title into Spanish: `"🇺🇦 En software dañino, apareció el Consejo de Administración. La gente no ha tomado."` and translated article body into Spanish.
  - Tapped pill: smoothly toggled between Spanish translation and Ukrainian original.
  - Reset language back to English in Settings.
- **Installed on Pixel 9 Pro (13:05):** Uploaded via `adb install -r`, launched with `cc.intelfeed.app/com.example.intelfeed.MainActivity`. Existing session was preserved (all API requests returned 200, zero crashes/errors).

---

## 2026-09-24 (afternoon, Claude): Review of Gemini's 24 Sept changes, then linked-intel highlighting and tagging made 1:1 with the website

The user asked Claude to review Gemini's changes since 11:27 (the entries above from "Bug fixes and quality-of-life enhancements" through "Natural voice enhancement") and to make the tagging and highlighting of linked intel work exactly like the website. The review diffed the current source against the 11:27 snapshot from the icon session. Originals of every file Claude touches are in this session's scratchpad (`before_claude/`).

### Part 1: fixes to Gemini's changes

1. **Fallback entity profile could write to the server under a made-up id (high).** `EntityViewModel.fallbackProfile()` (used when the server has no record for a name) set the profile's id to the raw name, e.g. "Cisco Talos". Watch/Mute, Notes, Relationships and Timeline then used that as the server id, so tapping Watch or saving a note would have written a watchlist row or shared note for an entity that doesn't exist.
   - `EntityProfile.placeholder` (new, default false) marks the fallback. For a placeholder the profile shows only Overview and Articles; the Watch/Mute chips and the Mute menu item are hidden (`EntityProfileScreen.kt`).
   - `loadRelationships`, `loadTimeline`, `loadMentions`, `loadNotes`, `saveNote` and `setWatchMode` return early for a placeholder, so nothing is read or written with the fake id even if a screen calls them.
   - The placeholder's description now says plainly that IntelFeed has no profile for this name yet.
2. **Reader scroll memory didn't save "back at the top" (medium).** In `ReaderBody` the `snapshotFlow` collector checked `parsed != null`, but it captured the value from the first composition. When the article wasn't cached, that was `null` forever, so position 0 was never saved: scroll down, back to the top, open an entity, press Back, and the reader jumped back down. It now reads the current value through `rememberUpdatedState` (`articleShown`, `reportScroll`).
3. **Translation ran the whole article through ML Kit twice (medium, speed).** `ArticleTranslator.translateArticle` translated every block and then `detail.contentText` again for read-aloud. The read-aloud text is now built from the translated blocks. The unused `plainText` parameter was removed (signature: `translateArticle(entryId, title, blocks, targetLang)`).
4. **Translation could use the wrong target language (low).** `ReaderViewModel` read `_state.value.targetLanguage`, which starts as "en" until the preference flow is collected. `translate()` and the cached-translation lookup in `onVisible()` now read `userPreferences.translateTargetLanguage.first()`. The article is also parsed off the main thread there (`Dispatchers.Default`).

Verified: `:app:compileDebugKotlin :app:testDebugUnitTest`: 192 tests, 0 failures.

Review notes that were **not** changed (for Gemini and the user):
- The debug APK grew from 23 MB to about 90 MB with ML Kit (native libraries for every ABI). An `abiFilters` setting or an App Bundle would cut it; not changed without asking.
- Translated articles lose their links and inline formatting (each block is translated as plain text). Entity and keyword highlighting is re-applied to the translated text, but names the model translates won't match.
- Auto-translate downloads a ~30 MB model per language pair without asking, including on mobile data (`DownloadConditions` has no Wi-Fi requirement).
- `FactRow` is now clickable with an empty `onClick` (for long-press copy), so a tap shows a ripple and TalkBack announces an action that does nothing.
- The app-language setting only translates a small set of strings (tabs, drawer headers, a few reader and settings rows); the rest of the UI stays English.
- The "N actively exploited" day chip: see Part 4 below (changed to match the website).

### Part 2: entity and glossary highlighting in articles now works like the website

Checked against the live site's reader code (`EntryReader-*.js`, `EntryReader.module-*.js` EntityHighlighter, `EntityGraph-*.js` glossary pass, `EntityPopover-*.js`). Differences found and fixed:

| | Before (app) | Website | Now |
|---|---|---|---|
| Colours per type | own palette (actor purple, malware orange, TTP amber…) | `--entity-*`: actor #f97316, malware #a855f7, CVE #ef4444, TTP #3b82f6, tool #eab308, vendor #6366f1, product #ec4899, country #06b6d4, CWE #b45309, mitigation #84cc16, observable #d946ef, rule #22c55e, campaign #14b8a6 | website palette in `EntityType.color()` (`ui/components/Common.kt`), so chips, profiles and highlights all change |
| Highlight look | text tinted in the type colour with a 12% background | normal text colour, 2px dotted underline in the type colour; observables monospace 0.94em | same (drawn in `ArticleContent.kt` `MarkedText`/`drawUnderlines`) |
| What is marked | actors, malware, tools, vendors, products, countries, CVEs, techniques | also CWE ids, mitigation names and ATT&CK ids, observables (value and the article's spelling, only when ≤200), from `/api/entries/{id}/cwes`, `/mitigations`, `/observables` | same (`ArticleTerms.entityTerms`, in the web's order) |
| Glossary terms | not shown | `POST /api/glossary/detect {entry_id}`; term name and search terms underlined (dotted, muted colour) and marked before entities; entities skip them | same; tap opens the term (category, maturity, description, technologies, "Search articles" = `"name" OR "term"…`) |
| Minimum length | phrases under 3 characters skipped | none | none (so "US" from a country's matched names is marked, as on the site) |
| Same phrase on two entities | first one won | last one wins (web order) | last one wins |
| Word boundary | Unicode letters | JavaScript `\w` = ASCII | ASCII |
| Inside links and code | skipped | marked; tapping the name opens the popover, not the link | marked, incl. code blocks; the entity takes the tap, the rest of the link still opens |
| Across markup | matched across `<b>`/`<a>` edges | one text node at a time | one text node at a time (`RichText.breaks`, `Code.breaks`) |
| Tap | opened the profile | popover with type/KEV/severity, value, facts, description, lookup links, Profile / Search / Copy | bottom sheet with the same content (`ui/reader/EntityPreview.kt`, `IntelSheets.kt`); Enrich and "Wrong?" (server writes) not offered |

Also:
- The Linked intelligence panel lists the new Weaknesses, Mitigations and Observables groups.
- **Bug fixed in Gemini's linker cache:** it was keyed on `System.identityHashCode(blocks)` plus the terms' hash only. Identity hashes can collide, which would show another article's highlights. Entries now keep the source list and terms and both are checked on a hit.
- Keyword highlights (tracked keywords, PIR keywords; app-only, the site has none) keep their amber style and still stay out of links and code; they go after glossary and entity marks.

**API and signature changes (Gemini, please read):**
- `ArticleHtml`: `SpanKind.GLOSSARY`; `Span.glossaryId`; `RichText.breaks: List<Int>` (text-node boundaries); `Code(text, breaks = emptyList(), marks = emptyList())`.
- `ArticleLinker.Term` is unchanged; GLOSSARY terms carry the glossary id in `entityId`. `annotate()` now also marks `Code` blocks. Matching rules are in the class comment; don't reintroduce a minimum length or Unicode boundaries for entities without checking the web code.
- `ArticleContent(... onEntityClick: ((EntityMark) -> Unit)?, onKeywordClick, onGlossaryClick: ((String) -> Unit)?)`: `EntityMark(type, id, name, text)` replaces the `(type, id, name)` lambda. `CodeBlock(code, modifier, marked = null)`.
- `EntryIntel` gained `cwes`, `mitigations`, `observables` (count/isEmpty include them). `ReaderUiState.glossary`. `IntelFeedRepository.detectGlossary(entryId)`, and the private `decodeItems()` helper for lists read as JSON.
- New models: `GlossaryMatch`, `GlossaryTerm`, `GlossaryTechnology`, `GlossaryDetectRequest`; new fields `ObservableItem.surfaceForm/sightingCount`, `Ttp.firstSeenAt`, `Cve.exploitStatus`, `Cwe.abstraction/parentCweId/mappingUsage/cweUrl/alternateTerms/firstSeenAt`, `wikipediaImageUrl` on actors, malware, vendors, products, tools and countries, `Tool.detectionArtifacts`.
- `EntryReaderScreen(onSearchQuery = …)` and `IntelFeedViewModel.searchQuery(query)` run a query as typed (used by the glossary sheet).

**Verified:** 204 unit tests, 0 failures (new: 10 in `ArticleLinkerTest` for the web rules, 2 in `ArticleHtmlTest` for text-node breaks). On the emulator: the new endpoints return 200 (glossary detect returns `[{"term": {...}, "match_count": n}]`, as modelled); "Exposed GitLab project email addresses…" shows dotted underlines in type colours and a Mitigations group; tapping "GitLab" opens the product sheet; the SpecterOps article underlines "offensive security" and "red teaming", tapping it shows the Red team term (IDENTIFY, mature, five technologies) and "Search articles" runs `"Red team" OR "red teaming" OR …` (1,102 articles). Entities inside links and headings are marked.

### Part 3: the list cards' intel tags now match the website's intel line

`intelCues()` (`ui/components/EntryCards.kt`) follows the web's `IntelBadges`: notes; the lead actor or malware with "+N" (actor_count + malware_count); **"N PIR"** with a bar coloured by PIR category (tactical #ef4444, operational #f97316, technical #06b6d4, strategic #8b5cf6); then "N TTPs", "N CVEs" (stronger chip when the worst severity is high, red #dc2626 when critical), "N Rules"; then the opportunity badge: **"KEV opportunity"** / **"high-risk opportunity"** (a KEV or high-risk CVE with no rule), else dashed **"detection opportunity"** or italic **"telemetry gap"**. Before: PIR first, "PIR ×2", "2 CVEs · KEV", "Detection gap", lowercase "rules", no telemetry gap.
- Chips are drawn like the web's (tinted fill, 1dp border, dashed border for gap/telemetry, text mixed toward the secondary text colour).
- Tapping the PIR chip opens the web's PIR popover as a sheet: matched requirements by category with "keyword: … · … relevance"; tapping one searches `pir:"<title>"`; "Requirements are yours to edit →" opens the Requirements screen. These go through a new `LocalIntelNavigation` (`IntelNavigation(searchQuery, openRequirements)`, provided in `Navigation.kt`).
- The intel line now also shows on **compact** rows and **grid** cards (`EntryGridCard(intel = …)`), as the web shows it on every list row and magazine card.
- Signature changes: `IntelCue(text, color, description, style: CueStyle, pirs)`; `CueStyle`; `PIR_CATEGORIES`; `PirMatchesSheet(pirs, onDismiss)`.

### Part 4: day chips filter the list, as on the website (replaces Gemini's KEV search)

On the web every chip under a day divider ("15 actively exploited", new malware, technique, sector, CVE, actor, malware, product, country) narrows the list to **that day's** articles that mention it, shows "Showing only <label> · Clear filter", and marks the chip active (✕); tapping it again brings the rest back. The app's entity chips opened the profile instead, and Gemini's "actively exploited" chip opened an all-time `cve.kev:true` search (4,991 results under a chip saying 15).
- New `DayFocus(dayKey, chip, label, params)` (`UserContentModels.kt`); `IntelFeedUiState.dayFocus`; `IntelFeedViewModel.setDayFocus(focus?)` (same chip again clears). `searchKev()` was removed.
- `GET /api/entries` gained `before` and a `@QueryMap focus` (`exploited_cves=true`, `entity_type`+`entity_id`, or `sector`, the web's params); `IntelFeedRepository.getEntries(dayFocus = …)` sends `since` = the later of the day's start and the view's own window, `before` = the day's end, like the web. With a focus the Priority Queue view uses the entries endpoint.
- The focus clears when the feed, folder or view changes (as on the web); a sort or hide-read change keeps it (`loadFeed(keepDayFocus = true)`).
- At most five chips per day, as on the web. `DayHeader(activeFocus, onDayFocus)` replaces `onEntityClick`/`onSearchKev`.

**Verified:** 204 unit tests, 0 failures (`IntelCuesTest` updated to the web's wording, 3 new cases). On the emulator (Last 24 hours): cards show "Contagious Interview +9", "4 PIR" with its bar, "7 CVEs", "KEV opportunity"; tapping "15 actively exploited" requested `/api/entries?since=<today 00:00 local>&before=<today 23:59:59.999>&exploited_cves=true` (200) and showed 5 articles under "Showing only articles mentioning an actively-exploited CVE · Today" with the chip marked ✕; the PIR sheet listed "Vulnerability Exploitation & Weaponization (keyword: zero-day · medium relevance)" and tapping it searched `pir:` (7,246 articles).

**APK:** `../IntelFeed.apk` replaced with this build (debug, 92 MB, SHA-256 `7bfc6025…aba0`). The previous file (Gemini's 13:40 build) is in this session's scratchpad as `IntelFeed-before-claude-1425.apk`. Installed on the emulator only; the Pixel wasn't connected.

**Still different from the website (not done):**
- The web popover's "Enrich" and "Wrong?" (false-positive report, unlink, merge) write shared server data; not offered.
- The web's glossary "View in panel" (glossary section of the Intel panel) has no app equivalent; the sheet has "Search articles" only.
- The web reader also has a kill chain / ATT&CK navigator view and URLs list (`/entries/{id}/kill-chain`, `/ttps/navigator`, `/urls`); not in the app.
- The web's "?" legend next to the day chips isn't shown.
- `:app:lintDebug`: 0 errors, 26 warnings (24 before today's changes).
- **Installed on the Pixel 9 Pro (14:30)** over USB (`adb install -r ../IntelFeed.apk`, SHA-256 `7bfc6025…`). App data kept; it launched with no crash entries and all 15 startup requests returned 200.

---

## 2026-09-24 (afternoon, Claude, continued): Workbench graphics the website has and the app didn't

The user asked Claude to go through the Workbench on the emulator and add the graphics and core features the website has there. Survey of the site (lazy chunks `WorkbenchPage`, `EntityProfilePage`, `AttackMatrixSection`, `RansomwareSection`, `DashboardPage`, `ThreatsPage`, `EntityGraph`, `entityProfileConfig`) against the app:

- **Website Workbench sections:** the 11 entity lists (app has them), Rules Library, Campaigns, Watchlist, Requirements (app has these), plus **ATT&CK Matrix**, **Ransomware tracker**, Glossary, Reports, Telegram Mentions, Telemetry Sources (app had none of these).
- **Website profile tabs:** Overview, **Relationships (drawn as a graph)**, **Detection**, **Vulnerabilities** (vendors, products, CWEs), **Weaknesses** (CVEs), **Geography** (countries). App: Overview, Timeline, Articles, Relationships (list), Notes.
- **Also on the website only:** /workbench/dashboard (widget dashboard: ATT&CK heatmap, trending charts, CVE severity, feed activity and more), /workbench/threats (ranked threats and "your stack").
- The app's only chart was the Timeline tab's mentions bars.

### 1. ATT&CK Matrix (new Workbench tab, after Techniques)

- `GET /api/attack/matrix?domain=&days=` → `AttackMatrix` (`data/model/AttackModels.kt`: tactics → techniques → sub-techniques with `article_count`, `rollup_article_count`, `rule_count`, `coverage`, `missing_data_sources`; `coverage_summary`; `max_article_count`). `IntelFeedRepository.getAttackMatrix(domain, days)`.
- `ui/workbench/AttackMatrixView.kt` (`AttackMatrixViewModel`, `AttackMatrixView`): the web's controls (Enterprise / Mobile / ICS; 7d / 30d / 90d / All, default 30d; Feed heat / Coverage / Both, default Both; Expand/Collapse subs), the coverage summary (covered / missing telemetry / no rule) and one 148dp column per tactic, scrolled sideways. Cells use the web's shading: heat = 15% + 75% × √(articles / max) of the technique blue; coverage = a 3dp left edge in green / amber / red (Coverage mode tints the cell instead). A collapsed parent shows its roll-up count, as on the web. Tap opens the technique profile; long-press shows the web tooltip's numbers (tactic, articles, rules and coverage, missing telemetry) in a sheet.
- `WorkbenchTab.ATTACK_MATRIX` with `WorkbenchTab.isView` (no search box; `fetchWorkbench` returns an empty page for it). The matrix only loads when the tab is first opened, and keeps its state while you move between tabs.
- Not done: the web's "Export Navigator JSON".
- Also fixed: technique ids in a profile's ATT&CK list were amber; now the technique blue, like everywhere else.
- **Verified:** new `AttackMatrixTest` (payload decoding, heat formula). On the emulator the live matrix loaded (enterprise, 30 days: 697 techniques, 377 covered, 83 missing telemetry, 237 no rule); expanding T1595 showed its three sub-techniques and its own count (12 instead of 24); tapping T1595.002 opened its profile (`/api/ttps/by-technique/T1595.002`).

### 2. Ransomware tracker (new Workbench tab, after ATT&CK matrix)

The web's Workbench "Ransomware" section (`RansomwareSection-*.js`), both views:
- **Leak Watch:** `GET /api/ransomware/disclosures` (limit 60, offset, `sort` recent/group/sector, repeated `group`/`sector`/`country`, `watched_only`, `since` days, `q`). Search box; 24h / 7d / 30d / All; Watched only; **Filters** sheet with the web's facets (group with its colour dot, sector, country, each with counts, multi-select); sort menu. KPI cards (new victims with ▲/▼ vs prior, active groups, top sector, watchlist hits), the "WATCHLIST HIT" banner, Today / Yesterday / This week / Earlier dividers, and rows (pulse dot, NEW / WATCHED tags, group chip → group profile, sector, country). Tap a row for Data claimed, First seen, Publish deadline, Source, "Pivot to <group> profile" and "Leak site post". The star watches or unwatches the organisation on **your own** watchlist (`PUT/DELETE /api/intelligence/watchlist`, type `ransomware_victim`), as on the web.
- **Landscape:** `GET /api/ransomware/stats?days=` (30d / 90d / 1y, default 90d): five KPI cards (victims and change, most active group, fastest riser, sectors hit, watchlist exposure), the **weekly line chart** (accent line and area gradient, dashed average, y ticks at 0 / ⅓ / ⅔ / max×1.12, every other week labelled, last point marked; tap to read a week), and bar charts: most active groups (group colours, count, ▲/▼ week-over-week; tap → profile), sectors (share %), countries, and the watchlist exposure list (HIT / CLEAR).
- Colours as on the web: `--rgroup-*` group palette (the server sends a key such as "qilin" in `group_color`), `--entity-victim` for rises and NEW, `--success` for falls, `--accent` for the line and sector bars.
- Files: `data/model/RansomwareModels.kt`, `ui/workbench/RansomwareViewModel.kt`, `ui/workbench/RansomwareView.kt`; API `getRansomwareDisclosures`, `getRansomwareStats`; `WorkbenchTab.RANSOMWARE` (a view). `IntelFeedViewModel.messenger` is now public (the Workbench view models use it).
- **Verified:** new `RansomwareTest` (decoding, colours, day buckets). On the emulator: 7-day Leak Watch showed 161 disclosures (43 active groups, Manufacturing top sector) with Qilin rows in its colour; a row expanded to its details and pivot/leak links; picking Akira in Filters requested `…&group=Akira&since=7`; Landscape (90d) showed 2,661 victims ▲10.1%, Qilin most active, INC Ransom fastest riser, the weekly chart and the group bars. 208 unit tests, 0 failures.

### 3. Relationship graph on profiles (Relationships tab)

- `GET /api/intelligence/graph/{type}/{id}?depth=1&window_days=` → `EntityGraph` (`data/model/GraphModels.kt`: nodes `{id: "<type>-<uuid>", type, label, size}`, the first node being the entity; edges `{source, target, weight, label, confidence}`; checked on the live server: Qilin has 314 nodes and 436 edges over 10 types). `IntelFeedRepository.getEntityGraph`; `EntityViewModel` loads it with the Relationships tab (`graph`, `graphLoading`, `graphError`, `graphWindowDays`, `setGraphWindow`).
- `ui/entity/GraphLayout.kt` ports the web's radial layout (`re()` in `EntityGraph-*.js`), first ring only: the entity in the middle, its direct links on a ring grouped by type in first-seen order, strongest first, 5 per type by default ("+N" adds 4, up to 20, as on the web), sectors sized by share (at least 0.25 rad) starting at the top, ring radius max(15 % of the view, 28 × nodes / 2π). Node radius = size × 2 + 4 within 6–16.
- `ui/entity/EntityGraphView.kt` draws it at the top of the Relationships tab: the web's shapes and colours (malware hexagons, techniques squares, CVEs triangles, countries ringed circles, articles grey cards, everything else circles), a halo on the entity, edges coloured by the linked type with width by strength and dashes for "possible", type labels, "+N" pills, a legend that hides types, and All time / 30d / 90d / 1y. Tap a node to open it (an article node opens the reader).
- **Differences from the web, made for phone screens:** labels run along each spoke instead of under the node (the web's horizontal labels piled on top of each other at this size), node size is capped to the gap between neighbours, and the ring is scaled to leave room for the widest label. The web's second ring (double-click to expand a node), story hulls, edge popovers and drawing new relationships are not done.
- **Verified:** new `GraphLayoutTest` (strongest-first per type, overflow, equal ring distance, hidden types, minimum radius). On the emulator Qilin's graph showed its actors, CVEs, malware, tools, countries, techniques, vendors and products with "+35", "+38" and so on; tapping LockBit opened its profile. 210 unit tests, 0 failures.

### Website Workbench features still missing in the app (backlog)

- **Dashboard** (`/workbench/dashboard`): configurable widgets, among them ATT&CK heatmap, trending actors/CVEs/malware/TTPs/vendors/products, CVE severity, feed activity, intel velocity, targeted countries, PIR coverage, KEV deadlines, actor activity, campaign momentum, "Under the radar", morning briefing.
- **Threats** (`/workbench/threats`): threats ranked by attention and new tradecraft, and "your stack" (followed vendors/products with KEV / EPSS ≥ 50 % / no-rule filters).
- **Profile tabs:** Detection (rule coverage, detection gaps, generate rule), Vulnerabilities (vendor, product, CWE: affected CVEs sorted by CVSS / EPSS), Weaknesses (CVE → CWE ladder), Geography (country). The Relationships tab's Claims / Co-mentions split.
- **Workbench sections:** Glossary, Reports, Telegram Mentions, Telemetry Sources; the matrix's "Export Navigator JSON".

**Build (15:10):** `:app:lintDebug` 0 errors (29 warnings). `../IntelFeed.apk` replaced with this build (SHA-256 `7212b93c8f6f…`); the 14:30 file is in this session's scratchpad as `IntelFeed-1430.apk`. Installed on the emulator. **Not installed on the Pixel:** it disconnected from USB before the install; run `adb install -r ../IntelFeed.apk` when it's plugged in again (the 14:30 build is on the phone).
- **Installed on the Pixel 9 Pro (after reconnecting)** over USB: `../IntelFeed.apk` (SHA-256 `7212b93c8f6f…`, rebuilt first, unchanged). App data kept; it launched with no crashes and all 15 startup requests returned 200.

---

## 2026-09-24 (15:20, Claude): APK version tracking

The user asked for a version tracker for every APK update. **Gemini, please use this from now on instead of copying the APK by hand.**

- `version.properties` (project root) holds `versionCode` and `versionName`; `app/build.gradle.kts` reads it (don't set the version in the Gradle file). The build number must always go up: Android won't install a lower one over a higher one.
- `APK_VERSIONS.md` (project root) is the release history, newest first: version, build, date, SHA-256 (first 12), who, what changed, installed on. Details stay in this log.
- `tools/release_apk.sh "<what changed>" [--by Claude|Gemini] [--major]` bumps the version (1.1 → 1.2; `--major` → 2.0), runs the unit tests and the debug build (a failure puts the old version back), copies the APK to `../IntelFeed.apk`, adds the history row and installs it on every connected device with data kept. `tools/release_apk.sh --install` installs the current `../IntelFeed.apk` on whatever is connected now (e.g. the phone plugged in later) and adds it to the row.
- Settings shows "IntelFeed for Android 1.1 (build 2)" (`SettingsScreen.kt`, now with the build number).
- Every APK before this is recorded as 1.0 (build 1). **Released 1.1 (build 2)** (SHA-256 `a53cdd8d356a`): same features as the 15:10 build; installed on the emulator, where Settings shows the new line. **The Pixel disconnected from USB again before the install**; run `tools/release_apk.sh --install` when it's back (it has the 15:10 build, which reports 1.0).
- **1.1 installed on the Pixel 9 Pro (15:25)** with `tools/release_apk.sh --install`: the phone reports versionName 1.1, versionCode 2; data kept, no crashes, all 15 startup requests returned 200. `APK_VERSIONS.md` lists it.

---

## 2026-09-24 (15:45, Claude): Day chips follow the view's time range — released as 1.2 (build 3)

- **User report:** on This week, tapping a day chip (e.g. "18 actively exploited" under Today) still showed only today's articles. The web behaves the same (a chip filters to its own day), but the user wanted the filter to match the view.
- **Change:** `DayFocus.window` (new `FocusWindow`: DAY, H24, D7, D30, ALL). Tapping a chip now uses the open view's range: Last 24 hours → 24h, This week → 7 days; other views (Unread, All, Priority, Starred…) keep the chip's day. The "Showing only …" bar has a range picker (the chip's day, 24h, 7 days, 30 days, All time; `IntelFeedViewModel.setDayFocusWindow`), and its text says the range ("· last 7 days"). For 24h/7/30 days the repository sends `since` = now − range and no `before` (it replaces the view's own window); All time sends neither; the day keeps the web's day bounds.
- **Files:** `UserContentModels.kt` (DayFocus, FocusWindow), `IntelFeedRepository.getEntries`, `IntelFeedViewModel` (`setDayFocus` default, `setDayFocusWindow`, `applyDayFocus`), `FeedScreen.kt` (bar with picker).
- **Verified on the emulator:** This week → "18 actively exploited" requested `/api/entries?since=<7 days ago>&exploited_cves=true`, the bar read "… · last 7 days" with 7 days selected, and the list showed Today and Yesterday; "30 days" requested `since=<30 days ago>`. Released with `tools/release_apk.sh` as **1.2 (build 3)**, SHA-256 `75001a8e9145`; installed on the emulator. The Pixel wasn't connected.
- The emulator had been shut down and came back signed out ("session expired"). The app only ends a session when the server rejects the refresh token (network errors don't), so the server rejected it, most likely because the emulator was killed during a token refresh; no code change. The user signed back in.
- **1.2 installed on the Pixel 9 Pro (15:50)** with `tools/release_apk.sh --install`: the phone reports 1.2 / build 3; data kept, no crashes, all 24 startup requests returned 200.

---

## 2026-10-02 (Claude): The app goes into the backend repo on GitHub, with CI builds and releases

The user asked for the app and its APK to go to GitHub through a pull request, with automatic builds so the latest APK is always downloadable. It goes into Austin's existing repo **a-oneil/IntelFeed** (private) as the folder `android/`, not a new repo. **Gemini: this folder is still where the app is developed;** GitHub gets a copy through `tools/sync_to_github.sh`.

- **Git here:** the work is on the branch `android-on-github` of this folder's local repo (git dir `~/programming/IntelFeed_App.git`); merge it into `main` once the GitHub PR is merged.
- **`tools/sync_to_github.sh "<what changed>"`** (new): exports the last commit (tracked files only, no uncommitted edits) into a worktree of the backend repo at `~/programming/IntelFeed-android-sync` (branch `android-sync`, always fresh from `origin/main`), commits it as `android/`, pushes it and opens a PR (or updates the open one). It refuses if `android/` on GitHub was changed by someone else; then **`tools/sync_to_github.sh --pull`** applies those GitHub changes here as one commit, with a `GitHub-Tree:` trailer that tells later syncs it's been brought in. It needs `gh` logged in and the backend clone at `~/programming/IntelFeed` (or `INTELFEED_BACKEND_CHECKOUT`).
- **CI (in the backend repo, not in this folder):** `.github/workflows/ci.yml` gets an `android` job. It runs when `android/**` or the workflow changes (not on the Monday schedule): JDK 17, `./gradlew :app:testDebugUnitTest :app:assembleDebug`, and the APK is attached to the run as an artifact. On `main`, when `version.properties` has a version with no `android-v<version>` release yet, it publishes that release with `IntelFeed.apk` attached. **So a change only reaches the Releases page if its version is new: run `tools/release_apk.sh` before syncing.**
- **Signing:** CI signs with the user's existing debug key, the same `~/.android/debug.keystore` that signed every APK so far (SHA-256 `8377fdc7…`). Builds from GitHub therefore install over the phones' current builds and keep their data. The key goes in the repository secret `ANDROID_DEBUG_KEYSTORE` (base64). Only the repo owner can add it. Until it's there, CI builds and tests but doesn't publish.
- **`docs/` no longer committed** (`.gitignore`: `/docs/`). Those 51 files are copies of the backend repo's `docs/` and are already in that repo; they stay on disk for reference.
- **Removed `w.xml`**, a stray file whose content was a literal unexpanded `$(adb … cat /sdcard/window_dump.xml)`.
- **`TokenCipherTest.kt:17`:** the sample token's header is now the standard example JWT header (`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`). The backend repo's gitleaks scan blocks JWT-shaped strings and allowlists only that header. The test's behavior doesn't change.
- **New `README.md`** (becomes `android/README.md` on GitHub): what the app is, where to get the APK, how releases work, the local build. `APK_VERSIONS.md`'s how-to now covers GitHub publishing.
