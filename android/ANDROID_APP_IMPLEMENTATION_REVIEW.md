# IntelFeed Android implementation review

**Reviewed:** 2026-09-22  
**Purpose:** A code-and-documentation handoff for future LLMs working on the Android client.  
**Scope:** Existing Android source, build configuration, tests, `claude_changes.md`, and the product/API/frontend/user-guide documentation under `docs/`. This file is an assessment only; no application source was changed during this review.

## Executive assessment

This repository contains a functional native Android companion for IntelFeed, not a native reimplementation of the documented React website.

The app already supports a credible mobile triage loop:

1. Sign in to an IntelFeed instance.
2. Browse the Priority Queue or ordinary feed filters.
3. Filter by a feed or top-level category.
4. Read an article, mark it read/unread, star or bookmark it.
5. View extracted threat-intelligence badges and pivot into selected dossiers.
6. Create and delete article notes.
7. Search entries and entities.
8. Browse six read-only Workbench domains.

The implementation is therefore beyond a mock-up: the visible data comes from real REST endpoints, mutations are wired to the server, authentication refresh is handled, and both debug and release variants build.

It is not close to full website parity. The documented website includes dashboards/widgets, rich triage, story-thread reading, extensive entity profiles and relationships, feed management, saved searches, reports, automation, AI/copilot, settings/admin tools, detection-rule authoring, sharing, exports, and many additional entity types. Most of those surfaces do not exist in the Android app.

Reasonable planning estimates, not formal acceptance-test results:

- **Core mobile reading/triage:** about 65-75% of a useful first mobile release.
- **Read-only intelligence browsing:** about 35-45% of the documented experience.
- **Full documented website parity:** roughly 20-30% by user-facing capability.
- **Production readiness:** alpha/beta quality. The core is sound, but automated coverage and distribution/security hardening are incomplete.

The most important product decision is whether this should remain a focused mobile companion or pursue broad website parity. Future work should not assume the latter without an explicit decision.

## What is in the repository

- One Android application module using Kotlin and Jetpack Compose.
- 23 production Kotlin files, approximately 6,739 lines.
- Seven major Compose screens/components: login, feed, feed drawer, reader, search, Workbench, and entity dossier.
- A single `IntelFeedViewModel` and immutable `IntelFeedUiState` coordinating nearly all UI state.
- Retrofit/OkHttp networking with 31 declared REST operations.
- DataStore-backed server URL and authentication state.
- 17 JVM unit tests across URL normalization, JSON serialization, and date formatting.
- 51 Markdown documents copied from or describing the larger IntelFeed web/backend project.
- No Android-specific product requirements document, no UI test implementation, no screenshot tests, and no end-to-end Android test suite.
- No Git metadata is present in this directory. `claude_changes.md` is the only change history supplied with the project.

The docs reference root files such as `readme.md`, `setup.md`, and `CLAUDE.md` that are not present here. Also, `docs/frontend.md` describes the React/TypeScript web SPA, not this Android codebase. Treat it as a parity reference, not as an Android architecture guide.

## Architecture currently implemented

### UI and navigation

- `MainActivity.kt` creates `AuthPreferences`, `IntelFeedRepository`, and `IntelFeedViewModel`, then renders `MainNavigation`.
- `Navigation.kt` uses a small manual destination state machine: login, main shell, reader, or dossier.
- The main shell has three bottom tabs: Feed, Workbench, and Search.
- Reader and dossier screens are full-screen overlays selected from ViewModel state.
- Android back closes a dossier, closes the reader, or returns a non-feed tab to Feed.
- There is no Navigation component graph, route/deep-link model, or true nested back stack. Navigation3 dependencies are present but unused.

This structure is simple and understandable, but it will become fragile if many more screens or deep links are added.

### State and data flow

- A single `StateFlow<IntelFeedUiState>` owns session, feed, reader, notes, Workbench, dossier, and search state.
- The ViewModel maintains one cancellable `Job` per screen area to prevent stale responses overwriting newer state.
- The repository wraps API calls in `Result` and preserves coroutine cancellation.
- Most writes are optimistically reflected in UI and rolled back or reloaded after failure.
- Apart from credentials/server URL, application state is memory-only. There is no Room cache, offline feed, saved scroll position, or process-restored domain state.

### Networking and authentication

- The login screen accepts a configurable instance URL, username, and password.
- Server addresses are normalized and validated before Retrofit creation.
- Access and refresh tokens are persisted in DataStore.
- The OkHttp interceptor adds bearer auth, performs a single-flight refresh after a 401, and retries once.
- Only refresh-endpoint 401/403 responses clear the local session; transient failures retain it.
- Logout clears local state first and then makes a best-effort server revocation call.
- Release builds omit HTTP logging; backup and device-transfer rules exclude DataStore.
- Unknown JSON fields are ignored, which gives reasonable forward compatibility with a growing server response.

### Build configuration

- Application ID: `cc.intelfeed.app`.
- Minimum SDK 24; target/compile SDK 36.
- Kotlin/JVM toolchain 17.
- Compose Material 3, Retrofit, OkHttp, kotlinx.serialization, DataStore, Coil, and Navigation3 are declared.
- Coil and Navigation3 are currently unused.
- Release minification is disabled.
- There is no release signing configuration in the checked-in project.

## Feature comparison with the documented website

| Area | Android implementation | Compared with documented site | Status |
|---|---|---|---|
| Authentication | Configurable instance, username/password login, persisted session, reactive logout, refresh-token rotation | No registration, invite flow, account/profile/password management, or external/OAuth flows | Strong core, partial scope |
| Feed list | Priority Queue, unread, all, starred, bookmarked, feed/category scoping, cursor paging, refresh, mark-all-read | No day grouping/summaries, density modes, date/type/tag filters, bulk selection, virtual folders, saved searches, or keyboard workflow | Useful mobile subset |
| Feed drawer | Top-level categories, nested feed rows, unread counts, triage queues | Only first 100 feeds; no feed search; no recursive child categories; no uncategorized management; no add/edit/import/subscription controls | Partial |
| Priority Queue | Uses `/api/entries/priority-queue`, preserves score, displays thread-shaped rows | No Why-ranked card, signal breakdown, feedback, threshold controls, watch/mute steering, or actual thread spine reader. A story row opens its first absorbed entry | Partial |
| Article reader | Title/metadata, plain-text article body, font sizing, original link, native share, read/star/bookmark, extracted actor/malware/CVE/TTP/country badges, article notes | No rich HTML/media, image/audio/video handling, in-body autolinks, wrong-link correction, tags, comments, AI panel, TTS, Markdown export, public share link, add-to-campaign, send-to-report, or adjacent-entry navigation | Good basic reader, large parity gap |
| Notes | List, create, delete notes attached to an entry | No edit, title/type/tag/pin controls, standalone notes, entity notes, markdown rendering, comments, permissions display, or confirmation on delete | Basic CRUD subset |
| Search | Calls the real unified-search endpoint; displays entity and article results; local chips for article/entity/actor/malware/CVE/rule | No Everything/Workbench/Feeds scope, direct-vs-mention grouping, server facet rail, parsed-filter chips, autocomplete, suggestions, saved searches, pagination, notes-specific UX, or full entity-type navigation | API connected, UI incomplete |
| Workbench lists | Read-only lists/search for threat actors, malware, CVEs, TTPs, detection rules, and campaigns | No Dashboard/widgets, Reports, Threats, ATT&CK matrix, telemetry, exposure, glossary, ransomware, PIRs, watchlist, countries, observables, vendors, products, tools, mitigations, or weaknesses | Narrow subset |
| Entity dossiers | Read-only summary layouts for the six supported Workbench types; selected pivots and safe external links | Site profiles include overview provenance, relationships/evidence, articles, notes, timeline, graph, watch/mute, enrichment refresh, merge/convert, exports, and actions. These are absent | Summary cards, not profile parity |
| Detection engineering | Rule list, simple search, read-only rule content, copy-to-clipboard, source link | No faceted library endpoint, editor, validation, versioning, lifecycle, conversion, telemetry feasibility, ATT&CK coverage, import/export, AI generation, or bulk actions | Read-only viewer |
| Campaigns/reports | Campaign list and read-only campaign summary with actor/malware pivots | No create/edit/delete, membership, timeline, graph, detection gaps, notes, exports, report builder, templates, TLP, versions, or sharing | Read-only viewer |
| Settings/admin | None | The site documents account, appearance, reading, tags, AI, engine, feeds/export, Telegram, system, users, and logs | Not implemented |
| Automation/AI | None | Automation builder, dry runs/logs, global copilot, article AI, generation tasks, provider configuration, prompts, and cost tracking are absent | Not implemented |
| Sharing/export | Android shares the original article title and source URL through the platform share sheet | This is not the site's tokenized public sharing. TLP enforcement and documented exports are absent | Different behavior |
| Adaptive/offline | Phone-oriented single-column/full-screen layout with a modal drawer | No tablet/foldable/list-detail design, offline cache, background sync, push notifications, or explicit landscape experience | Early |

## API alignment

The currently used API surface generally matches `docs/api-reference.md`:

- `/api/auth/login`, `/refresh`, `/logout`, and `/me`
- `/api/entries`, `/priority-queue`, entry detail, read/unread, bulk state actions, and mark-all-read
- `/api/categories` and `/api/feeds`
- `/api/notes`
- list/detail operations for actors, malware, CVEs, campaigns, and detection rules
- list operation for TTPs
- `/api/search/unified`

Good contract choices already present:

- Star/bookmark state uses idempotent `bulk-action` values instead of relying on toggle endpoints.
- `Response<Unit>` mutations are checked for HTTP success.
- CVE detail requests use the public CVE identifier where required by the documented route.
- Unknown response fields do not break decoding.
- Search and dossier requests cancel superseded work.

Contract and UX limitations to keep visible:

1. The app models only fields it currently renders. It intentionally discards search facets, parsed filters, spelling suggestions, profile provenance, relationships, timelines, and most server metadata.
2. Search is fixed to the first 20 entries and up to 25 items per entity group. There is no search pagination.
3. Every Workbench list is fixed to the first 30 rows. Offset support exists in the API/repository signatures but the UI never requests another page.
4. The drawer requests only the first 100 feeds.
5. The Priority Queue endpoint does not accept feed/category scope. The app deliberately substitutes scoped unread entries when a feed or category is selected. This is a product choice, not true scoped priority ranking.
6. Story-thread queue records are flattened into synthetic `EntryItem` rows and open the first absorbed article, not the thread spine described by the docs.
7. `SearchEntityItem` expects `name`, while the documented unified-search note result uses `title`. Article-note results may therefore render a blank primary label even though their `entry_id` pivot works.
8. Dossier routing supports only `threat_actor`, `malware`, `cve`, `ttp`, `rule`, and `campaign`. Other unified-search types display an unsupported message.

## Verification performed during this review

Commands executed against the current tree:

```text
./gradlew :app:testDebugUnitTest :app:assembleDebug :app:lintDebug
./gradlew :app:assembleRelease
```

Results:

- Debug unit tests: **17 passed, 0 failed**.
- Debug APK: **build successful**.
- Release APK: **build successful**.
- Android lint: **0 errors, 22 warnings**.
- No live server login or emulator interaction was performed as part of this review.

The lint warnings are non-blocking and are mostly dependency update notices. Code warnings include two default-locale `String.format` calls, one Compose modifier-parameter ordering issue, deprecated clipboard/icon APIs, and the deprecated `ScrollableTabRow` overload.

`claude_changes.md` reports an earlier live-server emulator smoke test on 2026-09-22 covering startup, Priority Queue, filters, categories, summaries, reader, Workbench search, actor dossier, and unified search. Treat that as useful historical evidence, not a repeatable automated test.

## What is particularly well implemented

1. **The app is genuinely wired to the product.** Screens are not filled with local sample data.
2. **The recent auth-refresh fixes are thoughtful.** Rotating refresh tokens and concurrent 401s are handled as a single-flight operation, and transient refresh failures do not erase a valid session.
3. **Stale response protection is explicit.** Per-area jobs and cancellation reduce common filter/search race conditions.
4. **Entry mutations are safer than naive toggles.** UI updates optimistically, explicit state is sent where possible, and failures roll back or reload.
5. **Untrusted external links are constrained to HTTP(S).** Missing browser handlers no longer crash the app.
6. **Feed HTML is converted through a shared utility.** Script/style bodies are dropped, entities are decoded once, and plain text from the API is preserved as plain text.
7. **Session data is cleared from in-memory UI state on logout.** A second account should not inherit the first account's loaded content.
8. **The mobile information hierarchy is coherent.** Feed, Workbench, and Search are understandable top-level destinations, and the visual theme is internally consistent.

## Important gaps and risks

### High priority

1. **Clarify the intended product boundary.** The repository docs describe a far larger website. Without an Android scope document, future agents are likely to implement random parity slices or mislabel expected omissions as defects.
2. **HTTP instance URLs are accepted but likely unusable on modern Android.** `ServerUrl.normalize` explicitly accepts `http://`, while the manifest has no cleartext network-security opt-in. Android's default cleartext policy for this target SDK will block ordinary HTTP self-hosted/dev instances. Decide whether HTTP should be rejected or allowed only for explicit local hosts/build types.
3. **Authentication tokens remain unencrypted in DataStore.** Backups are disabled/excluded, which is good, but a compromised/rooted device or local extraction can still recover the tokens. Use Keystore-backed encryption if the threat model requires protection at rest.
4. **Automated coverage is too shallow for the amount of stateful behavior.** There are no tests for ViewModel races/rollback, repository endpoint selection, refresh concurrency, login/logout transitions, Compose behavior, accessibility, or navigation. The 17 passing tests exercise utility and serialization paths only.
5. **Search results do not fully model the documented response.** In addition to blank note titles, the UI ignores authoritative per-type counts, match kind, filters, facets, and pagination. Local result counts can look complete while the server payload is intentionally trimmed.

### Medium priority

1. Workbench, feeds, notes, and search have hard result caps with no visible indication that more records exist.
2. A story thread looks clickable as a single intelligence object but opens one article. This can surprise analysts and loses the documented spine/context.
3. The reader strips rich HTML into one text block. It does not render article links, headings, code blocks, lists with full fidelity, images, or media even though models/dependencies anticipate some of them.
4. The app is online-only. Network interruption removes most usefulness, and there is no cache for recently read intelligence.
5. Manual navigation has no general back stack. Entity-to-entity pivots replace the current dossier, and there are no deep links or state restoration for a specific article/entity.
6. Many failures are presented as raw exception messages or silently retain old/empty state. Drawer and notes-loading failures are especially quiet.
7. Reader font size is saveable only within the current Compose state; it is not a persisted user setting. The site documents broader reading preferences.
8. All visible strings are hardcoded in Kotlin except the application name, limiting localization and making consistent terminology harder.
9. The fixed phone layout does not use window-size classes or adaptive list-detail navigation for tablets, foldables, or desktop Android.
10. The release build is non-minified and has no checked-in signing setup. It builds, but the repository is not a complete store/distribution pipeline.

### Lower priority / cleanup

- Replace deprecated Compose APIs and locale-sensitive formatting.
- Remove or deliberately adopt the unused Coil and Navigation3 dependencies.
- Add package/module documentation; `com.example.intelfeed` does not match the shipping application ID namespace convention.
- Consider dependency injection before the single ViewModel/repository becomes much larger.
- Add a stable error-envelope parser so server messages and codes can be shown consistently.

## Recommended implementation sequence

Future LLMs should favor vertical, testable slices rather than copying entire web pages.

### Phase 1: define and stabilize the mobile core

1. Write an Android scope/acceptance document: companion vs parity, supported roles, supported server versions, and required offline behavior.
2. Resolve the HTTP/cleartext policy and token-at-rest policy.
3. Add repository/API contract tests with MockWebServer, refresh-concurrency tests, ViewModel state tests, and a minimal Compose navigation/login/feed/reader test suite.
4. Fix unified-search note modeling and add paging/limit affordances for search, Workbench, feeds, and notes.
5. Introduce consistent typed errors and retry/empty-state behavior.
6. Add adaptive layouts and state restoration before the navigation tree expands.

### Phase 2: finish the analyst's mobile reading loop

1. Render article content with safe rich formatting and media handling.
2. Add tags, correct-link/wrong-link actions, Priority Queue Why details, and real story-thread reading.
3. Add campaign/report handoff actions from an article.
4. Add public-share creation and Markdown export only if required on mobile; keep it distinct from Android's native source-link share.
5. Add the documented reading preferences and accessibility checks.

### Phase 3: make intelligence browsing coherent

1. Replace six one-off dossier branches with a reusable entity-profile framework.
2. Add Articles, Relationships/evidence, Notes, and Timeline tabs first.
3. Add watch/mute and common pivots.
4. Expand to vendors, products, tools, countries, mitigations, observables, and weaknesses based on user priority.
5. Add Workbench pagination, sorting, and filters before adding more decorative dashboard surfaces.

### Phase 4: choose higher-order parity deliberately

Dashboards, reports, rule editing, automation, AI/copilot, admin engine controls, and full settings are each substantial products. Add only the mobile-relevant ones after usage priorities are known. A browser handoff may be a better mobile experience for low-frequency admin workflows.

## Rules future agents should preserve

These are derived from the current code and `claude_changes.md`:

1. Validate every instance URL with `ServerUrl.normalize` before persisting or creating Retrofit.
2. Open server/feed URLs through `ExternalLinks.openInBrowser`; do not launch arbitrary URI schemes.
3. Keep token refresh single-flight. The backend rotates refresh tokens, so parallel refresh requests can invalidate a session.
4. Clear a session's loaded UI data on logout or rejected refresh.
5. Let coroutine cancellation escape repository wrappers; do not convert cancellation into a visible request error.
6. Keep a cancellable job or an equivalent latest-request mechanism for loads that can be superseded.
7. Check `Response<Unit>.isSuccessful` and surface mutation failures.
8. Prefer explicit idempotent state actions over toggle endpoints when local state may be stale.
9. Use `HtmlText` or a reviewed replacement for feed-supplied HTML. Do not return to ad-hoc tag-stripping regexes.
10. Use entity IDs for pivots when available; exact-match fallback by name/alias is safer than taking the first fuzzy result.
11. Preserve the current scoped-Priority-Queue substitution unless the product decision is revisited explicitly.
12. Do not describe the Android app as matching `docs/frontend.md`; that document is about the React SPA.

## Questions that should be answered before a major expansion

1. Is the Android goal a focused triage/reader companion or full web feature parity?
2. Must private LAN HTTP instances work, or is HTTPS mandatory?
3. Which roles must the app support: analyst only, or administrator workflows too?
4. Is offline reading/background sync a release requirement?
5. Should Android Share send the source URL, create an IntelFeed public share token, or offer both?
6. What should a feed/category-scoped Priority Queue mean if the backend cannot currently compute it?
7. Which three missing workflows have the highest mobile usage: tags, story threads, watchlists, campaigns, reports, notifications, or AI?
8. What server/API version is the minimum supported contract, and how should incompatibility be surfaced?

## Bottom line

The existing code is a solid API-backed foundation for an Android triage companion. It builds cleanly, its recent correctness/security fixes are sensible, and the main reading loop is useful. It should not yet be treated as a native equivalent of the IntelFeed website. The next best move is to establish an explicit Android scope, harden the existing vertical slice with integration/UI tests, and then complete the mobile analyst loop before attempting dashboards, admin tooling, or broad website parity.
