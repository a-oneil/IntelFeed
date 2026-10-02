# IntelFeed live-site feature inventory and Android navigation guide

**Observed:** 2026-09-22 at `https://intelfeed.cc` in an authenticated, non-admin **User** account.  
**Purpose:** Product handoff for LLMs building the native phone app. This records the live website's visible workflows, especially reading and navigation, and identifies mobile additions without changing the Android application.  
**Method:** I navigated the website and opened read-only pages, menus, forms, an existing entity profile, and an article returned by `is:read`. I did **not** save, subscribe, generate AI output, mark an unread article read, change settings, or test write actions. A visible control proves a capability is offered, not that its submission succeeds. Dynamic counts, dashboard boards, and feed names are account-specific examples, not product constants.

## How to read this file

- **Observed** means directly visible in the live site. **Opened** means I navigated into that screen or panel. **Offered** means the control exists but its final action was not executed. **Docs** means described in repository documentation but not exercised live.
- The earlier [Android implementation review](ANDROID_APP_IMPLEMENTATION_REVIEW.md) is the code-level comparison. This file is the website-side inventory and a mobile UX checklist.
- Source documents most relevant to the reading flow: [reading and triage](docs/guide/reading-and-triage.md), [priority queue](docs/guide/priority-queue.md), [feeds](docs/guide/feeds.md), [searching](docs/guide/searching.md), and [query language](docs/query-language.md). Documentation is a design/behavior reference; where it differs from the live UI, verify against the server version before coding.

## The core mental model

IntelFeed has two top-level modes, **Reading** and **Workbench**. Reading is for moving through articles from quick views, categories, individual feeds, priority ranking, and saved searches. Workbench is for structured intelligence: entities, threats, detections, reports, requirements, dashboards, and related analysis. Search and Copilot are globally accessible.

The desktop reading interface is a three-part workspace: source navigation on the left, an entry list in the middle, and an article reader at the right. The official guide says these panes stack on a narrow screen: a sliding source drawer, list, and full-screen reader. The native Android app need not copy the desktop layout, but it should preserve the user's path and context: **source or queue → article list → article → entity/profile → back to the same article and list position**.

## Reading: navigation and list

### Source navigation — observed

| Surface | What the live UI offered | Phone implication |
|---|---|---|
| Reading / Workbench switch | Changes the navigation family. | Keep the distinction visible without burying Workbench in feed filters. |
| Unread Articles | Prominent total with a since-time and new-count indicator. | A recognizable inbox entry point and accurate unread badge. |
| Quick views | Last 24h, This Week, Watched, Bookmarked, Starred, Priority Queue. | Make these one-tap destinations; they are not all synonyms for `is:unread`. |
| Saved Searches | Named saved queries with unread/total-style counts; controls to create an AI report or delete. | Saved searches are navigational destinations, not merely search history. Report creation can be deferred. |
| Feed tree | Categories with unread counts and disclosure arrows; expanding shows individual feeds with their own counts. Selecting a category or a feed filters the entry list. | Support full nested navigation, counts, selected-state context, and a path back to All Items. |
| Feed discovery controls | Search feeds, expand/collapse categories, new category, ingest URL/PDF, add feed. | Search is useful with many feeds; authoring/import may be a later mobile feature. |
| Muted feeds | Separate collapsed group showing a feed count. | Do not silently discard muted sources from management/navigation. |

In the expanded live category, individual feeds displayed curation labels such as **Selective — security-relevant articles only** or **Known entities only — match against existing database**. Some feeds displayed an alert `!`. A selected single-feed view showed its type, unread count, last fetch age, and polling cadence. These are useful source-health/context details, not article fields.

### Entry list — observed

The list groups entries by publication day. A day header can collapse, mark that day read, and offer AI summarization. Existing day summaries can be expanded, read aloud, or regenerated; the guide warns that regeneration consumes shared AI tokens. The header also exposes topical chips for the day's actors, malware, ATT&CK techniques, CVEs/KEV, products and sectors; chips appear to be navigational filters/pivots. Entry cards/rows show source, age, title, preview, author/read time, and intelligence cues such as PIR matches, extracted entities/CVEs/TTPs, KEV or detection opportunities, correlation/radar signals, and near-duplicate **Echo** status. Podcasts may show a duration rather than article read time.

List toolbar controls observed: mark every entry in the current view read (with options), collapse all days, **Hide Read**, **Auto-read**, sort, and view mode. The view-mode choices opened in the browser were **Compact, Expanded, Magazine, Table**. Entries have selection checkboxes. The official reading guide describes bulk star, tag, mark-read, and add-to-campaign actions after selection; I did not run a bulk action. The desktop UI advertises `j`/`k` navigation, Enter to read, and `?` for shortcuts.

Important navigation distinction: clicking a **category** filters across its feeds, while opening its disclosure arrow reveals the **individual feed** list. Selecting one feed then shows just that feed's articles and its feed metadata. The phone drawer should make those two actions unambiguous, e.g. separate row selection and expansion affordances.

### Priority Queue — observed link, docs behavior

The live sidebar shows a Priority Queue with its own count. The [priority guide](docs/guide/priority-queue.md) describes a ranked inbox using novelty, coverage, severity, user-interest/PIR, and detection-content signals. It also describes a per-article **Why** explanation, feedback thumbs, watch/mute steering, and story rows grouping several outlets. I did not verify those details in a loaded live queue during this pass; treat them as **Docs**, not live-tested behavior. The existing Android app already calls the priority endpoint but does not show the Why breakdown or a true story-spine reader (see the review).

## Article reader — opened on an already-read article

Opening a result from `is:read` displayed the article in a reader pane without removing it from the read set; the toolbar showed **Unread** (the action that would reverse the state), along with **Star**, **Bookmark**, **Intel**, **AI**, **Notes**, **Tags**, **Ask Copilot**, typography settings, and **More**. The reader also offered previous/next entry controls, source/feed actions, pipeline-processing status, source/date/author/read-time metadata, PIR matches, a rich article body with headings, links and an image, and **More like this**. The content was not just a plain-text paragraph.

The [reading guide](docs/guide/reading-and-triage.md) additionally describes, but I did not execute, opening the original source, Markdown export, adding to campaign, read-aloud, find-in-article, linked entity pivots, and **Wrong?** corrections on incorrectly linked entity terms. It documents side panels (`n` Notes, `w` Intel, `a` AI), and `s`/`b`/`m`/`t`/`e` shortcuts for star/bookmark/read/tag/export. Keep these marked as documented until the exact live menu/panel actions are verified. A correction is a real change to entity linking, so a mobile design should not make the broad correction scopes easy to trigger accidentally. The final attempt to inspect those submenus was interrupted when the site rendered a blank page after a refresh; no conclusion about those actions' availability should be drawn from that transient state.

Reader navigation is the highest-value mobile gap: an analyst needs to open an article, inspect its extracted entities, pivot to a dossier, then back out to the **same article**, same feed/query, and same list position. The native app currently has a basic full-screen reader and some dossier pivots, but not the richer reader panels or a general back stack.

## Search and cross-navigation — opened

The global search field supports **Everything**, **Workbench**, and **Feeds** scope. A live query showed direct name/alias matches separately from entities merely **mentioned in text**, plus article results. The search page exposed entity-type facets, match type, publish windows, unread/starred/bookmarked/has-notes state, feed, content type, and tags. It provided parsed query chips, a visual query builder, syntax help, save, relevance/view controls, and a side filter rail. A query containing `is:read` returned already-read articles and enabled the safe reader inspection above. Search may take time to replace transient skeleton/loading results; do not assume an empty intermediate frame is a true empty set.

For navigation design, search results must preserve both the query and the distinction between a direct entity hit, a mention, and an article. The docs say the filter rail becomes a sheet and the reader full-screen on mobile. The current Android search UI uses the endpoint but omits most of these facets, groupings, and pagination.

## Feed intake and management — forms opened, no subscription submitted

The live **Add Feed** dialog had **six** tabs: Feed URL, GitHub Repo, Web Scraper, Bluesky, Telegram, and OPML. This differs from [the local feed guide](docs/guide/feeds.md), which says five tabs and places OPML import in Settings. Use the live six-tab inventory for this server, but verify the backend/API before implementing.

| Tab | Fields/capabilities visible live |
|---|---|
| Feed URL | URL or website URL entry and Discover action. |
| GitHub Repo | Repository and branch, recursive file patterns, include-file-content checkbox, category, poll interval; an offered one-click setup for 19 preconfigured detection-rule repositories. |
| Web Scraper | Blog index URL, optional CSS link selector and URL pattern, max articles, follow pagination, category, poll interval. |
| Bluesky | Mode, handle, include reposts, optional authentication/rate-limit section, optional attribution, category, poll interval. |
| Telegram | Channel handle/link or discover from connected account; media download, forwarded attribution, first-fetch max age, optional auto-attribution, category, poll interval. The form warns that a server-side Telegram account must already be authorized. |
| OPML | Drop or choose an OPML file for bulk import. |

The sidebar also offered **Ingest a URL or PDF** and **New category**; I did not submit either. Docs describe feed settings (category, polling, retention, mute, source assessment) and health views, but those editing surfaces were not opened. Feed add/edit is admin-only on many instances even though this account saw add controls; permissions should be checked server-side, not inferred from a button.

## Workbench and other site areas — observed/partially opened

| Area | Live UI inventory |
|---|---|
| Dashboard | Multiple boards with shared time range, layout lock/unlock, templates, add widget, and board creation. Observed boards spanned Triage, Intel, CVE, detection engineering, and Ransomware Ops. Widgets included briefing/triage, correlation, saved-search and watchlist pulses, AI usage, feed health, actor/campaign trends, CVE severity/KEV deadlines, rule and TTP coverage, and ransomware targeting. These board names are account configuration. |
| Threats | All / Actors / Malware / Vulnerabilities tabs, 7/14/30-day windows, Open/Handled views; UI describes ranking by story rather than outlet. |
| Detection | ATT&CK Matrix for Enterprise/Mobile/ICS with heat/coverage modes; Rules Library with all/new/recent/my-drafts views, search, telemetry/grouping options and offered import/export/generate/new-rule actions; Telemetry Sources searchable checklist. Some controls were disabled in this account's current state. |
| Entities | Navigation entries for Campaigns, Countries, CVEs, Malware, Mitigations, Observables, Products, Threat Actors, Tools, TTPs, Vendors, Weaknesses. Entity tables can have sort/filter/search, custom columns, row actions, and exports. CVE and Observable tables were sampled. |
| Entity profile | A CVE profile was opened. It had Overview, Weaknesses, Relationships, Detection tabs; severity/provenance, timeline, AI assessment, source reading, notes/activity, CVSS/KEV snapshot, pivots, claims-vs-co-mentions and relationship graph, and offered watch/Copilot/hunt-package actions. Not every action was enabled for the sampled CVE. |
| Reports | New Report / AI Report and templates such as Exposure, Landscape, Flash Alert, Actor Profile/Campaign Tracker, and Detection Report; report list with status/version/filter/sort. |
| Requirements | New Requirement and filters by priority, status, category, with match/last-match columns. |
| Watchlist | Entities, type, mode, and boost; watch/mute filter. |
| Ransomware | Leak Watch and Landscape, search and filters for victims/groups/domains. |
| Telegram Mentions | Discovered channels with offered subscribe/dismiss actions and subscribed/dismissed filters. |
| Glossary | Term list, aliases, category/maturity/article filters, Add Term. |
| Notes | Searchable note workspace, source/entity-type filters, New Note, Markdown export; note content renders Markdown and entity links. Article-specific Notes control also exists in reader. |
| Automation | Rules list with enabled state, templates/import/export/new. The unsaved new-rule editor exposed name/description/labels, trigger, per-entry execution, max entries, and Flow/Form editing with conditions, branches, and actions. |
| Copilot | Global side panel with new/history, ambient context, suggested prompts, and input. I did not send a prompt. |
| Settings | User-visible Account, Appearance, Reading preferences, Tags, and Claude Code Skill. Reading preferences include default layout/page size/sort, link and mark-read behavior, density/preview, typography, and read-aloud voice. Admin sections were not visible under this role. |

This is an inventory, not a recommendation to port every web workflow. The Android code review identifies which of these are already represented and which are absent.

## Phone-app feature checklist, ordered by the reading journey

### P0 — make the existing triage loop navigable and trustworthy

- [ ] Preserve source context and list position across **queue/view → list → reader → dossier → back**. Support Android back and deep links to a specific article/entity.
- [ ] Make All Items, Unread, Priority Queue, Last 24h, This Week, Watched, Bookmarked, Starred, saved searches, categories, and individual feeds distinct, reachable destinations with accurate counts.
- [ ] Make category selection versus category expansion obvious; add feed search and full feed-tree pagination/loading rather than the current first-100-feed ceiling.
- [ ] Keep read/unread, star, and bookmark state synchronized and reversible. Explain whether opening an article auto-marks it read; expose that preference or provide clear feedback.
- [ ] Add reader previous/next navigation that follows the current list or search ordering, with a reliable return to the same scroll position.
- [ ] Show loading/error/empty states and the selected filter or feed name, so a blank result is not confused with a failed request.

### P1 — complete the mobile reading and triage experience

- [ ] Render safe rich article structure (headings, lists, links, code, images/media where supported) rather than flattening all content to plain text.
- [ ] Show day groups, topical chips, AI day summaries with token-cost awareness, and meaningful article cues (PIR, CVE/KEV, actor/malware/TTP, correlation, Echo, detection opportunity) without crowding cards.
- [ ] Add tags and an article Intel panel with typed linked entities and direct dossier pivots; preserve a way back to the article.
- [ ] Add the Priority Queue's Why/signal explanation and real multi-outlet story rows/spine reader; avoid opening only the first absorbed article.
- [ ] Add search scope, facets, direct-vs-mention grouping, parsed filters, saved searches, and paging beyond the current first page.
- [ ] Add reader affordances according to actual demand: article notes, find-in-article, source link, read aloud, Markdown export, and campaign/report handoff. Treat AI and Copilot as separate, potentially costly workflows.
- [ ] Add watch/mute on entities and connect Watched view/priority ranking to those choices.

### P2 — selective Workbench expansion

- [ ] Build consistent entity profiles with Overview, Relationships/evidence, Articles, Notes, and Timeline before copying every web table.
- [ ] Expand entity navigation based on mobile usage (observables, vendors/products, tools, countries, weaknesses/mitigations), with table pagination/filtering.
- [ ] Keep detection rules, campaigns, requirements, and reports useful for mobile *review and handoff* before attempting full authoring or complex builders.
- [ ] Decide explicitly whether dashboard customization, automation authoring, feed intake, admin settings, and AI generation belong in native mobile or should open the website.

## Implementation cautions for future LLMs

1. **Do not equate visible with tested.** No live write/subscription/generation action was executed in this inventory.
2. **Prefer a focused mobile analyst workflow over blanket site parity.** The existing app already has auth, basic feed/reader/search, and six read-only Workbench types; extend those coherently before adding unrelated pages.
3. **Keep server permissions and costs visible.** AI generation, day-summary regeneration, feed subscription, note sharing, and admin tasks may have role, token, or instance-wide effects.
4. **Treat the web guide's mobile notes as UX intent, not proof of native Android behavior.** The present Android app is separate Kotlin/Compose code.
5. **Verify live/API drift.** The six-tab Add Feed dialog is a concrete example where site UI and local guide differ. Dynamic search counts and personalized dashboards should not be hardcoded.
6. **Do not use this document to infer bugs from transient loading.** The live search and route changes briefly displayed stale/skeleton content; I did not run repeatable acceptance tests.
