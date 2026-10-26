# Public read-only mode

An admin switch that lets anyone who can reach the instance open IntelFeed and look around without an account. Visitors see the real app with real data from the feeds an admin has chosen, but every control that changes something is gone, nothing they do costs AI time or makes the server fetch anything, and private work stays private. Signing in brings back the full app.

The switch is **off by default**. While it is off, every API route except the login, health, share-link, public RSS and indicator-feed routes answers 401 without a token.

## Turning it on

**Settings → Users → Security → Public read-only mode.** It sits next to Account Registration and Invite Code and is stored as the `public_read_only_enabled` system setting (env default `PUBLIC_READ_ONLY_ENABLED=false`). It never creates accounts and does not change registration or invite codes.

The login page learns whether the mode is on from the unauthenticated `GET /api/auth/registration-status`, which carries `public_read_only_enabled` alongside the registration flags.

**Then pick the feeds.** Every feed starts hidden from visitors, so turning the mode on publishes nothing by itself. An admin opens a feed's settings and checks **Visible to visitors** (Identity pane), stored as `feeds.visible_to_visitors`; the `update_feed` tool sets the same flag. Only an admin can change it; the API refuses it from anyone else. Manual Uploads never shows, whatever the flag says.

**Behind Cloudflare,** set `TRUSTED_CLIENT_IP_HEADER=CF-Connecting-IP` in the API's environment before turning the mode on. Without it every visitor arriving through one Cloudflare edge shares that edge's address and one rate-limit bucket, so one busy visitor locks out a region. The header is only trustworthy while the origin accepts Cloudflare's ranges alone (`scripts/ops/cf-origin-lockdown.sh`, see [operations.md](operations.md#rate-limiting)).

## What visitors see

There is no banner and no badge. The header's search box, ⌘K, Copilot, Settings and Logout give way to a single **Sign in** button. The login page carries a "Keep browsing read-only" link back, signing in lands on the page that was open (with the visitor's cached responses dropped), and logging out returns to the public view rather than a login wall. If an admin switches the mode off while a visitor has the app open, their next refused request sends them to the login page.

| Area | Visitors get | Removed for visitors |
| --- | --- | --- |
| Feed reader | Articles from visible feeds, filters, sort, view, text size, Find in article, Open original; read-aloud for articles that already have audio | Read/unread, star, bookmark, tags, notes, the AI tab and summaries, share, export, translate, bulk selection and actions, day summaries, Telegram images, swipe actions on phones |
| Sidebar | Articles in the last 24 hours, Last 24h / This Week / Priority Queue, the visible feeds by name, in the folders that hold them | Unread counts, Watched / Bookmarked / Starred, Automation, Notes, saved searches, add feed, ingest, new category, folder reordering, right-click menus |
| Entity lists | The tables and their relationship columns | Create, export, delete, merge, row selection, the TTP coverage and rule columns |
| Entity profiles (every type) | Overview, relationships, graph, timeline, linked articles, saved assessments (analyst-written or AI-drafted), sources | Detection and Detection Gaps tabs, editing (fields show values only), aliases, Watch, the ⋯ menu, Ask Copilot, AI analysis, notes, the next-actions rail, enrichment, the Wikipedia search, ransomware victims, relationship pin/reject/unlink, drawing new links in the graph |
| Entity pop-ups | The card, Profile, Copy | Search, Enrich, Wrong? |
| Intel panel | Extracted entities, the entity graph, glossary, referenced URLs | Extract, Gen Rules, campaigns, Navigator, detection rules, observables, insights, PIR matches |
| Story threads | Threads with at least one visible article, rebuilt from those articles | Marking a thread opened or read |
| Priority Queue | Ranking by the system score | Votes, personal ranking, the unread count |
| Dashboard | The built-in Triage, Intel and CVE tabs, locked and re-packed so removed widgets leave no gaps | New tabs, widgets, widget settings; the DE and Ransomware Ops tabs; morning briefing, saved-search hits, watchlist pulse, AI usage, feed health, worker queue, automation logs, campaign, Telegram, playbook-drift, ransomware, rules and observables widgets; the overview's detection and unread tiles; marking correlations read |
| Workbench | ATT&CK matrix (article heat only), the entity lists, glossary | Reports, Rules Library, Telemetry Sources, Threats, Campaigns, Observables, Ransomware, Requirements, Telegram Mentions, Watchlist; glossary add/edit/delete |
| Documentation | The pages and their images | The API reference links and the docs copilot |
| Keyboard | j/k, o, w, Escape, ? | Every shortcut that writes, opens a hidden panel, exports, searches, or opens the palette or copilot; the `?` help lists only what works |
| Theme and layout | Changes on the visitor's own screen | Anything saved to the server |

Search, settings, automation, campaigns, the threat board, rule pages and report builders show **Not available** with a Sign in button. Tag chips and the Top Tags widget are labels for a visitor, not links into Search. The API docs (`/docs`, `/redoc`, `/openapi.json`) stay login-only: `openapi.json` keeps the real `get_current_user` check.

**What stays visible regardless of feeds.** The reference catalogs (CVEs, TTPs, CWEs, mitigations, countries, sectors) are public whatever mentions them, and so is an entity with no article links at all (a catalog import). The `article_count`, `first_seen_at` and `last_seen_at` stored on each entity row count every feed; lists and profiles show those stored values. Counts computed per request (widgets, trends, the ATT&CK matrix, pivots, relationship and tag counts) cover visible articles only.

## How the server enforces it

**Routes opt in one by one.** A route a visitor may read takes `get_viewer` (`backend/app/core/security.py`) instead of `get_current_user`. With a token, `get_viewer` checks it exactly as `get_current_user` does. With no `Authorization` header it returns an `AnonymousViewer` while the switch is on and a 401 while it is off; a header that carries no usable token (`Bearer` alone, another scheme) is always a 401. The viewer has `id = None`, so every per-user filter (read state, stars, watches, My Stack, personal weights, tag visibility) matches no row. Every other route keeps its login check, so a new or overlooked route stays locked. A route about one article (`{entry_id}` in the path) takes `get_entry_viewer`, which also answers 404 to a visitor for an article they can't see.

**A second lock on writes.** `AnonymousWriteLockMiddleware` (`backend/app/core/public_access.py`) refuses every non-GET request that carries no bearer token, whatever the route says. It parses the header as FastAPI's `HTTPBearer` does, so a scheme in any case counts and an empty credential does not. The exceptions are login, register, refresh, logout, the share page's own calls, and a short reviewed list of read-only POSTs the visitor UI needs: `/api/entries/intel-counts`, `/api/entries/resolve-names`, `/api/intelligence/resolve-names`, `/api/glossary/detect` and `/api/autolink/scan` (bodies capped at 16 KB), and `/api/entity-relationships/signals/{entity_type}` (48 KB, for the entity tables' id lists). Each takes ids or text and returns matches. In the browser, `api/client.ts` drops a visitor's write before it is sent and shows one "This view is read-only." toast. Personal-state writes (read, star, bookmark, bulk actions, thread opened, playback progress, the Triage view) do nothing for a visitor.

**The data layer hides what no visitor gets** (`backend/app/services/public_view.py`). While the request's viewer is anonymous, a SQLAlchemy `do_orm_execute` listener adds criteria to every ORM select:

- **Feeds and articles.** `Feed` keeps only feeds with `visible_to_visitors` set (never Manual Uploads); `Entry` keeps only their articles, subqueries and relationship loads included. An article from a hidden feed is a 404 to a visitor, wherever it is linked from.
- **Article links.** Every article-link table (`EntryTTP`, `EntryCVE`, `EntryThreatActor` and the rest, and story-thread membership) keeps only rows about visible articles, so counts, trends, heatmaps and per-article lists that never load `Entry` still exclude hidden feeds.
- **Entities.** A threat actor, malware family, tool, vendor or product is hidden when every article mentioning it is in a hidden feed. One known only from a Manual Upload or a hidden feed never appears in a list, profile, relationship, event or autolink match.
- **Saved AI output.** No `AIResult` row loads. Entity assessments live on the entity row and stay visible.

The criteria apply to SQL the ORM emits, so a request's session must start empty: `session.get()` answers from the identity map without a query.

**Outside the ORM.** Raw SQL, the search index and caches don't pass through that listener, so each path a visitor reaches states the rule itself:

- **Story threads** (raw SQL) come back rebuilt from their visible members: threads with none are dropped, the title is the earliest visible article's, the stored summary and AI spine give way to a day-grouped spine over visible members (computed per request, never stored), and related threads are left out. The same applies to threads in the priority queue and on a profile's Active Story card.
- **The search index** (similar articles, glossary term pages and counts) is queried with a filter on the visible feeds.
- **Correlation events** keep an allowlist of types (actor, malware and technique correlations; CVE, exploit, KEV and trending events) about visible articles and visible entities. Campaign and requirement matches, rule and coverage events and feed health are left out: their text names private work.
- **The entity timeline** leaves out rule and campaign events and anything about a hidden article or entity.
- **Relationships** need both ends visible and keep only visible evidence; an edge drawn only from hidden articles is left out, and descriptions and creators are cleared.
- **Field provenance** leaves out claims drawn from hidden articles.
- **Caches** hold visitors apart: pivots, graphs and the ATT&CK matrix have visitor keys of their own, and the corpus total behind specificity scores is memoized per viewer kind.
- **Shared state** never comes from a visitor's view. The autolinker vocabulary and the 0–10 scale cutoffs, which a visitor's request can trigger a rebuild of, are built inside `instance_view()`, which lifts the filter for the build.

**Folders and feeds.** The category list keeps only folders holding a visible feed, and their parents, without their pipeline defaults. Feed responses keep the name and category only: the URL, errors, health, pause reasons, adapter config, title filters and analyst notes are cleared, and no unread counts are computed. The tag list keeps global tags on visible articles.

**Response scrubbing.** A visitor's JSON loses usernames and user ids (`username`, `analyst`, `created_by` and similar) and any key about rules, coverage, detection gaps, campaigns, observables, requirements and PIR matches, IOCs or translations. It also loses note, comment and AI-result counts and the `unread` figure. A hidden list comes back empty and a hidden count or flag as zero or false, so pages keep their shape; a hidden object or string is removed. Any object whose `type`, `entity_type`, `event_type`, `source_type`, `target_type` or related-entity type is a campaign, observable or rule is removed from its list, along with graph edges left pointing at it. Article bylines (`author`) are untouched.

**Reads stay reads.** Read-aloud serves audio that already exists (`GET /api/tts/existing`, then the file) and never synthesizes for a visitor, and a visitor's playback skips the last-played stamp. Audio files are addressed by a hash of their text, so a visitor can fetch one only by already holding its key. The image proxy serves a visitor, from its cache or by fetching, only an image that a visible article shows (an `<img>` source or its lead image); otherwise the browser loads the original URL directly. No visitor route starts Celery work.

**Dashboards** come from `DEFAULT_BOARDS` (`backend/app/dashboard_defaults.py`), trimmed to Triage, Intel and CVE and to the widget types listed above, re-packed so the remaining widgets fill the rows, with stable synthetic ids.

## Limits and caching

Anonymous `/api/*` traffic is rate-limited per client IP, over a minute and over an hour, so a visitor can click around quickly but nobody can copy the site wholesale:

| What | Per minute | Per hour |
| --- | --- | --- |
| Opening an article (`GET /api/entries/{id}`, the only route that returns full article text) | 20 | 150 |
| Graph, pivot, timeline, analytics, map, calendar, priority-queue, relationship and autolink-scan routes | 20 | 200 |
| Everything else | 180 | 1,500 |

Opening one article in the reader is about 15 requests (the article, its entity lists, glossary terms, counts) but only one of them is the article itself, so the article budget is what stops a scraper, and the general budget only has to fit a person's pace. The windows are checked and recorded in one atomic Redis step, so parallel requests cannot overrun them. A refused request is not counted. The browser shows one "Too many requests" toast per burst, and the 429's `Retry-After` says how long to wait. Signed-in traffic is not limited, and TAXII and the published indicator files keep their own per-minute budget (see [operations.md](operations.md#rate-limiting)).

Every API response carries `Cache-Control: private, no-store` (routes that serve the same bytes to everyone, like proxied images and audio files, set their own), plus `X-Robots-Tag: noindex, nofollow`; refusals (401, 413, 429) carry them too. The SPA carries a `noindex` meta tag and serves a disallow-all `robots.txt`.

## Keeping it safe as the API grows

`backend/tests/test_public_read_only.py` lists every visitor route and every route that needs no login. It fails when a route takes `get_viewer` or skips auth without being listed, and when a visitor route about one article skips `get_entry_viewer`, so each one is a deliberate decision. It walks every visitor route with the switch off (all 401) and on (no 401/403/5xx, no database writes, no Celery dispatch).

The **canary test** seeds one article in a hidden feed, marked everywhere it can be (title, URL, text, an actor known only from it, a story thread and beat built from it, a correlation event, a relationship, a claim quote), walks every visitor route signed in so caches fill, then walks them as a visitor and fails if any response carries a marker or a hidden id. Further tests cover what the walk can't reach: the image proxy, tags, autolink scan and vocabulary, ATT&CK counts and cache, rate-limit windows under parallel requests, and malformed authorization headers.

To open another route to visitors: switch it to `get_viewer` (or `get_entry_viewer` for an `{entry_id}` route), make sure it reads nothing personal and starts no work for an anonymous viewer, check that any raw SQL, search or cache it uses applies the visitor rule, add it to `VISITOR_ROUTES` in the test, and for a read-only POST add it to `ANONYMOUS_READ_POSTS` (or `ANONYMOUS_READ_POST_TEMPLATES`) and to `VISITOR_READ_POSTS` in `frontend/src/api/client.ts`. The canary walk then covers it.

## Live updates

Visitors do not get the live-updates stream (it needs a per-user ticket). Lists refresh on their normal query intervals.
