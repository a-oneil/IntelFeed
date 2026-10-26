# Public read-only mode

An admin switch that lets anyone who can reach the instance open IntelFeed and look around without an account. Visitors see the real app with real data, but every control that changes something is gone, nothing they do costs AI time or makes the server fetch anything, and private work stays private. Signing in brings back the full app.

The switch is **off by default**. With it off, every API route except the existing login, health, share-link, public RSS and indicator-feed routes answers 401 without a token, exactly as before.

## Turning it on

**Settings → Users → Security → Public read-only mode.** It sits next to Account Registration and Invite Code and is stored as the `public_read_only_enabled` system setting (env default `PUBLIC_READ_ONLY_ENABLED=false`). It never creates accounts and does not change registration or invite codes.

The login page learns whether the mode is on from the unauthenticated `GET /api/auth/registration-status`, which carries `public_read_only_enabled` alongside the registration flags.

**Then pick the feeds.** Every feed starts hidden from visitors, so turning the mode on publishes nothing by itself. An admin opens a feed's settings and checks **Visible to visitors** (Identity pane), stored as `feeds.visible_to_visitors`. Only an admin can change it; the API refuses it from anyone else. Manual Uploads never shows, whatever the flag says.

Behind Cloudflare, set `TRUSTED_CLIENT_IP_HEADER=CF-Connecting-IP` in the API's environment, or every visitor shares the edge's address and one rate-limit bucket (see [operations.md](operations.md#rate-limiting)).

## What visitors see

There is no banner and no badge. The header's search box, ⌘K, Copilot, Settings and Logout give way to a single **Sign in** button. The login page carries a "Keep browsing read-only" link back, signing in lands on the page that was open, and logging out returns to the public view rather than a login wall.

| Area | Visitors get | Removed for visitors |
| --- | --- | --- |
| Feed reader | Every article, filters, sort, view, text size, Find in article, Open original; read-aloud for articles that already have audio | Read/unread, star, bookmark, tags, notes, the AI tab and summaries, share, export, translate, bulk actions, day summaries, Telegram images |
| Sidebar | Articles in the last 24 hours, Last 24h / This Week / Priority Queue, the feeds marked visible, by name, in the folders that hold them | Unread counts, Watched / Bookmarked / Starred, Automation, Notes, saved searches, add feed, ingest, new category, right-click menus |
| Entity profiles (every type) | Overview, relationships, graph, timeline, linked articles, saved assessments (analyst-written or AI-drafted), sources | Detection and Detection Gaps tabs, editing, aliases, Watch, the ⋯ menu, Ask Copilot, AI analysis, notes, the next-actions rail, enrichment, the Wikipedia search, ransomware victims, relationship pin/reject/unlink |
| Entity pop-ups | The card, Profile, Copy | Search, Enrich, Wrong? |
| Intel panel | Extracted entities, the entity graph, glossary, referenced URLs | Extract, Gen Rules, campaigns, Navigator, detection rules, observables, insights, PIR matches |
| Story threads | Browsing | Marking a thread opened |
| Priority Queue | Ranking by the system score | Votes, personal ranking, the unread count |
| Dashboard | The built-in Triage, Intel and CVE tabs, locked | New tabs, widgets, widget settings; the DE and Ransomware Ops tabs; morning briefing, saved-search hits, watchlist pulse, AI usage, feed health, worker queue, automation logs, campaign, Telegram, playbook-drift, ransomware, rules and observables widgets; the overview's detection and unread tiles |
| Workbench | ATT&CK matrix, the entity lists, glossary | Reports, Rules Library, Telemetry Sources, Threats, Campaigns, Observables, Ransomware, Requirements, Telegram Mentions, Watchlist |
| Documentation | The pages | The API reference links and the docs copilot |
| Theme and layout | Changes on the visitor's own screen | Anything saved to the server |

Search, settings, automation, campaigns, the threat board, rule pages and report builders show **Not available** with a Sign in button. The API docs (`/docs`, `/redoc`, `/openapi.json`) stay login-only: `openapi.json` keeps the real `get_current_user` check.

## How the server enforces it

**Routes opt in one by one.** A route a visitor may read takes `get_viewer` (`backend/app/core/security.py`) instead of `get_current_user`. With a token, `get_viewer` checks it exactly as `get_current_user` does. With none, it returns an `AnonymousViewer` while the switch is on, and the same 401 as before while it is off. The viewer has `id = None`, so every per-user filter (read state, stars, watches, My Stack, personal weights, tag visibility) matches no row. Every other route keeps its login check, so a new or overlooked route stays locked.

**A second lock on writes.** `AnonymousWriteLockMiddleware` (`backend/app/core/public_access.py`) refuses every non-GET request without a bearer token, whatever the route says. The exceptions are login, register, refresh, logout, the share page's own calls, and a short reviewed list of read-only POSTs the visitor UI needs: `/api/entries/intel-counts`, `/api/entries/resolve-names`, `/api/intelligence/resolve-names`, `/api/glossary/detect` and `/api/autolink/scan`. Each of these takes ids or text and returns matches, and their bodies are capped at 16 KB. In the browser, `api/client.ts` drops a visitor's write before it is sent and shows one "This view is read-only." toast. Personal-state writes (read, star, bookmark, thread opened, playback progress) do nothing for a visitor.

**The data layer hides what no visitor gets** (`backend/app/services/public_view.py`):

- **Feeds not marked visible, and Manual Uploads.** While the request's viewer is anonymous, every ORM select of `Feed` or `Entry` keeps only feeds with `visible_to_visitors` set (never the Manual Uploads feed) and their entries, subqueries and relationship loads included. An article from a hidden feed is a 404 to a visitor, wherever it is linked from. Story-thread members, which come from raw SQL, are filtered against the same rule. The filter runs on queries the ORM emits, so a request's session must start empty: `session.get()` answers from the identity map without a query.
- **Saved AI output.** No `AIResult` row loads during a visitor's request. Entity assessments live on the entity row and stay visible.
- **Folders.** The category list keeps only folders holding a visible feed, and their parents, without their pipeline defaults.
- **Feed internals.** Feed responses keep the name and category only. The URL, errors, health, pause reasons, adapter config, title filters and analyst notes are cleared.
- **Response scrubbing.** A visitor's JSON loses usernames (`username`, `analyst` and similar) and any key about rules, coverage, detection gaps, campaigns, observables, requirements and PIR matches, IOCs or translations. It also loses note, comment and AI-result counts and the `unread` figure. A hidden list comes back empty and a hidden count or flag as zero or false, so pages keep their shape; a hidden object or string is removed. Any object whose `type` is a campaign, observable or rule is removed from its list, along with graph edges left pointing at it. Article bylines (`author`) are untouched.

**Reads stay reads.** Read-aloud serves audio that already exists (`GET /api/tts/existing`, then the file) and never synthesizes for a visitor, and a visitor's playback skips the last-played stamp. The image proxy fetches for a visitor only an image a stored article shows, or one already cached. Otherwise the browser falls back to loading the original URL directly. No visitor route starts Celery work or makes an outbound request.

**Dashboards** come from `DEFAULT_BOARDS` (`backend/app/dashboard_defaults.py`), trimmed to Triage, Intel and CVE and to the widget types listed above, with stable synthetic ids.

## Limits and caching

Anonymous `/api/*` traffic is rate-limited per client IP, over a minute and over an hour, so a visitor can click around quickly but nobody can copy the site wholesale:

| What | Per minute | Per hour |
| --- | --- | --- |
| Opening an article (`GET /api/entries/{id}`, the only route that returns full article text) | 20 | 150 |
| Graph, pivot, timeline, analytics, map, calendar, priority-queue, relationship and autolink-scan routes | 20 | 200 |
| Everything else | 180 | 1,500 |

Opening one article in the reader is about 15 requests (the article, its entity lists, glossary terms, counts) but only one of them is the article itself, so the article budget is what stops a scraper, and the general budget only has to fit a person's pace. A refused request is not counted. The browser shows one "Too many requests" toast per burst, and the 429's `Retry-After` says how long to wait. Signed-in traffic is not limited, and TAXII and the published indicator files keep their own per-minute budget (see [operations.md](operations.md#rate-limiting)).

Every API response carries `Cache-Control: private, no-store` (routes that serve the same bytes to everyone, like proxied images and audio files, set their own), plus `X-Robots-Tag: noindex, nofollow`. The SPA carries a `noindex` meta tag and serves a disallow-all `robots.txt`.

## Keeping it safe as the API grows

`backend/tests/test_public_read_only.py` lists every visitor route and every route that needs no login. It fails when a route takes `get_viewer` or skips auth without being listed, so each one is a deliberate decision. It walks every visitor route with the switch off (all 401) and on (no 401/403/5xx, no database writes, no Celery dispatch). It also spot-checks the locked areas, refused writes, feed and Manual Uploads hiding, dashboards, headers, the image proxy and the scrubber.

To open another route to visitors: switch it to `get_viewer`, make sure it reads nothing personal and starts no work for an anonymous viewer, add it to `VISITOR_ROUTES` in the test, and for a read-only POST add it to `ANONYMOUS_READ_POSTS` and to `VISITOR_READ_POSTS` in `frontend/src/api/client.ts`.

## Live updates

Visitors do not get the live-updates stream (it needs a per-user ticket). Lists refresh on their normal query intervals.
