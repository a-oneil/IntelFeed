# Public read-only mode

An admin switch that lets anyone who can reach the instance browse without
signing in. Visitors see real data from admin-picked
feeds; nothing they do changes data, uses AI or makes the server fetch
anything, and private work stays hidden.

**Off by default**: every API route then answers 401 without a token, except login, health, share links, public RSS and the
indicator feeds.

## Turning it on

**Settings → Users → Security → Public read-only mode**, next to Account
Registration and Invite Code. System setting `public_read_only_enabled` (env
default `PUBLIC_READ_ONLY_ENABLED=false`); it doesn't touch accounts,
registration or invite codes. The login page reads it from the no-login
`GET /api/auth/registration-status`, which returns `public_read_only_enabled`.

**Then pick the feeds.** Every feed starts hidden. An admin ticks **Visible to visitors** in a feed's Readers pane
(`feeds.visible_to_visitors`, admin-only; the `update_feed` tool sets it
too). Manual Uploads is never shown.

**Behind Cloudflare,** set `TRUSTED_CLIENT_IP_HEADER=CF-Connecting-IP` in the
API's environment first. Otherwise visitors through one Cloudflare edge share
one rate-limit bucket, and one busy visitor can lock out a region. Only trust that header if the server accepts traffic from Cloudflare
alone (`scripts/ops/cf-origin-lockdown.sh`, see
[operations.md](operations.md#rate-limiting)).

## What visitors see

The header's search box, ⌘K, Copilot, Settings and Logout become
one **Sign in** button. The login page has a "Keep browsing read-only" link.
Sign-in returns you to your page; logout to the public view. If the mode is turned off mid-visit, the next
request goes to login.

| Area | Visitors get | Removed for visitors |
| --- | --- | --- |
| Feed reader | Visible-feed articles, filters, sort, view, text size, Find in article, Open original; read-aloud where audio exists | Read/unread, star, bookmark, tags, notes, AI tab and summaries, share, export, translate, bulk actions, day summaries, Telegram images, phone swipe actions |
| Sidebar | Last-24-hours count, Last 24h / This Week / Priority Queue, visible feeds by name in their folders | Unread counts, Watched / Bookmarked / Starred, Automation, Notes, saved searches, add feed, ingest, new category, folder reordering, right-click menus |
| Entity lists | Tables and relationship columns | Create, export, delete, merge, row selection, TTP coverage and rule columns |
| Entity profiles (every type) | Overview, relationships, graph, timeline, linked articles, saved assessments (analyst or AI), sources | Detection and Detection Gaps tabs, editing (values only), aliases, Watch, ⋯ menu, Ask Copilot, AI analysis, notes, next-actions rail, enrichment, Wikipedia search, ransomware victims, relationship pin/reject/unlink, drawing graph links |
| Entity pop-ups | Card, Profile, Copy | Search, Enrich, Wrong? |
| Intel panel | Extracted entities, entity graph, glossary, referenced URLs | Extract, Gen Rules, campaigns, Navigator, detection rules, observables, insights, PIR matches |
| Story threads | Threads with a visible article, rebuilt from visible articles | Marking opened or read |
| Priority Queue | System-score ranking | Votes, personal ranking, unread count |
| Dashboard | Built-in Triage, Intel and CVE tabs, locked, remaining widgets packed without gaps | New tabs, widgets, widget settings; DE and Ransomware Ops tabs; morning briefing, saved-search hits, watchlist pulse, AI usage, feed health, worker queue, automation logs, campaign, Telegram, playbook-drift, ransomware, rules and observables widgets; overview detection and unread tiles; marking correlations read |
| Workbench | ATT&CK matrix (article heat only), entity lists, glossary | Reports, Rules Library, Telemetry Sources, Threats, Campaigns, Observables, Ransomware, Requirements, Telegram Mentions, Watchlist; glossary add/edit/delete |
| Documentation | Pages and images | API reference links, docs copilot |
| Keyboard | j/k, o, w, Escape, ? | Shortcuts that write, open a hidden panel, export, search, or open the palette or copilot; `?` help lists only what works |
| Theme and layout | Local changes | Anything saved to the server |

Search, settings, automation, campaigns, the threat board, rule pages and
report builders show **Not available** and Sign in. Tag chips and
the Top Tags widget are plain labels, not Search links. The API docs (`/docs`,
`/redoc`, `/openapi.json`) still need a login.

**Visible regardless of feeds:** the reference catalogs (CVEs, TTPs, CWEs,
mitigations, countries, sectors), whatever mentions them, and any entity with
no article links (such as one from a catalog import).

**Counts.** Stored `article_count`, `first_seen_at` and `last_seen_at` (shown
in lists and profiles) span all feeds. Per-request counts
(widgets, trends, the ATT&CK matrix, pivots, relationship and tag counts)
cover visible articles only. Small figures still counting every feed: the
CWE page's top vendors, a sector's count of actors targeting it, and a
signal explanation's "independent outlets" figure.

## How the server enforces it

**Routes opt in one by one.** Visitor-readable routes use `get_viewer`
(`backend/app/core/security.py`) instead of `get_current_user`:

- With a token, it acts exactly like `get_current_user`.
- With no `Authorization` header, it returns an `AnonymousViewer` while the
  switch is on, a 401 while off.
- A header with no usable token (`Bearer` alone, another scheme) is a 401.

The visitor has `id = None`, so per-user filters (read state, stars, watches,
My Stack, personal weights, tag visibility) match nothing. Other routes keep
their login check, so new or forgotten routes stay locked. A route about
one article (`{entry_id}` in the path) uses `get_entry_viewer`, which also
404s an article the visitor can't see.

**A second lock on writes.** `AnonymousWriteLockMiddleware`
(`backend/app/core/public_access.py`) refuses every non-GET request without a
bearer token (parsed as FastAPI's `HTTPBearer` does), whatever the route says.
Exceptions:

- login, register, refresh and logout;
- the share page's own calls;
- reviewed read-only POSTs that take ids or text and store nothing: `/api/entries/intel-counts`,
  `/api/entries/resolve-names`, `/api/intelligence/resolve-names`,
  `/api/glossary/detect` and `/api/autolink/scan` (body up to 16 KB), and
  `/api/entity-relationships/signals/{entity_type}` (up to 48 KB, for the
  entity tables' id lists).

In the browser, `api/client.ts` drops visitor writes with one "This view is
read-only." toast; personal actions (read, star, bookmark, bulk actions,
thread opened, playback progress, the Triage view) do nothing.

**The data layer hides what no visitor gets**
(`backend/app/services/public_view.py`). A SQLAlchemy `do_orm_execute`
listener filters every ORM query for visitors:

- **Feeds and articles.** Only feeds with `visible_to_visitors` load (never
  Manual Uploads), and only their articles, including subqueries and
  relationship loads; a hidden-feed article is a 404 everywhere.
- **Article links.** Article-link tables (`EntryTTP`, `EntryCVE`,
  `EntryThreatActor` and the rest, plus story-thread membership) keep only
  visible-article rows, so counts, trends, heatmaps and lists exclude hidden
  feeds without loading `Entry`.
- **Entities.** An actor, malware family, tool, vendor or product mentioned
  only in hidden feeds (or Manual Uploads) never appears in a list, profile,
  relationship, event or autolink match.
- **Saved AI output.** No `AIResult` row loads, and AI-extracted article
  metadata (`metadata.article_intel`) is left out. Entity assessments (on the
  entity row) stay visible.
- **Private work.** Nothing loads from campaigns (and their entries, entities
  and sources), observables, detection rules, intelligence requirements and
  their matches, intel profiles, notes, entity notes, comments, or the
  ransomware victim tracker. Campaign or observable ids passed to a pivot,
  timeline, list filter (`campaign_id`) or enrichment lookup find nothing.

These filters apply only to ORM SQL, so a request's session must start empty:
`session.get()` can answer from its cache without a query.

**Outside the ORM.** Raw SQL, the search index and caches skip the listener,
so each applies the rule itself:

- **Story threads** (raw SQL) are rebuilt from visible articles (none →
  dropped), titled by the earliest one. Visitors get a slug alias (`t-<thread id>`, accepted by the
  thread route) since the real slug comes from the first headline. Counts, dates, ranking and entity
  chips cover visible articles only. The stored summary and AI spine become a
  day-by-day spine of visible articles, built per request, never stored. Title search uses rebuilt titles; related threads are left out.
  Same in the priority queue, similar-article results and Active Story cards.
- **Search index and embeddings** (similar articles, glossary term pages and
  counts) are filtered to visible feeds.
- **Correlation events** are limited to certain types (actor, malware and
  technique correlations; CVE, exploit, KEV and trending events) about visible
  articles or no article, and visible entities. Campaign and requirement
  matches, rule and coverage events and feed health are left out (their text
  names private work).
- **The entity timeline** drops rule and campaign events and anything hidden.
- **Relationships** need both ends visible and keep only visible evidence;
  links from only hidden articles are dropped. Descriptions and creators
  are cleared.
- **Field sources** drop claims from hidden articles.
- **Caches**: pivots, graphs, the ATT&CK matrix and the corpus total behind
  specificity scores have separate visitor cache keys.
- **Shared data** is never built from a visitor's view. Rebuilds a visitor
  triggers (autolinker vocabulary, 0–10 scale cutoffs) run inside
  `instance_view()`, which lifts the filter.

**Folders and feeds.** Only folders holding a visible feed, and their
parents, are listed, without pipeline defaults. Feed responses keep only
name and folder (URL, errors, health, pause reasons, adapter config, title
filters, analyst notes cleared; no unread counts). The
tag list keeps global tags on visible articles.

**Response scrubbing.** A visitor's JSON loses:

- usernames and user ids (`username`, `analyst`, `created_by` and similar);
- any key about rules, coverage, detection gaps, campaigns, observables,
  requirements and PIR (priority intelligence requirement) matches, IOCs
  (indicators of compromise) or translations;
- note, comment and AI-result counts, and the `unread` figure.

Hidden lists return empty and counts or flags as zero or false, so pages keep
their shape; hidden objects or strings are removed. Objects
whose `type`, `entity_type`, `event_type`, `source_type`, `target_type` or
related-entity type is a campaign, observable or rule are removed, with
graph edges to them. Priority signals whose saved
explanation names private work (`pir_match`, `correlation_event`,
`detection_content`) keep their score but get a generic explanation. Article
bylines (`author`) are kept.

**Products** keep their vendor only when the visitor can see it; otherwise the
vendor id is cleared too.

**Reads stay reads.**

- Read-aloud serves only existing audio (`GET /api/tts/existing`, then the
  file) and saves no last-played time. Files are named by a text hash, so a
  visitor can only fetch one whose name they have.
- The image proxy serves visitors only images a visible article shows (an
  `<img>` source or lead image), at a few fixed widths, cached or fetched;
  otherwise the browser loads the original URL.
- No visitor route starts background (Celery) work.

**Dashboards** come from `DEFAULT_BOARDS` (`backend/app/dashboard_defaults.py`),
cut to Triage, Intel and CVE and the widgets above, packed, with fixed
made-up ids.

## Limits and caching

Visitor `/api/*` traffic is rate-limited per client IP — enough for a person,
too little to copy the site:

| What | Per minute | Per hour |
| --- | --- | --- |
| Opening an article (`GET /api/entries/{id}`, the only route that returns full article text) | 20 | 150 |
| Heavier reads: graph, pivot, timeline, analytics, map, calendar, priority queue, relationships, autolink scan, the entity-links list and the CWE catalog | 20 | 200 |
| Everything else | 180 | 1,500 |

Lists carrying article summaries or many links (`/api/entries`, the priority
queue, a feed's or glossary term's entries, `/api/entity-links`) return at
most 50 rows per page to visitors (the app's page size), so request limits
also cap volume.

Opening an article takes about 15 requests, only one of them the article, so
the article limit stops scrapers while the general limit fits a person's pace.

- Limits are checked and counted in one Redis step (parallel requests can't
  slip past); refused requests aren't counted.
- The browser shows one "Too many requests" toast per burst; the 429's
  `Retry-After` header says how long to wait.
- Signed-in users are limited only on AI routes. TAXII
  and the published indicator files have their own per-minute limit (see
  [operations.md](operations.md#rate-limiting)).

Every API response, including refusals (401, 413, 429), carries
`Cache-Control: private, no-store` and `X-Robots-Tag: noindex, nofollow`.
Shared-bytes routes (proxied images, audio) set their own `Cache-Control`. The web app has a `noindex` meta tag and a
crawler-blocking `robots.txt`.

## Keeping it safe as the API grows

`backend/tests/test_public_read_only.py` lists every visitor route
(`VISITOR_ROUTES`) and every no-login route. It fails when a route uses
`get_viewer` or skips login without being listed, or when a one-article
visitor route doesn't use `get_entry_viewer` — so opening a route is always
deliberate. It calls every visitor route with the switch off (all must be 401)
and on (no 401, 403 or 5xx, no database writes, no Celery tasks).

The **canary test** marks hidden-feed articles everywhere:
titles, URLs, text, an actor, malware family, tool, vendor and product known
only from them, a hidden-only story thread, a thread mixing hidden and visible
articles, a correlation event, a relationship, and a claim quote. It calls
every visitor route signed in (filling caches), then as a visitor, failing on
any marker or hidden id. Other tests cover the rest: signal text, article metadata, campaign filters, thread
search, events with no article, page caps, the image proxy, tags, autolink
scan and vocabulary, ATT&CK counts and cache, rate limits under parallel
requests, and malformed `Authorization` headers.

To open another route to visitors:

1. Switch it to `get_viewer` (or `get_entry_viewer` for an `{entry_id}`
   route).
2. Ensure it reads nothing personal and starts no background work for
   visitors.
3. Check any raw SQL, search or cache it uses applies the visitor rule.
4. Add it to `VISITOR_ROUTES` in the test.
5. For a read-only POST, also add it to `ANONYMOUS_READ_POSTS` (or
   `ANONYMOUS_READ_POST_TEMPLATES`) in `backend/app/core/public_access.py`,
   and to `VISITOR_READ_POSTS` in `frontend/src/api/client.ts`.

The canary test then covers it.

## Live updates

Visitors get no live-updates stream: it needs a per-user ticket, and its
broadcast channel is unfiltered (feed and entry ids from every
feed, correlation-event text). A visitor's article list refreshes on page
change, reload, or returning to a view after its 30-second cache expires.
Timer-refreshed widgets and thread views keep refreshing.
