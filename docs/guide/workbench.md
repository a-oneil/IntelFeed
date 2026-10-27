# The Workbench

The Workbench holds what IntelFeed has built from your reading: dashboards,
entity tables, detection rules and reports. Switch the sidebar to
**Workbench** with the toggle at the top. It starts with
**Dashboard** and **Reports**, then three groups: **Detection**, **Entities**
and **Intelligence**.

![The Threats board listing ranked threats with story and outlet counts and draft-detection-rule actions](../assets/screenshots/threats-board.png)

*The Threats board ranks recent activity by attention and new tradecraft.*

## Dashboard

The Workbench opens on the dashboard, a board of widgets you arrange.

- **+ Widget** adds a widget. Drag its header to move it and its corner to
  resize it. The layout saves to your account.
- **Templates** fills a board from a ready-made layout.
- **Lock** stops accidental moving or resizing.
- **Range** sets the time window for every widget on the board.
- **Board tabs** keep several boards, such as triage and reporting. The **+**
  next to the tabs adds one.
- The gear on a widget opens its settings, where it has any.

There are 51 widgets. Good ones for a first board:

- **Triage Queue Stats** and **Unread Count**: how much is waiting.
- **Trending Actors**, **Trending CVEs**, **Trending Malware**: what is written
  about most right now. TTPs, vendors and products have trending widgets too.
- **Feed Activity** and **Feed Health**: how much each feed sends, and whether
  it still fetches.
- **KEV Deadlines**: known-exploited CVEs and CISA's fix-by dates.
- **ATT&CK Heatmap** and **ATT&CK Coverage Gap**: which techniques you can
  detect, and which you can't.
- **New Detections**: rules added recently.
- **Under the Radar**: threats that seem important but have little coverage.
- **Morning Briefing** and **Weekly Recap**: written summaries for a handover.
  These need an AI provider.
- **PIR Coverage**: how well your feeds answer your intelligence requirements
  (see [Intelligence](#intelligence) below).

## Reports

Write and publish finished intelligence: exposure reports, flash alerts, actor
profiles and more. See [Campaigns and reports](campaigns-and-reports.md).

## Detection

**ATT&CK Matrix**: shades each MITRE ATT&CK technique by how often your feeds
report it and whether your rules cover it. Often-reported techniques with no
rule are your gaps. **Export Navigator JSON** downloads the grid for MITRE's
ATT&CK Navigator.

**Rules Library**: every detection rule you have. See
[Writing detection rules](detection-rules.md).

**Telemetry Sources**: tick the log sources you collect. IntelFeed then tells
you when a rule needs logs you don't collect, so it could never fire.

**Threats**: what is active now, ranked by story rather than article, so ten
write-ups of one breach count once. Tabs: **All**, **Actors**, **Malware** and
**Vulnerabilities**. See [The Threats board](threats-board.md).

## Entities

One table per entity type: Campaigns, Countries, CVEs, Malware, Mitigations,
Observables, Products, Sectors, Threat Actors, Tools, TTPs, Vendors and
Weaknesses.

Sort and filter each table, and choose which columns show and in what order;
the layout saves to your account. Click a row to open the entity's profile (see
[Entities and profiles](entities.md)).

Use these tables when your question starts from a thing, such as "which CVEs
are known to be exploited?".

## Intelligence

**Glossary**: definitions of security terms, shown when you hover them in
articles. **+ Add Term** adds your own.

**Ransomware**: victims named on ransomware leak sites, as a table.

**Requirements**: your standing intelligence questions (PIRs, priority
intelligence requirements). New articles are checked against them, and a match
raises an article in the [Priority Queue](priority-queue.md). Write a few
narrow ones rather than many broad ones.

**Telegram Mentions**: Telegram channels your articles mention that you don't
ingest yet, so you can add them as feeds.

**Watchlist**: the entities you watch, with their new mentions.

## Engine (admin only)

The Engine console is at **Settings → Engine**, not in the Workbench sidebar.

It shows how articles move through processing, with each step's settings beside
it, plus screens for **Scheduled jobs**, **Pipeline plans**, **Enrichment**,
**Maintenance** and **Publishing** (outbound indicator feeds).

Admins use it when a feed stops, extraction produces junk, or an enrichment
source is rate-limited. Enrichment sources and their API keys are set up here.
Every setting is listed in
[engine-settings.md](../engine-settings.md).

![The Glossary listing security terms with category and maturity columns](../assets/screenshots/glossary.png)

*The Glossary links each term to the articles that use it, so a term is a starting point for a search.*

Next: [The Threats board](threats-board.md)
