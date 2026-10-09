# Getting started

What to do in your first hour, in order.

![The IntelFeed dashboard with overview stat tiles, a morning briefing, a triage flow chart, and an under-the-radar list](../assets/screenshots/dashboard.png)

*The dashboard once feeds have been ingesting for a while.*

## Your account

The first account created on an instance becomes the admin. After that,
registration may be invite-gated — if you were given credentials, use them; if
you were sent an invite link, it will take you to the register page.

Admin matters more than it sounds. Non-admins can read everything, write notes,
build campaigns and reports, save searches, and write detection rules. Admins
additionally manage feeds, AI configuration, users, the engine, and system
settings. If a section in this guide says "admin only", that's why. Running an
instance for a team — locking registration, invite links, managing accounts —
is covered in [Users and access](users-and-access.md).

## The onboarding tour

On first login a tour slides open, in three chapters. Every step is skippable,
and **closing it saves your place rather than ending it** — it stays closed until
you ask for it back, and **Settings → Account** then offers **Resume the tour**
(picking up on the step you closed on) or **Replay from the start**. Only
reaching the end marks it finished.

**Set up** (admin only, and each step disappears once it's satisfied):

1. **Reference data** — checks whether the countries, ATT&CK, CWE and
   vendor/product catalogues are seeded, and gives you the command if they
   aren't. Until they are, articles ingest but most entity types never link
   (migrations load only countries and a baseline of ATT&CK techniques), which
   is the single most common "IntelFeed looks broken" report.
2. **Add feeds** — curated starter packs, an OPML import, or a single URL.
3. **AI provider** — Ollama, Claude, or an explicit "run without AI" that says
   what you lose. Connecting one tests it for real, then routes the AI tasks at
   it, because a registered provider on its own runs nothing. The step reports
   how many tasks are now running and on which model. Agentic tasks stay on the
   Claude Code CLI if the provider can't call tools.
4. **Services & team** — optional containers, invites and roles.
5. **Verify it works** — waits for a real poll and shows feeds fetched, entries
   ingested and entities linked. Configuring something isn't the same as it
   working.

**Learn the app** (everyone): the reading loop, the Priority Queue, entities and
pivoting, search, the workbench, and detection rules and intel products.

**Make it yours** (everyone): theme, keyboard shortcuts, and where help lives.

If someone else already set the instance up, the setup chapter is skipped and
the rail tells you why — you still get the whole product tour. Driving IntelFeed
from Claude Code lives in **Settings → Claude Code Skill**, not in first-run.

## Adding feeds

Click **+ Add Feed** in the sidebar. You can paste an RSS or Atom URL and
IntelFeed works out what it is — YouTube channels, subreddits, Mastodon
accounts, podcasts and NVD are all recognised automatically — or use the tabs
for GitHub repositories, web scraping, Bluesky and Telegram.

Three or four good sources is a fine place to start. You don't need a hundred
feeds on day one, and the fastest way to make IntelFeed useless is to point it
at everything.

Give each feed a category, because categories are the folders you'll be
filtering by for the rest of the instance's life. Group by what you'd want to
read together on a bad morning — "Vendor research", "CVE feeds", "Government
advisories" — not alphabetically.

[Adding and managing feeds](feeds.md) is the full page: every source type, bulk
OPML import, retention and fetch intervals, spotting a feed that has quietly
died, and the one-time admin bootstrap Telegram needs before it will work.

## Settings worth setting on day one

**Settings → Reading** (everyone)

- **Reader typography** — font size, line height, column width. You will be
  staring at this pane for hours; make it comfortable.
- **Default view and sort** — whether the list opens on unread only, and
  newest or oldest first.
- **Compact view / entry previews** — how much of each article the list shows.
- **Mark read on scroll** — on if you skim, off if you triage deliberately.

**Settings → Appearance** (everyone)

Theme gallery, light and dark. Changes apply instantly.

**Settings → Engine**, Feeds view (admin only)

- **Image proxy** — caches external images on your server. Faster, and the
  article's source never sees your analysts' IP addresses. The trade is that a
  cached image doesn't update if the original changes.

**Settings → AI Configuration** (admin only)

- Verify whatever provider you set during onboarding, on the Providers tab.

**Settings → Engine**, enrich stage (admin only)

Turn on the enrichment sources you want. NVD, EPSS and CISA KEV between them
are what make a CVE page worth opening — score, exploitation likelihood, and
whether it's known-exploited in the wild. See
[Entities and profiles](entities.md).

## What happens next

Feeds poll on a schedule. As articles land, IntelFeed scans each one for known
entities and links them, and — if AI is configured — summarises and extracts
from them. The first useful view is the entry list; go to
[Reading and triage](reading-and-triage.md).

Give it a few days before judging the intelligence side. Entity pages are
cumulative: they're thin on day one and genuinely useful by the end of the
month.
