# Getting started

What to do in your first hour, in order.

## Your account

The first account created on an instance becomes the admin. After that,
registration may be invite-gated — if you were given credentials, use them; if
you were sent an invite link, it will take you to the register page.

Admin matters more than it sounds. Non-admins can read everything, write notes,
build campaigns and reports, save searches, and write detection rules. Admins
additionally manage feeds, AI configuration, users, the engine, and system
settings. If a section in this guide says "admin only", that's why.

## The onboarding wizard

On first login a wizard slides open. It's all optional and it won't come back
once dismissed:

1. **Import OPML** — bring feeds over from another reader in bulk.
2. **Add feeds** — one at a time.
3. **Configure AI** — pick a provider. Skippable; AI features simply stay off.
4. **Choose a theme.**
5. **Keyboard shortcuts** — worth thirty seconds.
6. **Claude Code skill** — only relevant if you plan to drive IntelFeed from
   Claude Code.

If someone else already set the instance up, the setup steps are skipped.

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
