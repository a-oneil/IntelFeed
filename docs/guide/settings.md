# Settings and personalising

Settings opens with its own nav rail; the app sidebar folds away beside it.
What you see depends on your role — non-admins get Account, Appearance, Reading,
Tags and Claude Code Skill; admins get everything.

## Account

Profile and password. Little to say.

## Appearance

The theme gallery — several dozen built-in light and dark themes, plus any
custom ones your instance has. Changes apply instantly, so click through them
rather than reading the names.

If you're going to be in the app all day, this is worth two minutes. Contrast
and density matter more than they sound when the job is scanning lists.

## Reading

Where the reading experience is tuned.

**Display** — default view (all entries or unread only), entries per page,
default sort order, date format.

**Behavior**

- *Open links in new tab* — whether article links leave the app.
- *Mark read on scroll* — on if you skim, off if you triage deliberately. This
  one changes how the whole app feels; try both.
- *Show entry previews* — the snippet under each title.
- *Compact view* — more rows per screen, less of each.

**External links** — a confirmation before you follow a link off IntelFeed. It
shows the destination host in large type, the full URL in a block you can copy
(or copy defanged), and a red banner when the link's text names one site but the
link goes to another. (If the destination's URL itself mentions the site — an
indicator domain linked to a VirusTotal or urlscan page about it — you get a
quieter note instead of the red banner.) That mismatch, a shortener, a raw IP, an internationalised
domain or a `user@host` URL are the things worth a second look in a phishing
write-up. The scope is a choice: *links in article content* (the default —
feed-supplied text is the untrusted part), *all external links*, or *off*.
MITRE, NIST (NVD), CVE.org and CISA, plus the sites of your own feeds, never
prompt, and ticking "Don't ask again" in the dialog adds a host to your trusted
list here. Trust is per exact host, so trusting `example.com` does not trust
`blog.example.com`. A link whose text names a different site is always
confirmed, even for a trusted host. Middle-click and ⌘/Ctrl-click are held too;
the browser's own right-click menu is not.

**Reader typography** — font size, line height, column width for the article
pane.

**Read aloud** — the voice and playback settings for server-side text-to-speech.

**Your Radar** — only present when an admin has enabled Personalised Radar. It
shows each signal family's learned weight, the votes behind it, and both ways
out: switch back to the house ranking, or discard the fitted weights.

The honest advice: leave sort on newest-first and default view on unread, and
spend your tuning effort on the [Priority Queue](priority-queue.md) instead.
Ordering your whole inbox differently is a much weaker lever than ranking it.

## Tags

The tag manager: rename, recolour, merge and delete tags across the instance,
with usage counts.

Merge is the one that earns its place. Tags are free-text and instance-wide, so
within a month you will have `to-rule`, `to_rule` and `torule`. Merging folds
them together without losing anything.

Tags are the durable, searchable flag — see the star/bookmark/tag split in
[Reading and triage](reading-and-triage.md).

## Claude Code Skill

Setup instructions for pointing Claude Code at your instance, so you can drive
IntelFeed from a terminal rather than the UI. The page gives you the install
steps and the environment variables.

There are two skills: the full one, and a read-only variant that exposes only
query and search tools. Use the read-only one unless you specifically want an
agent that can write.

## Admin sections

**AI Configuration** — three tabs. *Providers* (which model runs which task, and
keys), *Prompts* (the prompt behind every AI task, editable), *Cost* (tokens and
spend per provider and task). Covered in
[Automation and AI](automation-and-ai.md).

**Engine** — the ingestion pipeline console: feed health, stage settings,
autolinking, AI extraction, enrichment, scoring, scheduled jobs and pipeline
plans. See [the engine reference](../engine.md). Old `/workbench/engine` links
redirect here.

**Feeds & Export** — OPML import/export and feed management, including per-user
subscriptions if your instance has them on. See [Feeds](feeds.md).

**Telegram** — the one-time bootstrap walkthrough.

**System** — grouped settings stored in the database rather than in config
files, so they change without a redeploy: security, feeds, image proxy, API
keys, AI, intelligence and autolinker behaviour, rate limiting, monitoring,
backup, public RSS.

**Users** — accounts and roles.

**Logs** — automation runs, AI task logs, per-task costs and errors. The first
place to look when an automation seems to have stopped.

## What isn't in Settings

One thing people hunt for here and don't find: **the glossary**, which lives at
**Workbench → Glossary**.

Webhook URLs aren't a settings section either; they're configured on the
notification action inside each automation rule.
