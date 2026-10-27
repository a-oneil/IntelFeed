# Settings and personalising

This page covers each part of **Settings**: your own preferences, and what
admins control for the whole instance. Sections are listed on the left in three groups: **You**, **Connect** and
**Administration**. Everyone sees Account, Appearance, My AI, Reading, Tags and
Claude Code Skill; the rest are admin only. The **Search settings…** box finds a
section by keyword, such as "password" or "theme".

![The Appearance settings pane showing a grid of selectable light and dark themes](../assets/screenshots/settings.png)

*Settings → Appearance. Click a theme to switch to it.*

## Account

- **Profile**: your username, role and the date you joined.
- **Getting started**: the onboarding tour. **Resume the tour** reopens it on
  the step you left. **Replay from the start** runs it again. See
  [Getting started](getting-started.md).
- **Change Password**: enter your current password and a new one.

## Appearance

Pick from the built-in light and dark themes; changes apply at once. To make
your own, duplicate a theme or use **+ Create Theme**. Admins can set the
default theme for everyone, and **Use default theme** puts you back on it.

## My AI

If your admin allows personal keys, add a key of an allowed type (Claude API,
OpenAI-compatible or Ollama), choose which tasks use it or make it your
default, and see this month's spend against your cap. Each key shows its last
test result.

Tasks you start yourself (copilot, rule drafts, summaries, reports) use your
key. The background pipeline, automation rules and share links never do. If
personal keys are off, the page says so. See
[Automation and AI](automation-and-ai.md#your-own-key).

## Reading

**Your Radar** appears only when an admin has turned on personalised ranking.
Your ▲/▼ votes in the Priority Queue teach it how much each kind of signal
matters to you. It changes the order you see, not what reaches the queue. The switch turns it off (back to the shared ranking), and
**Forget what it learned** clears your learned weights.

**Display**: **Default view** (all entries or unread only), **Entries per
page**, **Default sort order** and **Date format**.

**Behavior**

- **Open links in new tab**
- **Mark read on scroll**: on if you skim, off if you triage one article at a
  time. Try both.
- **Show entry previews**: the short snippet under each title.
- **Compact view**: more rows per screen.

**External links**: **Confirm before leaving IntelFeed** shows where a link
really goes before you follow it. Choose **Articles and summaries** (the
default), **All external
links**, or **Off**. Links inside IntelFeed never ask.

The dialog lets you copy the link, or copy it defanged (unclickable, for
reports). It warns in red when the link text names one site but the link goes
to another, and notes shorteners, raw IP addresses, unusual characters,
HTTPS-to-HTTP downgrades and `user@host` links, all common phishing tricks.

MITRE, NIST (NVD), CVE.org and CISA, and their subdomains, never ask. Tick
**Don't ask again for …** to trust a site yourself; remove it later under
**Trusted sites**. Trust is per exact site name, so `example.com` doesn't cover
`blog.example.com`. A trusted site still asks if the link looks like one of the
tricks above.

**Reader Typography**: **Font size**, **Line spacing** and **Content width**,
plus **Read-aloud voice**: **Natural voice (server)** sounds the same everywhere
but takes a few seconds the first time; **Browser voice** is instant and works
offline but sounds different on each device.

Tip: rather than tuning sort order, use the [Priority Queue](priority-queue.md).

## Tags

Rename, recolour, merge and delete tags. Each tag shows how many articles carry
it, and **View** opens them.

- **Chip** shows the tag as a badge on the article row.
- **Share** makes a tag global: one set of assignments everyone sees.
  **Unshare** makes it personal again. New tags are personal unless you tick
  **Everyone** when you create them.
- **Tooltip** adds a short description shown on the chip.

Use **Merge** to fold `to-rule`, `to_rule` and `torule` into one without losing
anything.

For when to use a tag instead of a star or bookmark, see
[Reading and triage](reading-and-triage.md).

## Claude Code Skill

Setup for using IntelFeed from Claude Code in a terminal: install the skill,
set the environment variables, reload your shell, and start asking.

There are two skills: the full one, and a lite one that can only search and
read. Use the lite one unless you want an agent that can make changes.

## Admin sections

**Feeds & Export**: **OPML Export** (a copy of your feed list), YouTube
defaults such as excluding Shorts, and the public RSS feeds. Importing OPML is
in the **Add Feed** window. See [Adding and managing feeds](feeds.md).

**Telegram**: the one-time setup walkthrough.

**AI Configuration**: **Providers**, **Prompts**, **User keys** and **Cost
Dashboard**. See [Automation and AI](automation-and-ai.md).

**Engine**: the processing pipeline console. It shows feed health and what each
step did to each article, with the settings for autolinking, AI extraction,
ranking and more. The buttons along the top open **Jobs**, **Plans**,
**Enrichment**, **Publishing** and **Maintenance**. Most instance-wide settings
live here next to the step they control, including API keys, rate limits and
the image proxy. See [the engine reference](../engine.md).

**Logs**: automation run history, plus the server's application, error, HTTP,
task, audit and update logs.

**System**: error monitoring (Sentry), backup retention, and maintenance
buttons: **Rebuild Search Index**, **Sync Entity Indexes** and
**Revalidate Autolinks**.

**Users**: accounts, roles, registration and public read-only mode. See
[Users and access](users-and-access.md).

## What isn't in Settings

- **The glossary** lives at **Workbench → Glossary**.
- **Webhook URLs** are set on the notification action inside each automation
  rule.

Next: [Users and access](users-and-access.md)
