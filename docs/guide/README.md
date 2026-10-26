# Using IntelFeed

This is the user guide — how to actually work in IntelFeed. It assumes nothing
about the code underneath. If you want to know how a feature is built, the
rest of the documentation covers that; this section covers how to use it.

Read the first two pages in order if you're new. After that, pages stand alone. If you're after the phone app, that's [IntelFeed for Android](../android-app.md).

| Page | What it covers |
|---|---|
| [Getting started](getting-started.md) | First login, your first feeds, the settings worth changing on day one |
| [Adding and managing feeds](feeds.md) | Every source type, categories, OPML import, retention, dead feeds, Telegram |
| [Reading and triage](reading-and-triage.md) | The three panes, the reader, clearing a big inbox fast |
| [Searching](searching.md) | The search box, the filter rail, saved searches |
| [Entities and profiles](entities.md) | What gets linked in an article, and what a profile page is for |
| [Priority Queue and watching](priority-queue.md) | How the ranking decides what's important, and how to steer it |
| [Story threads](story-threads.md) | One row for a story covered twenty times: the spine, the coverage, "N new" |
| [The Workbench](workbench.md) | The dashboard, entity browsers, everything under Workbench |
| [The Threats board](threats-board.md) | What was reported this week, why it ranks where it does, and what each row's button does |
| [Writing detection rules](detection-rules.md) | Article to rule, the editor, the rule library |
| [Campaigns and reports](campaigns-and-reports.md) | Grouping an investigation, then writing it up |
| [Automation and AI](automation-and-ai.md) | Rules that run themselves, and the copilot |
| [Notes and sharing](notes-and-sharing.md) | Notes, comments, share links, exports |
| [Settings and personalising](settings.md) | Themes, reading preferences, tags, and what lives where |
| [Users and access](users-and-access.md) | For admins: registration, invite links, managing accounts, per-user feed lists |
| [When something isn't working](troubleshooting.md) | Dead feeds, wrong links, silent automations, bad rankings |

## The short version

IntelFeed pulls security articles out of feeds, reads them for you, and links
what it finds — threat actors, malware, CVEs, ATT&CK techniques, vendors,
products, countries, tools — to profile pages that accumulate over time.

That difference matters. In a normal feed reader an article is the end of the
road: you read it, you mark it read, it's gone. Here, an article about LockBit
also adds to the LockBit page, the CVEs it names, and the techniques it
describes. Six months in, those pages are the thing you actually use, and the
articles are just the evidence behind them.

So there are two ways to work, and you'll use both:

- **Reading** — the feed inbox. New articles, triage, clearing the queue.
- **Workbench** — the accumulated intelligence. Entity pages, the threat board,
  detection rules, campaigns, reports.

The switch between them is at the top of the left sidebar.

## Getting unstuck

Press `?` anywhere for the keyboard shortcuts. Ask the copilot on the
[documentation home](/documentation) — it can read these pages and answer
questions about them. (Reading this on GitHub instead? The [docs index](../README.md)
lists every page.) And every page in the left rail is searchable with the
filter box above it.
