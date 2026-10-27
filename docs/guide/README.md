# Using IntelFeed

This is the user guide. It shows you how to work in IntelFeed day to day, and
it doesn't assume you know anything about the code. If you want to know how a
feature is built, see the rest of the [documentation](../README.md).

If you're new, read the first three pages in order. After that, each page
stands on its own. For the phone app, see [IntelFeed for Android](../android-app.md).

| Page | What it covers |
|---|---|
| [Getting started](getting-started.md) | Your first login, the setup tour, the settings worth changing on day one |
| [Adding and managing feeds](feeds.md) | Every source type, categories, OPML import, dead feeds, Telegram |
| [Reading and triage](reading-and-triage.md) | The three panes, the reader, clearing a big inbox fast |
| [Searching](searching.md) | The search box, the filter rail, saved searches |
| [Entities and profiles](entities.md) | What gets linked in an article, and what a profile page is for |
| [Priority Queue and watching](priority-queue.md) | How the ranking picks what matters, and how to steer it |
| [Story threads](story-threads.md) | One row for a story that many outlets covered |
| [The Workbench](workbench.md) | The dashboard, the entity lists, and everything else under Workbench |
| [The Threats board](threats-board.md) | What was reported this week, and why each row ranks where it does |
| [Writing detection rules](detection-rules.md) | From article to rule, the editor, the rule library |
| [Campaigns and reports](campaigns-and-reports.md) | Grouping an investigation, then writing it up |
| [Automation and AI](automation-and-ai.md) | Rules that run on their own, and the copilot |
| [Notes and sharing](notes-and-sharing.md) | Notes, comments, share links, exports |
| [Settings and personalising](settings.md) | Themes, reading preferences, tags, and where each setting lives |
| [Users and access](users-and-access.md) | For admins: registration, invite links, accounts, public read-only mode |
| [When something isn't working](troubleshooting.md) | Dead feeds, wrong links, silent automations, odd rankings |

## The short version

IntelFeed collects security articles from feeds. It reads each one and links
what it finds to a profile page. Those things are called **entities**: threat
actors (the groups behind attacks), malware, CVEs (published software flaws),
ATT&CK techniques (standard names for attacker behaviour), vendors, products,
countries, tools and more.

In a normal feed reader, an article is the end of the road: you read it and
it's gone. Here, an article about LockBit also adds to the LockBit page, the
pages of the CVEs it names, and the pages of the techniques it describes. After
a few months, those pages are what you use most, and the articles are the
evidence behind them.

So there are two ways to work, and you'll use both:

- **Reading**: the feed inbox. New articles, triage, clearing the queue.
- **Workbench**: what has built up over time. Entity pages, the Threats board,
  detection rules, campaigns, reports.

The **Reading / Workbench** switch is at the top of the left sidebar.

## Getting unstuck

- Press `?` in the reader to see the keyboard shortcuts.
- Open **Documentation** (its button sits at the top of the sidebar) and ask
  the copilot there. It can read these pages and answer questions about them.
- Use the filter box above the page list on the Documentation page to find a
  page by name.

Reading this on GitHub? The [docs index](../README.md) lists every page.

Next: [Getting started](getting-started.md)
