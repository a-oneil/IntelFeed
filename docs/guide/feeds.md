# Adding and managing feeds

Feeds are where every article comes from. This page covers adding, sorting
and tuning feeds, and spotting broken ones. Any signed-in user can add a feed;
admin-only settings are marked.

![The Engine feed health view showing 307 feeds split into healthy, stale and erroring, with a table of erroring feeds](../assets/screenshots/feeds.png)

*Feed health in the Engine console: which feeds are healthy, stale or erroring.*

Start small. Twelve good sources beat two hundred.

## Adding one

Click the **+** button (**Add feed**) in the sidebar. The **Add Feed** window
has six tabs: **Feed URL**, **GitHub Repo**, **Web Scraper**, **Bluesky**,
**Telegram** and **OPML**. If your instance has categories, you must pick one
before you can subscribe.

### URL

Paste an RSS or Atom feed URL, or a website's address, and click **Discover**
to see a preview. YouTube channels and podcast feeds are recognised: videos
appear as entries, and episodes play in the app. Pick a category and a **Poll
Interval** (default 30 minutes), then click **Subscribe**.

Prefer a site's full-text feed over a summary-only one.

### GitHub repo

Follow the files in a repository, such as a detection rule repo. Enter
`owner/repo`, the **Branch**, and **File Patterns** (one per line, for example
`**/*.yml`). Tick **Include file content** to import the files themselves.

**Set Up All Detection Repos** subscribes you to a ready-made set of public
detection rule repositories (SigmaHQ, Elastic, Splunk, YARA and more) in one
click.

### Web scraper

For a site with no feed. Give it the **Blog URL** and IntelFeed pulls the
article links from the page. Narrow it with a **Link Selector** or **URL
Pattern**, and cap it with **Max Articles**.

Scrapers break when a site is redesigned, so check it again after a week. To
rename it, edit the feed's **Display name**.

### Bluesky

Choose a **Mode**:

- **Author**: every post from one handle.
- **Custom feed**: a Bluesky custom feed (you can paste its bsky.app link).
- **Search**: posts that match a query. A search for your product's name is a
  cheap early warning.

### Telegram

An admin has to set Telegram up once on the server first. See
[Telegram setup](#telegram-setup) below. After that, **Discover from my
Telegram account** lists the channels the account has joined.

## Categories

Categories are the folders in your sidebar, and every feed sits in one. Group
feeds by how you want to read them, not by name or vendor. For example:

- *Government advisories*: CISA, NCSC, national CERTs.
- *Vendor research*: the big security vendor blogs.
- *CVE feeds*: NVD and similar.
- *Ransomware*: leak sites and tracking blogs.
- *Community*: Reddit, Mastodon, Bluesky, YouTube.

A good test: when something breaks at 9am, which folder do you open first?

Create categories before you import in bulk. A feed added without a category
goes into the one most feeds of its type already use.

Right-click a category (or long-press on a phone) for **Rename...**,
**Extract Intelligence**, and, for admins, **Edit Category...** and
**Delete Category**.

### Category settings and defaults

**Edit Category...** (admins only) changes settings for every feed in a
category: check interval, retention, source ratings, and what runs on each new
article. Two switches decide where the change goes:

- **Apply to the feeds here now**: changes every feed in the category today.
- **Save the pipeline settings as this category's default**: a feed added to
  this category later (by hand, from OPML, or from a starter pack) starts with
  the settings under "What runs on each new article". Interval, retention and
  ratings are never saved as defaults.

Defaults apply only when a feed is created. They don't change feeds already in
the category, or a feed moved into it. Use the first switch for that.

## Importing in bulk

The **OPML** tab in the **Add Feed** window imports an OPML file, the format
other feed readers export. Folders become categories. Importing is admin-only,
unless per-user feed subscriptions are on (see
[Users and access](users-and-access.md)).

To save a copy of your feeds, use **Export OPML** under
**Settings → Feeds & Export** (admins only).

After an import, delete what isn't about security.

## Per-feed settings

Right-click a feed in the sidebar for **Edit Feed...**, **Mark All Read**,
**Refresh**, **Mute**, **Extract Intelligence**, **Translate Articles**,
**Move to...** and **Unsubscribe**.

**Edit Feed...** has six panes:

- **Overview**: what the feed has produced, and its last error.
- **Identity**: the **Display name**, the **Category**, and two switches.
  **Receive new articles** off pauses the feed. **Count toward unread** off
  mutes it (see below).
- **Source** (admins): the URL, feed type, **Check for new articles** (poll
  interval), **Keep articles for** (retention; anything extracted stays), and
  **Translate articles into English**. Set short retention on busy, low-value
  feeds.
- **Pipeline** (admins): what runs on each new article.
- **Assessment**: your rating of the source's reliability, timeliness and
  relevance, plus notes.
- **Readers** (admins): who reads the feed, and **Visible to visitors** for
  public read-only mode.

**Skip articles whose title contains** (admins, Source pane) drops articles
whose title contains a listed phrase (one per line, any case) before they are
saved, so they never reach tagging, AI or scoring. The pane shows how many of
the last 100 titles would have been dropped. Use it for repeating filler, such
as "ISC Stormcast For" on SANS ISC Diary. Articles already saved stay.

**Mute** hides a feed's articles from your main list and unread count. You can
still open the feed. Its articles are still tagged, analysed by AI and scored.
A muted feed's Overview shows its AI use over the last 30 days, and an admin can
switch its AI off there in one click. Muted feeds sit in a **Muted** fold in the
sidebar.

## Keeping feeds healthy

Feeds stop working quietly, and a silent feed looks like a quiet week. Check
once a month in:

- The **Feed Activity** and **Feed Health** widgets on the Dashboard. A bar that
  drops to zero and stays there needs a look.
- **Settings → Engine**, **Feeds** view (admins). It lists dead, empty,
  erroring, stale and disabled feeds, with each feed's errors and value.

## Duplicates

IntelFeed compares the title and the start of the text, so copies of one story
become one entry. The Priority Queue ranks
an article that many feeds copy word for word **lower**, because more copies
doesn't mean more important. See [Priority Queue and watching](priority-queue.md).

## Telegram setup

Telegram is the one source an admin sets up on the server first. Reading
channels needs a real Telegram user account, because bots can't read channels.

1. Create a Telegram API application at my.telegram.org and note the
   `api_id` and `api_hash`.
2. Put `TELEGRAM_API_ID` and `TELEGRAM_API_HASH` in the server's `.env` file
   and restart the services.
3. Run the interactive login script on the server. It saves a session file.
4. Back up that session file. If you lose it, you have to log in again.

**Settings → Telegram** (admins) walks through each step with the exact
commands.

Use a separate Telegram account, not your personal one; it joins every channel
you track.

To find channels, open **Workbench → Telegram Mentions**: the channels your
articles link to, and where each was mentioned.

## Adding content by hand

The upload button next to **+** in the sidebar (**Ingest**) adds content that
isn't in a feed. It has three tabs:

- **URLs**: one link per line. A GitHub repository link adds one item per file.
- **Files**: drop many files at once. A `.zip` file is unpacked.
- **Paste**: paste a report, an advisory or a chat log.

Tick **Indicator list** when each line is one indicator (IP, domain, hash or
URL). Each item becomes an entry under **Manual Uploads** and is processed like
any article. The original file can be downloaded from the entry.

## What happens after you add a feed

IntelFeed saves new articles, merges duplicates, and links the entities each
mentions. If AI is set up, it also summarises each article.

The first check can take a few minutes. If a feed still shows nothing after an
hour, look for its error in the feed's **Overview** pane or in
**Settings → Engine**, **Feeds** view.

Next: [Reading and triage](reading-and-triage.md)
