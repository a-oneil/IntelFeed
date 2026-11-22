# Story threads

A story thread gathers one developing story, covered by many outlets over
several days, into a single row. This page explains where thread rows appear
and how to read one, for example a row that says "11 outlets · 23 articles ·
6 new".

**Prerequisite:** threading is off until an admin turns it on, and it needs a
reachable Ollama server. See [Check that threading is on](#check-that-threading-is-on).

The same story often arrives many times: the first report, a follow-up with a
new indicator, then a dozen outlets repeating the first one. A **story
thread** holds all of that together: the story, its articles, and a short
**timeline** that lists what changed in each update.

## Check that threading is on

Threads are off by default. If you never see a thread row, this is the usual
reason.

An admin turns them on under **Settings → Engine**, in the score stage, under
**Story threads**. IntelFeed uses Ollama to compare articles, so it needs an
Ollama server it can reach that has the embedding model installed (by default
`nomic-embed-text`). It works through the backlog newest first, so threads
appear over the first few runs, not all at once. Setup details and tuning are
in the developer page [Story Threads](../story-threads.md).

Threading runs on a timer and can be up to about half an hour behind. A story
reported a few minutes ago may show as separate articles first, then be
grouped into a thread.

## Where you'll see one

- **The Priority Queue.** A thread is one row in place of its articles. It
  ranks by the score of its best *unread* article, in the same highest-first
  list as single articles. Once you have read the whole thread, it leaves the
  queue.
- **The reader.** Open a thread row and the reader shows the thread (see
  below).
- **The Threats board.** The board counts *stories*, not outlets, so a wave of
  repeats counts once. A story with no named actor, malware or CVE still gets a
  row if it has something useful in it: a technique, an observable, or a
  product you follow. See [The Threats board](threats-board.md).
- **More like this.** Similar articles in the reader come from the same
  matching, or from shared keywords for articles not yet processed.
- **Briefings and scoring.** Daily briefings count each story once, so eight
  outlets covering one zero-day count as one development. An article grouped
  as a repeat is scored as one too (the *feed echo* signal in
  [Priority Queue and watching](priority-queue.md)).

A thread has no page of its own. Its link, `/priority-queue?thread=<slug>`,
opens it directly, so you can bookmark it or paste it into a note.

## Reading a thread

**The header** shows the date range, the number of outlets, which outlet
reported it **first**, and the **yield**: how many techniques, CVEs and
detection rules came out of the thread's articles, and how many repeats were
grouped. Key entities are listed underneath and link to their profiles.

**The timeline** is the main part. It has one line per update to the story,
not one per article. Each line has a tag:

| Tag | Meaning |
| --- | --- |
| **First disclosure** | The first article on the story |
| **New technique** | A technique, tool or payload not reported earlier in the thread. Only an AI-written timeline uses this tag |
| **Peak coverage** | The day with the most coverage |
| **Update** | A later development |

Repeats are not listed on the timeline. Each line says how many repeats it
groups.

You may see **"Timeline grouped by day. Summary not written yet."** Every
thread starts with a simple timeline that groups articles by day and uses the
top-scoring article as each day's headline. If an AI provider is set up, a
nightly pass replaces it with a written title, a one-line summary and one line
per update. The simple timeline is accurate but shorter.

**Coverage** lists the thread's articles. The one that reported first is
tagged **first**. Repeats are collapsed under "*N* re-reports grouped".

**Nearest threads**, at the bottom, are similar stories. They open in the same
pane.

**Mark as read** at the top marks every article in the thread as read. That is
also how you clear a thread from the queue.

## "N new"

A thread row shows how many articles are new since you last opened it.
Opening the thread resets the count.

## Why an article isn't in a thread

- It has not been processed yet (see the delay above).
- It is very short, or it is a templated bulletin, such as Linux distribution
  errata or CVSS bulletins. Feeds like these publish hundreds of near-identical
  posts, so they are kept out on purpose.
- It is a roundup. "CISA adds three flaws to KEV" names different products
  each time, so grouping roundups would create a false story.
- It is the only article on its story so far. By default a thread needs at
  least three similar articles from at least two different outlets. One outlet
  posting four times still counts as one outlet.

If threads group articles that do not belong together, or miss ones that do,
an admin can tune them. The settings are in the developer page
[Story Threads](../story-threads.md).

Next: [The Workbench](workbench.md)
