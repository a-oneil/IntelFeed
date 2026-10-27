# Reading and triage

This page covers the three panes, the reader, the keyboard, and how to get
through a big pile of unread articles quickly.

![The reader with an article open: entity links underlined in the body, an extracted summary above it, and the entry list beside it](../assets/screenshots/reader-article.png)

*An article open in the reader. Entities in the body are already linked, and
the summary above the text is made when the article arrives.*

## The layout

```
┌───────────────┬─────────────────┬──────────────────────┐
│  SIDEBAR      │  ENTRY LIST     │  READER              │
│               │                 │                      │
│  Reading ⇄    │  One row per    │  The article, with   │
│  Workbench    │  article        │  entities linked     │
│               │                 │                      │
│  Quick views  │  Day dividers   │  Intel / AI / notes  │
│  Saved        │  and summaries  │  panels beside it    │
│  searches     │                 │                      │
│  Feeds        │                 │                      │
└───────────────┴─────────────────┴──────────────────────┘
```

Drag the pane edges to resize them, or collapse the sidebar. On a phone the
panes stack (see [On a phone](#on-a-phone)).

## The sidebar

The **Reading / Workbench** switch at the top changes what the sidebar lists;
switching to Workbench takes you there. In Reading mode you get:

- **Quick views**: Priority Queue, Last 24h, This Week, Watched, Bookmarked
  and Starred.
- **Automation** and **Notes**: shortcuts to those pages.
- **Saved Searches**: see [Searching](searching.md).
- **Feeds**: your categories and feeds, with unread counts. The buttons above
  search your feeds, add a category, open **Ingest** (add content by hand), and
  add a feed (**+**).

Drag the sections to reorder them.

## The entry list

One row per article. Unread articles have a dot.

**Day dividers** split the list by day. Their chips sum up the day: actively
exploited CVEs mentioned, an entity first seen that day, the top technique, the
most targeted sector and the top CVE. Click a chip to filter that day by it;
the **?** chip explains them. A divider button marks the day read.

**Day summaries.** **Summarize day** (or **Catch me up** for today) asks the AI
for a short brief. The summary of the unfiltered list is shared: once anyone
makes it, everyone sees it, and **Regenerate** spends AI tokens again. A
summary of one feed or category is yours alone.

**Selecting several articles.** Tick the checkboxes, then use the toolbar:
**Mark Read**, **Mark Unread**, **Star**, **Bookmark**, **Tag**,
**Extract Intel**, **Export**, **Export Bundle**, **Summarize**,
**Ask Copilot**, **Report** and **Hide**. **Cancel** (or `Escape`) clears the
selection.

## The reader

The toolbar, left to right: previous and next, star, mark read, bookmark, the
intel panel, the AI panel, notes, tag, ask the copilot, text size, and **More**
(**Export**, **Share**, **Find in article**, **Read aloud**,
**Translate to English** and **Open original**).

**Linked entities.** Hover or click a highlighted name for a card with a
summary and **Profile** (open its page),
**Search**, **Copy**, **Enrich** and **Wrong?**. This is the main way to move around.

**Panels.** `w` opens the intel panel: everything linked to this article, with
**Extract All**, **Gen Rules** (draft detection rules) and **+ Campaign**. `a`
opens the AI panel (summary and analysis). `n` opens your notes.

**Find in article.** `Ctrl+F` / `⌘F` searches inside the open article.

**Read aloud.** With the **Natural voice (server)** setting, the server makes
the audio: the first play takes a few seconds, later plays start at once. If
that fails, the browser's own voice reads it. Switch voices in
**Settings → Reading**.

### If something is linked wrongly

Linking is sometimes wrong, such as "apt" in a sentence about package
managers. Open the entity's card and click
**Wrong?**. The options go from narrow to wide:

- **Wrong for this article**: removes this one link.
- **Not a name for …**: the matched alias isn't a real alias for this entity.
  Shown only for alias matches.
- **Wrong type — convert**, **Duplicate — merge into…** and
  **Unlink from every article**: admins only.
- **Never match "…" anywhere**: this word is never linked again, to any entity.

Pick the narrowest option that's true. These choices change future linking.

For an observable (an IOC such as an IP, domain or file hash), the menu offers
**Wrong for this article — remove sighting**, and for admins
**Never capture "…" — tombstone**.

## Keyboard

| Key | Action |
|---|---|
| `j` / `↓` | Next entry |
| `k` / `↑` | Previous entry |
| `o` / `Enter` | Open the original article |
| `s` | Star / unstar |
| `b` | Bookmark / remove bookmark |
| `m` | Toggle read / unread |
| `Shift+M` | Mark everything above the current entry as read |
| `t` | Tag this entry |
| `e` | Export as markdown |
| `w` | Intel panel |
| `a` | AI panel |
| `n` | Notes panel |
| `/` | Search |
| `Ctrl+K` / `⌘K` | Command palette |
| `Ctrl+Shift+K` / `⌘⇧K` | Open or close the copilot |
| `Escape` | Close the reader, search or panel |
| `?` | Show the shortcuts in the app |

Learn `Shift+M`: skim with `j`, stop at the first article you care about, press
`Shift+M`, and everything you skipped is marked read.

## Starred vs bookmarked vs tagged

- **Star**: "I'm coming back to this today."
- **Bookmark**: "This is a reference I'll want in a year."
- **Tag**: a searchable label, such as `to-rule` or `false-positive`. Saved
  searches are often built on tags.

**Settings → Tags** lets you rename, recolour and merge tags, such as `to-rule`
and `to_rule`.

## Clearing a big inbox

Two hundred unread and twenty minutes:

1. Start in the **Priority Queue**, ranked by what's likely to matter. See [Priority Queue and watching](priority-queue.md).
2. Work down with `j`. Star anything worth a proper look.
3. Switch to **Last 24h** and read the day summaries and divider chips instead
   of the articles.
4. Go to the bottom and press `Shift+M` to clear the rest (or use the divider's
   mark-day-read button).
5. Open **Starred** and do the real work there.

## On a phone

Swipe right from the left edge to open the sidebar, and left to close it. Tap
an article to open it full-screen; swipe right from the left edge to go back.
Swipe left on a row for star, bookmark and mark-read buttons. Pull down to
refresh.

Use a phone for sorting: star what deserves a look and mark the rest read.

Next: [Searching](searching.md)
