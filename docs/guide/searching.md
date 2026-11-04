# Searching

This page covers the search box, the results page, filters and saved searches.
By the end you can find any article, entity or note, narrow the results, and
save a search to come back to.

There is one search box, in the header on every page. Typing in it opens the
results page at `/search`.

![Search results for ransomware showing direct entity matches, grouped actors and malware, and a faceted filter rail](../assets/screenshots/search.png)

*One query returns both articles and entities, with filters to narrow by type.*

## The basics

Press `/` to jump to the search box. Then type what you're looking for:

- `ransomware` finds articles that mention it.
- `APT29` finds articles about APT29, and the APT29 entity itself. (An
  *entity* is a named thing IntelFeed tracks: a threat actor, malware, CVE and
  so on. See [Entities and profiles](entities.md).)
- `CVE-2026-1234` finds that CVE (a public ID for a software flaw) and
  everything linked to it.
- `LockBit builder` finds articles containing both words.

## Scope

The search box has a scope chip that reads **in: everything**. Click it, or
press **Tab** in the box, to cycle through the three scopes:

| Scope | Results |
|---|---|
| Everything | Entities and articles |
| Workbench | Entities only |
| Feeds | Articles only |

The scope only changes what the results page shows. It starts on
**everything**, then stays where you put it, whichever page you search from.

## Direct matches vs mentions

Entity results come in two groups.

- **Direct matches** are entities whose name, alias or ID matches what you
  typed. Searching `lockbit` shows the LockBit group itself. The top one is
  opened up so you can read it straight away.
- **Mentions** are entities that only talk about it, such as other actor
  profiles or detection rules that refer to LockBit. They are grouped by type
  below the direct matches.

Articles that match are listed too, when the scope includes them.

## The filter rail

The rail on the left narrows the results. It has the scope, entity type (with
counts), **Matched on**, and, for articles: a date range, **State** (Unread,
Starred, Bookmarked, Has notes), **Feed**, **Content type**, **Tags**,
**Media** and **Language**.

Every box you tick is written into the search box as a filter. Tick
"Last 7 days" and "Unread" and the box gains a `date:` filter and `is:unread`.
You can see exactly what the rail did, edit it by hand, and save it. Clicking
around the rail is a good way to learn the query syntax.

On a phone, the rail opens from the **Filters** button.

## Field filters

You can mix free text with field filters. Some useful ones:

```
feed:nvd cve.severity:critical
# NVD articles that mention a critical CVE

threat_actor:APT29 date:>2026-01-01
# APT29 articles from this year

cve.kev:true cve.epss:>0.5
# Known to be exploited, and likely to be attacked

signal:under_reported sort:radar
# Stories IntelFeed thinks are under-covered, in priority order

rule.data_source:sysmon rule.tactic:persistence
# Persistence detection rules that use Sysmon logs

category:"Vendor Blogs" is:unread
# Unread articles from one feed category

is:starred NOT type:youtube
# Your starred articles, minus videos
```

The box suggests field names and values as you type. On the results page, the
**?** button opens the syntax help and **Builder** opens a visual query
builder. [Query language](../query-language.md) is the full reference.

`sort:radar` orders results by priority score, the same ranking the
[Priority Queue](priority-queue.md) uses.

## Your notes are searchable

Notes show up as their own group of results. That includes notes on
articles, notes on entity profiles, and standalone notes from the Notes panel.

Each note result shows the sentence that matched, not the note's first line.
A note on an entity with no title is named after its subject, for example
"Note on CVE-2026-20262".

```
note:fortibleed          # title or body
note.tag:followup        # by tag
note.about:cve           # notes on CVEs
note.about:entry         # notes on articles
note.about:standalone    # notes not attached to anything
note.pinned:true         # pinned notes only
note.type:analysis       # entity notes of one type
```

`note.about:entry` also returns the articles the notes are on.

**Notes are shared.** Search shows notes written by anyone on the instance.
Only the author or an admin can edit or delete a note, but everyone can read
it.

## The command palette

Press `Ctrl+K` (or `⌘K` on a Mac) to open the command palette. With nothing
typed, it lists the entities and pages you visited recently, then every
command, grouped as **Run**, **Create**, **Go to**, **Browse** and **Manage**.
Type to filter the list, for example "add feed", "create rule", "threat
actors" or "tags". Admins also see admin pages such as the Engine console and
Feed health.

## The rule library has its own search

**Workbench → Rules Library** has its own search, because there the rules are
the whole subject. You can filter by **Rule format**, **Severity**,
**Source repo**, **ATT&CK tactic**, **Technique**, **Threat actor**,
**Malware**, **Tool**, **Vendor**, **Product**, **Telemetry**, **Tags** and
**License**. The counts update as you filter. Ticking two values in the same
group shows rules that match either one.

Use `rule.` filters in the main search box when you want rules mixed with other
results. Use the library when rules are the work. See
[Writing detection rules](detection-rules.md).

## Saved searches

Run a query, click **Save**, and give it a name. It appears under
**Saved Searches** in the sidebar.

```
tag:to-rule is:unread                    # flagged for rule work, not yet read
category:"Vendor Research" is:unread     # one category, unread only
type:youtube OR type:podcast             # things to watch or listen to
signal:under_reported                    # what IntelFeed thinks is under-covered
```

The number next to a saved search is worked out in the background, so it can
lag behind, and it stops counting at 5,000. Opening the saved search always
runs the real query, so the results themselves are always current.

Next: [Entities and profiles](entities.md)
