# Notes and sharing

What you write down, and who can see it.

## Notes

Notes attach to three things: an article, an entity profile, or nothing at all.

- **On an article** — `n` in the reader. What you thought while reading it.
- **On an entity** — the Notes tab of any profile. Analysis that outlives the
  article that prompted it. Entity notes are typed (analysis, assessment and so
  on) so a profile's notes read as a body of work rather than a pile.
- **Standalone** — the **Notes** panel, reached from the sidebar in Reading
  mode, for anything that doesn't belong to one object yet. The same panel
  browses every note on the instance.

Notes are markdown, they're pinnable, they can carry tags, and they are fully
searchable — see the note filters in [Searching](searching.md).

**Notes are shared across the instance.** Anyone on your instance can read any
note. Only the author (or an admin) can edit or delete one. This is a feature —
it's how a team builds shared analysis instead of five private notebooks — but
know it before you write something you'd rather keep to yourself.

## Comments

Comments are threaded discussion on an object, as opposed to notes, which are
analysis. Use comments for "should we escalate this?" and notes for "what this
group does".

## Share links

**Share** on an article, report, campaign or copilot conversation produces a
public URL that works without a login.

Understand what that means: **the link is the access control.** Anyone who has
it can read the thing. There's no expiry gate, no viewer list, no audit of who
opened it. It's the right tool for sending a write-up to a partner org, and the
wrong tool for anything you wouldn't send in plain email.

TLP is honoured — TLP:RED material doesn't generate a link — but TLP only helps
if you set it honestly.

A shared article link carries the article and its linked entities. A shared
copilot conversation carries the whole thread, including whatever context was
pinned when you asked, so re-read it before sending.

## Exports

Where sharing is for people, exports are for systems.

| From | Formats |
|---|---|
| An article | Markdown (`e` in the reader) |
| A campaign | Markdown, CSV, MISP, STIX 2.1 |
| A report | Markdown, HTML, PDF, MISP, STIX 2.1, CSV |
| Detection rules | Native format per rule, or an ATT&CK Navigator layer |
| Search results | CSV |

STIX and MISP are the ones to reach for when the destination is another
platform; markdown when the destination is a human or a wiki.

## Read-aloud audio

The reader can synthesise an article and play it through the shared player, and
share links pre-generate the audio so a recipient isn't waiting on it. Audio is
cached and expires on its own, so nothing accumulates forever.
