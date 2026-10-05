# Notes and sharing

What you write down, who can see it, and what a share link gives away. Read [Share links](#share-links) before you send anything outside your team.

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

**Share** in the article reader, and **Share** on a copilot conversation in the copilot dock, each produce a public URL that works without a login. Reports and campaigns don't have share links; they leave as [exports](#exports).

Understand what that means: **the link is the access control.** Anyone who has it can open the page, and there's no viewer list or audit of who did. It's the right tool for sending a write-up to a partner org, and the wrong tool for anything you wouldn't send in plain email.

### What a shared article exposes

More than the article:

- the article text, its media and linked entities, and any detection rules extracted from it;
- **every note on that article**, whoever on your instance wrote it — notes have no private setting;
- the article's current AI results.

**Recipients can also run AI on it.** The shared page can run AI analysis and generation tasks and put questions to an AI agent about the article, with no login. Those calls run as *you*, the person who made the link, under your account and at your instance's AI cost. Each analysis task can run once per article, and its result is stored on the article, so it's then visible to everyone who can see that article's AI results, not only the person who triggered it. Questions put to the agent are answered and not stored, and there is no limit on how many a link holder can ask.

A shared copilot conversation is read-only and carries the whole thread, including whatever context was pinned when you asked. Re-read either one before sending.

**TLP does not gate sharing.** Reports and campaigns carry a TLP marking, which shows on a report's banner in exports, but nothing checks it when an article or conversation is shared — TLP:RED material shares like anything else. Holding back what's marked red is up to you.

### Expiry and revoking

The **Share** button creates a link that stays live until it's revoked; the app has no expiry picker. Underneath:

- **Reuse.** You have at most one active link per article. Share, and the CLI's `create_share_link`, hand back the one you already have if there is one, whatever its expiry, and only create a new link when you have none.
- **`ttl_days`.** The CLI's `create_share_link` tool accepts it, but it applies only to a link that call creates. Pass it for an article you've already shared and the existing link comes back unchanged: the expiry is not added, shortened or extended. Once a link's expiry passes it answers "expired" (HTTP 410) instead of showing the article.
- **An expired link still counts as active.** Share keeps handing it back, and recipients keep seeing "expired", until it's revoked. Revoke it, then share again for a fresh link.
- **Revoking** is through the API only (`DELETE /api/entries/{entry_id}/share`); there is no button in the app. A revoked link answers 404. You revoke your own link; an admin revokes everyone's for that article.
- **Links belong to the person who made them.** If two analysts share the same article each has their own link, and revoking one leaves the other working.

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
