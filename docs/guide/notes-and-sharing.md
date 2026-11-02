# Notes and sharing

This page covers writing notes, who can see them, what a share link gives away,
and how to export your work. Read [Share links](#share-links) before you send
anything outside your team.

## Notes

You can write a note on an article, on an entity, or on its own.

- **On an article:** press `n` in the reader. Use it for what you thought while
  reading.
- **On an entity:** use the notes section on the profile's Overview tab. Use it
  for analysis that outlives the article that prompted it.
- **On its own:** click **Notes** in the Reading sidebar. The same panel lets you
  browse every note on the instance.

Notes are written in Markdown. Article notes can be pinned and tagged, and all
notes are searchable (see the note filters in [Searching](searching.md)).

**Everyone on your instance can read every note.** Only the author or an admin
can edit or delete one. This lets a team build shared analysis, but keep it in
mind before you write something private.

## Comments

The app has no comment threads. Use notes for discussion as well as analysis.

## Share links

**Share** in the article reader, and **Share** in the copilot panel, each make a
public link that works without a login. Clicking Share copies the link. Reports
and campaigns have no share links; send them as [exports](#exports).

**The link is the only lock.** Anyone who has it can open the page, and there is
no list of who opened it. That is fine for sending a write-up to a partner, and
wrong for anything you wouldn't send in plain email.

### What a shared article exposes

More than the article:

- the article text, its media, its linked entities and any detection rules
  taken from it;
- **your own notes on that article**, including ones you add after sharing.
  Other people's notes on it stay inside your instance;
- the article's current AI results.

**People with the link can also use AI on it.** Without logging in, they can run
the article's AI analysis tasks and ask an AI agent questions about it. This
always runs on your instance's AI providers, never on anyone's personal key, and
is logged under the account of the person who made the link.

- Each AI task can run only once per article. Its result is saved on the article,
  so everyone who can see the article's AI results sees it.
- Questions to the agent are answered but not saved. A question can be up to
  4,000 characters, and the agent reads only the last 20 messages of the chat.
- Each link has a daily AI limit, 20 requests by default. An admin can change
  it under **Settings → AI Configuration → User keys → Share link daily limit**
  (0 means no limit). The count resets at midnight UTC.

A shared copilot conversation is read-only and shows the whole thread, including
whatever context was attached. Re-read it before you send it.

**TLP does not block sharing.** Reports and campaigns carry a TLP label, but
nothing checks it when you share an article or a conversation. Holding back
TLP:RED material is up to you.

### Expiry and revoking

- A link made with **Share** never expires. The app has no expiry setting.
- You have one link per article. Clicking Share again gives you the same link.
  Two people sharing the same article each get their own link.
- There is no revoke button. Revoking needs the API (see the sharing section of
  the [API reference](../api-reference.md)). You can revoke your own link; an
  admin can revoke every link for an article. A revoked link stops working.
- Links made through the CLI's `create_share_link` tool can have an expiry
  (`ttl_days`). An expired link shows "expired" and keeps counting as your link
  until it is revoked.

## Exports

Sharing is for people. Exports are files you can send anywhere.

| From | Formats |
|---|---|
| An article | Markdown (`e` in the reader) |
| Selected articles | Markdown ZIP (**Export**), or a research bundle with an IOC CSV and an ATT&CK layer (**Export Bundle**) |
| An entity or campaign | Markdown (**Export as Markdown** in the profile's **⋯** menu) |
| An entity's observables | CSV or STIX 2.1 (**Export CSV** / **Export STIX** on its Infrastructure panel) |
| A report | Markdown, HTML, PDF |
| Detection rules | Each rule in its own format, or a ZIP of many |
| The ATT&CK Matrix | ATT&CK Navigator layer (**Export Navigator JSON**) |

STIX 2.1 is a standard format other threat intel platforms can import. Use
Markdown when the reader is a person or a wiki.

## Read-aloud audio

The reader can turn an article into speech and play it in the audio player.
Making a share link also prepares the audio in advance, so the person you send it
to doesn't wait. Audio is stored for a while and then removed on its own.

Next: [Settings and personalising](settings.md)
