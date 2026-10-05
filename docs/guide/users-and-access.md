# Users and access

For whoever runs an instance for more than one person: how accounts get created, how to lock registration or gate it with an invite link, how to manage accounts, and what changes when each analyst keeps their own feed list. Everything here is under **Settings**, and everything except the first part is admin-only.

## Roles

There are two: **user** and **admin**.

Anyone can read everything, write notes, build campaigns and reports, save searches and write detection rules. Admins additionally manage feeds, AI configuration, users, the engine and system settings — see [Getting started](getting-started.md#your-account).

The **first human account** registered on a fresh instance becomes the admin; everyone after that is a user. (A built-in `system` service account, used for attribution on automatic work, never counts as "first" and never appears in the user list.) Promote a colleague to admin from **Settings → Users**.

## Controlling registration

**Settings → Users** has two settings at the top:

- **Account Registration** — on by default. Turn it off to lock the instance: the register page refuses with "Account registration is currently disabled". There is no "add user" button — accounts only come from the register page — so to add someone to a locked instance, turn registration back on while they sign up.
- **Invite Code** — a code the register page asks for. Leave it empty and anyone who can reach the register page can sign up; set it and registration needs the code.

Once a code is set, **Copy Invite Link** puts a link on your clipboard — your instance's `/register` page with the code already filled in. Send that instead of the bare code.

The code is one shared secret for the whole instance, not one per person. Anyone holding the link can register until you change the code or turn registration off, so send it the way you'd send a password, and change it after a batch of new people has joined.

## Managing accounts

**Settings → Users** lists every account with its **role**, **status** (Active or Inactive), how many **feeds** it subscribes to, **last login** and **created** date. For each:

- **Edit** — change the username, role, active state, or set a new password (six characters minimum).
- **Delete** — permanently removes the account, with a confirmation step.

Inactive accounts can't log in, and a session that's already open stops working on its next request. That makes **Inactive** the right tool for someone who has left, when you want to keep their name on the notes and comments they wrote; delete only when you're sure.

You can't lock yourself out: an admin can't remove their own admin role, deactivate their own account or delete their own account. Ask another admin.

## What's personal and what's shared

- **Personal:** each person's read, starred and bookmarked state, their personal tags, their saved searches, and their dashboard layouts.
- **Shared across the instance:** entities and their profiles, notes, the feeds and their articles, and campaigns. Anyone can *read* any note; only its author or an admin can edit it ([Notes and sharing](notes-and-sharing.md)).
- **Tags** come in two kinds: a *global* tag is one assignment everyone sees, a *personal* tag is yours alone ([Settings and personalising](settings.md)).

## One feed list, or one per person

By default there's a single shared feed list: a feed an admin adds is read by everyone, and **muting** a feed hides it from everyone.

Turn on **per-user feed subscriptions** (admin; **Settings → Engine**, in the Feeds view, the setting labelled *Per-user feed subscriptions*) and each analyst gets their own list over the shared pool. Then:

- **Muting and unsubscribing are personal.** Removing a feed as a non-admin only unsubscribes *you*; the feed and its articles stay for everyone else. A feed with no subscribers stops being fetched. An admin can still delete a feed outright by purging it.
- **Any user can import an OPML file**, and the feeds they import subscribe them (otherwise importing is admin-only).
- **The Feeds column in Settings → Users** shows how much of the shared pool each account reads, with a count of muted feeds.
- **New accounts** start subscribed to the instance's default list — the earliest admin's subscriptions.

**Check your muted feeds before you switch it on.** While the setting is off, muting a feed changes the shared feed only. Each person's personal list was copied from the shared state once, when per-user subscriptions were installed, and has not tracked it since. So turning the setting on is not a no-op if anyone has muted a feed in the meantime: that feed reappears for everyone, and from then on personal lists drift apart. Note which feeds are muted first, and re-mute what should stay muted afterwards.
