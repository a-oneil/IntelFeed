# Users and access

This page is for whoever runs an instance for more than one person: sign-up,
invites, accounts, browsing without an account, and per-person feed lists.
Everything here is under **Settings → Users** and is admin-only, except the
first section.

## Roles

There are two roles: **user** and **admin**.

Everyone can read everything, add feeds, write notes, build campaigns and
reports, save searches and write detection rules. Admins can also manage and
delete feeds, and control AI configuration, users, the Engine and system
settings. See [Getting started](getting-started.md#your-account).

The **first person** to register becomes the admin; everyone after is a user. A
built-in `system` account signs automatic work and never appears in the user
list. To make a colleague an admin, edit
their account in **Settings → Users**.

## Controlling registration

**Settings → Users** has three switches at the top:

- **Account Registration**: on by default. Turn it off to lock the instance;
  the register page then says "Account registration is currently disabled".
  There is no "add user" button. To add someone to a locked instance, turn
  registration on while they sign up, then off again.
- **Invite Code**: a code the register page asks for. One is created when the
  first account registers. Clear it and anyone who can reach the register page can sign up.
- **Public read-only mode**: see [below](#letting-people-browse-without-an-account).

When a code is set, **Copy Invite Link** copies a register link with the code
filled in. Send that instead of the bare code.

The code is one shared secret, valid until you change it or turn registration
off. Send it like a password and change it after a group has joined.

## Managing accounts

**Settings → Users** lists every account with its **Role**, **Status** (Active
or Inactive), **Feeds** (how many it subscribes to), **Last Login** and
**Created** date. For each one:

- **Edit**: change the username, role or active state, or set a new password
  (at least six characters).
- **Delete**: removes the account for good, after you confirm.

An inactive account can't sign in, and an open session stops working on its
next request. Make someone **Inactive** when they leave to keep their name on
their notes.

An admin can't remove their own admin role, or deactivate or delete their own
account. Ask another admin.

## Letting people browse without an account

**Public read-only mode** (off by default) lets anyone who can reach the
instance look around without signing in.

Visitors see articles, entity profiles, story threads and the built-in
dashboards. They can't change anything, run AI, or see private work such as
notes, campaigns, detection rules, observables and reports. The header shows
**Sign in** in place of search, the copilot and Settings.

Turning it on publishes nothing by itself, because every feed starts hidden
from visitors. To show a feed, tick **Visible to visitors** in its **Readers**
pane. Manual uploads are never shown.

Full details: [Public read-only mode](../public-read-only-mode.md).

## What's personal and what's shared

- **Personal:** your read, starred and bookmarked state, the entities you
  watch, your saved searches and your dashboard layouts.
- **Shared:** entities and profiles, feeds and articles, notes and campaigns.
  Anyone can *read* any note, but only its author or an admin can edit it
  ([Notes and sharing](notes-and-sharing.md)).
- **Tags:** tag names are shared. A *global* tag has one set of assignments
  everyone sees; a *personal* tag's assignments are yours alone
  ([Settings and personalising](settings.md#tags)).

## One feed list, or one per person

By default there's one shared feed list: a feed anyone adds is read by
everyone, and **muting** a feed hides it for everyone.

To give each analyst their own list from the shared pool, an admin turns on
**Per-user feed subscriptions** (**Settings → Engine**, **Feeds** view). Then:

- **Muting and unsubscribing are personal.** A non-admin who removes a feed is
  only unsubscribed; the feed stays for everyone else. A feed with no
  subscribers stops being fetched. An admin can still delete a feed for
  everyone.
- **Any user can import an OPML file** into their own list.
- **The Feeds column in Settings → Users** shows how many shared feeds each
  account reads and has muted.
- **New accounts** start with the same subscriptions as the earliest admin.

**Check your muted feeds before you turn it on.** Mutes made while the setting
is off aren't recorded on anyone's personal list, so those feeds show up again
for everyone. Note which feeds are muted first, and mute them again afterwards.

Next: [When something isn't working](troubleshooting.md)
