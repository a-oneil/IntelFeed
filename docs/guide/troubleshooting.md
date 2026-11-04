# When something isn't working

Common problems and what to do about them, most frequent first. Some fixes
need an admin; those are marked.

![The Engine console showing per-entry pipeline stages, from translate and autolink through scoring, AI analysis and adjudication](../assets/screenshots/engine.png)

*The Engine console shows what each processing step did with each article.*

## A feed stopped producing

A dead feed looks just like a quiet week, so check rather than wait.

1. On the dashboard, the **Feed Activity** and **Feed Health** widgets show
   it. A bar that drops to zero and stays there is your answer.
2. Admins: **Settings → Engine**, **Feeds** view, shows each feed's last
   successful fetch, its errors and how reliable it has been.

The usual causes: the site moved its feed, a scraped site was redesigned, or a
login expired. Fix the URL in the feed's settings. For a scraper, check whether
the site now offers a real feed and switch to it. See
[Adding and managing feeds](feeds.md).

## An entity is linked to the wrong thing

For example "apt" in a sentence about package managers, or a product name that
is also an ordinary word. Open the entity's card in the reader, click
**Wrong?**, and pick the narrowest option that's true. See
[If something is linked wrongly](reading-and-triage.md#if-something-is-linked-wrongly).

These choices change future linking, so the widest option isn't the safe
default.

## There are two pages for the same thing

Admins: open the **⋯** menu on either profile and choose **Merge…**. The
articles, relationships and aliases move onto the page you keep. You can only
merge two entities of the same type.

If the *type* is wrong (say, something saved as a tool that is really a
product), choose **Convert type** instead. Convert stops the AI from
re-creating the wrong version.

If you delete an entity, tick **Don't re-create it** in the delete dialog.
Without it, the AI or the autolinker may bring the entity back.

## An automation rule stopped firing

Admins: **Settings → Logs**, **Automation** tab, shows every run. Two things to
check:

- Look at each **action's** status, not only the run's overall result. A run
  can succeed while one of its actions fails.
- Check that the conditions still match. A rule that names a feed breaks when
  the feed is renamed.

Before you turn an edited notification rule back on, make sure it won't send
one message per article. That can flood a channel.

## The copilot isn't answering

- **A sign-in prompt in the copilot panel**: the AI service's sign-in has
  expired. An admin can sign in again at **Settings → AI Configuration**, with
  **Re-authenticate** on the Claude Code CLI provider's **Copilot
  authentication** card.
- **No provider set**: an admin needs to give the copilot task a provider
  and model under **Settings → AI Configuration → Prompts**.
- **Answers with no tool chips**: the copilot answered from the AI model's
  general knowledge, not from your data. Ask again more specifically. If it
  still doesn't use tools, the provider may not support tool calling.

## Search returns nothing for something I can see

- Check the **scope chip** in the search box. It may be limited to entities or
  to articles. Press **Tab** in the box to change it.
- Check the filter rail. Filters you picked earlier are written into the query
  and stay there.
- If one article is truly missing from search, the search index has fallen out
  of step. IntelFeed repairs this by itself: failed articles are retried every
  five minutes, and a full check runs every night. Usually you only need to
  wait. Admins can run the **reconcile-meilisearch** job straight away from
  **Settings → Engine → Jobs** with **Run now**.

## A saved search shows the wrong count

The number next to a saved search is worked out in the background, so it can
lag behind new articles. It also stops counting at 5,000. Open the saved
search to run the real query and see the right results.

## Entity profiles are empty

There are two different causes:

- **New instance**: profiles build up over time. They're thin on day one and
  useful by the end of the month. Nothing is wrong.
- **Enrichment off**: a CVE page with no severity or KEV status means the
  enrichment sources are off. An admin turns them on at
  **Settings → Engine → Enrichment**. NVD, EPSS and CISA KEV matter most.

## The Priority Queue ranks badly for me

It needs steering:

- **Watch** the entities you're responsible for, and **mute** the ones that
  are noise to you (both on the entity's profile). This is the biggest lever,
  and the least used.
- **Write your intelligence requirements** (the standing questions you need
  answered) at **Workbench → Requirements**. Articles that match them rank
  higher.
- **Vote** with ▲ and ▼ on queue items to teach the ranking what is useful.

Give it a couple of weeks before deciding it's wrong. See
[Priority Queue and watching](priority-queue.md).

## Images aren't loading

If the image proxy is on, the first view of an image is slower while your
server saves a copy. If the original image changes, you still see the saved
copy until it expires.

## Enrichment says rate limited

Each enrichment source has a limit on how many requests it accepts, and some
have a daily budget. A request over the limit waits a moment for room; if
there is none, the lookup stays queued and runs once the source has room
again (after a spent daily budget, the next UTC day). A source that answers "too many requests", or
keeps failing, is paused for a while (its own Retry-After time, or a minute
and growing). Scheduled jobs wait longer for room; when a source refuses
them they stop, keep what they did, and continue on their next run (the run's
details in the Jobs view say `stopped`). NVD's public API is the usual cause. If it happens all the time,
an admin can add an **NVD API Key** under **Settings → Engine → Enrichment →
Keys** to raise the limit.

## Still stuck

Ask the copilot on the [documentation home](/documentation). It can search
these pages and the developer documentation. (On GitHub, start from the
[docs index](../README.md).)

Back to the start: [Using IntelFeed](README.md)
