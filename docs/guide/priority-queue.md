# Priority Queue and watching

The Priority Queue is the same articles as your inbox, ranked by how likely they
are to matter. It's the answer to "I have four hundred unread and twenty
minutes."

Open it from the sidebar, or search with `sort:radar` for the same ranking
inside any query.

## What it looks like

It is a normal entry list and reader — same keys, same actions — pinned to the
priority ranking instead of date order. Two things are different:

**A "Why" card** sits with each article, above the table of contents, listing
the signals that lifted it and what each one contributed. The ranking is never a
number you have to take on faith; it always shows its work.

**Story rows** appear inline when several outlets are covering the same thing.
Rather than showing you the same story five times, the queue folds it into one
row you can open — and the articles inside it are withheld from the list, so
the story appears once, not once per outlet. A story ranks by its best unread
article plus a bump for each extra outlet carrying it, because corroboration
across newsrooms is itself a signal. A story you have finished reading drops
out of the queue entirely.

## What the ranking looks at

Signals fall into five families. None of them is "this article is important" —
each is a specific, checkable observation:

**Novelty** — is this new?
- *novel entity* — first, or nearly first, mention of an actor, malware or tool
- *entity resurgence* — something resurfacing after a long silence
- *new pairing* — two entities appearing together for the first time
- *scoop* — the source that broke it

**Coverage** — who else is saying it?
- *source convergence* — independent outlets landing on the same story
- *under-reported* — real substance, barely covered
- *feed echo* — the opposite: everyone syndicating one piece

**Severity** — how bad, concretely?
- *KEV added* — a CVE entered CISA's known-exploited catalogue
- *EPSS jump* / *EPSS high* — exploitation probability rising, or already high
- *weaponised PoC* — working exploit code exists
- *critical CVSS*

**Interest** — does this match *you*?
- *PIR match* — it hits one of your intelligence requirements
- *correlation event* — it connects to something you're already tracking

**Content** — is there anything to act on?
- *detection content* — the article contains rules or detection logic
- *research depth* — substantive analysis rather than a news blurb

`signal:under_reported`, `signal:kev_added` and the rest work as search filters,
so any signal can become a saved search.

## Steering it

The queue learns from you, in two ways you control directly.

**Watch and mute.** From any entity profile's **⋯** menu. Watched entities lift
their articles and surface them even below the normal threshold; muted entities
disappear from the queue entirely (but not from search or the feed list). Both
are per-user. This is the biggest lever you have, and the most underused — watch
your vendors, your products, and the actors that go after your sector.

**Thumbs.** The queue asks whether a ranking was right. Everyone's votes
together nudge the shared ranking by at most ±10%, which is deliberate — a
handful of votes should not swing what the whole instance sees.

If your administrator has enabled **Personalised Radar**, you can additionally
opt in under Settings → Reading → *Your Radar*, and then your own votes fit a
personal weight per signal family: if novelty rankings keep wasting your time
and KEV rankings keep earning it, your ordering shifts. It only ever *re-orders*
your queue — it never hides an article the shared score put above the line, and
the panel shows each family's weight, the votes behind it, and both ways out
(switch off, or discard the fitted weights).

**Intelligence requirements.** *PIR match* is the one signal whose meaning you
define. Write your standing requirements under **Workbench → Requirements** —
the sectors, regions, technologies and actors you are actually responsible for
— and articles matching them rise. If you do one piece of setup beyond watching
entities, do this.

One caveat worth knowing: the engine weights every signal by how *rare* it is,
so a signal that fires on half the queue contributes almost nothing. If your
requirements are written broadly enough that most articles match, PIR match
stops distinguishing anything. Narrow requirements are worth more than many.

## Working it

1. Open the Priority Queue and read the top of the ranking, not the whole list.
2. For each, read the Why card before the article. It often answers the question
   on its own — "EPSS jumped from 0.04 to 0.71" is frequently the whole story.
3. Star what needs real work. Mark the rest read.
4. Thumbs-down anything that clearly wasted your time, so it happens less.
5. When the ranking stops being interesting, stop. That's the signal the queue
   exists to give you; there's no prize for reaching the bottom.

Give the thumbs a couple of weeks before deciding the ranking is wrong for you.
It's adjusting weights from a small number of judgements at first.
