# The Threats board

How to use **Workbench → Threats** to decide what to write a detection for this week. It ranks what was *recently reported* by attention and new tradecraft, gives each row one job to do, and shows its working. After this page you should be able to read a row, know why it ranks where it does, and know what its button will do.

![The Threats board listing ranked threats with story and outlet counts and draft-detection-rule actions](../assets/screenshots/threats-board.png)

## The controls

- **Tabs — All, Actors, Malware, Vulnerabilities.** The first three are the same board filtered by what the row *is*; Vulnerabilities is its own view (below). The tab is in the URL (`?tab=`), so you can bookmark one.
- **Window — 7d, 14d, 30d.** How far back "recently reported" reaches. Everything on the board, including a row's rank, is computed over this window.
- **Open / Handled.** Open is the default. **Mark handled** on a row moves it to Handled; it comes back by itself if new tradecraft arrives, so handled means "dealt with as of now", not "ignore forever". **Reopen** puts a handled row back.

## Reading a row

A collapsed row is four things: who or what it is, the story, one quiet line of facts, and a button.

**The story** is a short summary of what was reported. When the nightly AI brief exists for that threat it's shown — written only from the articles in the window. Otherwise you get the lead headline, quoted, with its outlet and whether that outlet was first. It is never a sentence the board assembled from numbers.

**The facts line** reads like `3 stories · 17 articles · 6 duplicates hidden · 4 rule-ready indicators · 2 rules name it · +1 weak`. Stories and articles differ because the board counts *stories*, not outlets: a wave of re-reports is one story, folded and counted rather than ranked as if it were many. See [Story threads](story-threads.md).

**The button** is named for the job, worked out from what the rule library already holds:

| Button | What it means |
| --- | --- |
| **Draft detection rule →** | Nothing in the library covers this. Draft one from the reported tradecraft |
| **Extend *N* rules →** | Rules already name this threat. Add the newly reported techniques |
| **Check *N* weak matches →** | Only loosely matching rules exist. Compare them against what was reported |
| **Audit *N* known TTPs →** | Coverage looks current. Audit it against everything on record |
| **Adopt *N* ready rules →** | Matching rules can run on the telemetry you collect today |
| **Rules need telemetry →** | Rules exist, but they need log sources you don't collect yet |
| **Read the story →** | A story with no actor, malware family or CVE named yet. Read it and identify it |
| **Send to merge** | This row duplicates another threat |

The button opens the threat's profile — for a CVE, straight to its **Detection** tab — where the coverage view and the [rule tools](detection-rules.md) live; the label tells you which job to do when you get there. A story row opens its thread instead (below). *Adopt* and *Rules need telemetry* depend on your [Telemetry Sources](workbench.md) being filled in — without them the board can't tell "can run" from "can't".

## The drawer

Click a row to expand it. Three columns:

- **Articles** (or **Coverage**, when stories were folded): the articles behind the row, with their outlet and date, how many techniques each carries, and a link to open each in the reader or at the source.
- **New this window**: the techniques that weren't known for this threat before the window began. This is what *new tradecraft* means on this board.
- **Why this rank**: the score and where it came from — stories, outlets, new tradecraft, rule-ready indicators, and the rule inventory split into rules that *name* the threat and weak matches, with the repositories they came from. Nothing is hidden behind the number.

For a threat with a story behind it, the drawer can also show **Precedent**: the closest earlier story, as a percentage match, so you can ask "have we seen this shape before?"

There is deliberately **no coverage percentage**. Counting how many of a group's techniques some rule is tagged with comes out around 90% for nearly every actor, which says nothing. The inventory of rules is there to open, not to be read as a verdict.

A row marked *held out of the ranking — a category, not a threat* is a genre word the extractor mistook for an entity. Resolve it from entity hygiene in the Engine console; it isn't a threat to chase.

## Stories with no name yet

Not every story resolves to an actor, malware family or CVE. If one carries something you could still act on — a technique, an observable, or a product in your stack — it gets a row anyway, tagged as a story. Its button is **Read the story →**, and it opens the thread in a reader docked beside the board, so you don't leave the board. The same thread is also in the [Priority Queue](priority-queue.md). It has no rule inventory, because there's nothing to look rules up against until something names it.

## The Vulnerabilities tab

CVEs ranked by exploitation rather than by who reported them. A CVE's rank is lifted by evidence it's being used: known-exploited in CISA's KEV catalogue lifts it most, then a high EPSS score, then a known exploit — the drawer shows the exact multiplier for the row in front of you. A threat in a product you run is lifted further.

"A product you run" comes from your **stack**:

- **Manage stack** (top right of this tab) opens a panel to follow vendors and products. Until you've followed any, the tab says so and ranks the whole landscape, because nothing can sort onto your surface until it knows what you run.
- Once there's a stack, four tiles run across the top: how many are **new this week in vendors you follow**, how many are **actively exploited** (CISA KEV or weaponized), how many have **no rule resolving to them** in the library, and which CVE is **trending now** by mentions.
- **The long tail — your stack, exhaustive** sits under the ranked board and lists everything for your stack, not just what made the cut.

## Where to go next

- Following a threat into a rule: [Writing detection rules](detection-rules.md).
- The same ranking idea applied to *articles* rather than threats: [Priority Queue and watching](priority-queue.md).
- Grouping a threat into an investigation: [Campaigns and reports](campaigns-and-reports.md).
