# Automation and AI

Two ways of getting work done without doing it: rules that run on their own, and
a copilot you can ask.

## Automation rules

**Sidebar → Automation → + New.** A rule is a trigger, optional conditions, and
one or more actions.

**Triggers**

- when a new article arrives
- on a schedule
- when a keyword matches
- when a CVE is linked
- manually, from a button

**Conditions** narrow it: the feed, words in the content, severity, whether it's
starred or tagged, whether a mentioned entity is on your watchlist.

**Actions** are the point:

- extract TTPs, CVEs, actors or malware
- generate detection rules
- add tags
- notify — Slack, Discord, Teams, email, webhook
- add to a campaign
- mark read, starred, bookmarked, or prioritised
- create a note from a template

Webhook URLs live on the notification action inside the rule, not in a separate
settings page.

### Worked example

> **Auto-Sigma on critical CVE**
> Trigger: a CVE is linked
> Condition: CVSS ≥ 9.0
> Actions: extract TTPs → generate a Sigma rule → tag `auto-rules` →
> post to Slack

Now a critical CVE landing produces a draft rule in your library and a message
in the channel, and someone reviews it in the morning.

### Before you enable it

**Dry-run first.** Rules have a test mode that runs against recent entries and
shows what would have happened. Use it. A rule that notifies is a rule that can
flood a channel, and the distance between "fires twice a day" and "fires two
hundred times a day" is one condition you forgot.

Be especially careful with batch rules — a rule you expected to send one digest
can instead act per-article. Check the dry-run output count, not just that it
succeeded.

**Watch the logs.** **Settings → Logs** shows every run: rule, time, whether
conditions matched, which actions ran, and errors. When an automation seems to
have stopped, check per-action status rather than the run's overall result — a
run can report success with one action quietly failing inside it.

## The copilot

The chat panel that docks on the right of every page. Open it from the header or
with `Ctrl+Shift+K` / `⌘⇧K`.

It has tools. It isn't answering from memory — it searches your entries, looks
up entities, pivots, and reads the documentation, and it shows you a chip for
every tool call as it works, so you can see where an answer came from. If an
answer has no tool chips behind it, treat it as the model talking rather than
your data talking.

**Context.** A pill shows what it's looking at — the open article, the entity
profile, the campaign — based on where you are. **Ask Copilot** buttons around
the app open it pre-scoped to one thing. Dismiss the pill to ask instance-wide
questions instead.

**Writes need confirmation.** It can propose creating a campaign or adding a
note. Both surface a confirmation card, and nothing is written until you accept.

**Conversations** are saved and resumable, and can be shared as a public link.

**On the documentation page** there's a second, smaller copilot that answers
from these guide pages and the developer docs — good for "how do I…" and "where
does X live", and it cites the page it used.

Things it's good at: "what's trending in the last 24 hours", "summarise what we
have on this actor", "which CVEs in our feeds are known-exploited", "draft a
Sigma rule from this article". Things to check rather than trust: anything
numeric, anything attributive, anything you're about to put in a report.

## AI features elsewhere

- **Article summaries** in the entry list.
- **Daily summaries** on day dividers — shared instance-wide, so regenerating
  one spends tokens for everyone.
- **Entity extraction** at ingest, which is what fills profile pages.
- **The AI panel** (`a`) in the reader for questions about the open article.
- **Report and rule drafting**, covered in their own pages.

## Providers and cost (admin)

**Settings → AI Configuration**, three tabs: **Providers** (which model runs
what), **Prompts** (the prompt behind each task, editable), and **Cost**.

You can run entirely locally on Ollama, on a hosted API, or mix — different
tasks can go to different providers, which is how you put cheap bulk work on a
local model and keep the expensive model for analysis.

The Cost tab shows tokens and spend per provider and task. One caveat: where the
copilot runs on a flat-rate sign-in, its dollar figures are notional — what the
tokens *would* cost at API rates, not a charge you'll see. The real limit there
is the plan's quota.

Prompts are editable, and editing them is the highest-leverage thing an admin
can do here. If extraction keeps making a particular mistake, the fix is usually
a sentence in the prompt.
