# Campaigns and reports

A **campaign** is how you hold an investigation together while it's happening. A
**report** is how you hand it to someone else when it's done.

## Campaigns

A campaign binds articles, entities, detection rules and notes under one name —
"Operation Stealth", "LockBit Q3", "the Fortinet thing". It's a folder with
intelligence semantics.

### Creating one

**Workbench → Campaigns → + New**, then:

- **Name** — what you'd call it in conversation.
- **Description** — why you're tracking it. Write this now; you won't remember
  in three weeks.
- **TLP** — CLEAR, GREEN, AMBER or RED. This governs how it can be shared.
- **Status** — active, on hold, concluded.
- **Severity** — critical through low.

### Filling it

From inside the campaign, add entries, entities, detection rules and notes.

Faster, usually: add things as you find them. The reader toolbar has **Add to
campaign**, and so does the entry list's bulk selection — so a triage pass where
you select six related articles and push them all into a campaign at once takes
a couple of seconds.

### The campaign page

- **Timeline** — articles, entities and rules in chronological order. This is
  the view that answers "what actually happened, in what order".
- **Entity graph** — the network of everything linked to it.
- **Detection coverage** — which techniques in this campaign you can detect.
- **Sources** — where the campaign's material came from.

Campaigns are entities themselves, so they get a profile page like any other and
can be related to actors, malware and the rest.

### Exporting

Markdown, CSV, MISP event, or STIX 2.1.

## Reports

**Workbench → Reports → + New.** Start from a template:

| Template | For |
|---|---|
| Flash alert | Breaking, short, actionable — summary, key findings, indicators, recommended actions |
| Actor profile | A deep-dive: attribution and aliases, TTPs, target sectors, infrastructure, indicators, timeline |
| Campaign tracker | An incident: overview, attack chain, indicators, TTPs, affected systems, timeline |
| Landscape | A period snapshot: key trends, notable threats, vulnerability highlights, sector impact, outlook |
| Threat exposure | A named scope — regions × verticals — and the threat surface matched against it |
| Detection report | Your rules, your coverage gaps, log source requirements, recommendations |

Each family has its own drafting prompt, so a detection report and a flash alert
are not written by the same instructions. Those prompts are editable by an admin
under Settings → AI → Prompts.

### Exposure reports and intel profiles

A **threat exposure** report starts from an *intel profile* rather than from
articles you picked. A profile is a saved scope — a set of regions and a set of
sectors, with a lookback window — that you name and reuse: one per customer,
per client portfolio, per watch area. Nothing in IntelFeed is "your org"; a
profile is whichever scope you are reporting against this time.

Build one in the exposure builder. It searches the corpus for the actors and
malware families active against that scope and shows **why each one matched**:

- **co-occurrence** — articles in the window linking the entity and a scope
  country or sector,
- **claims** — recorded targeting of those countries or sectors,
- **victims** — ransomware leak-site disclosures in scope.

Candidates that matched on only one of the three still appear, ranked lower with
the gap stated — you decide, not the query. Your keep/drop decisions are
remembered on the profile, so rebuilding next quarter doesn't re-ask what you
already rejected.

### Writing one

The template arrives with its sections laid out. Edit them in markdown, and
insert snippets — a TTP matrix, a timeline table, detection guidance — rather
than rebuilding those by hand. Articles and entity profiles can be pulled
straight into sections, which keeps the citations honest.

**Send to report** in the entry list, the reader and entity profiles pushes
material into a draft without leaving what you were doing.

Some templates draft sections with AI. Same caveat as everywhere else: it's a
first pass. It is very good at structure and very willing to state things
confidently that it half-inferred, so read every generated sentence as though a
junior analyst wrote it in a hurry.

Every save creates a version; you can revert.

### TLP

Set it deliberately. It governs sharing: TLP:RED material doesn't get a public
link. TLP is a promise you're making to whoever gave you the information —
marking everything AMBER because it feels safer makes the marking meaningless.

### Exporting

Markdown, HTML, PDF, MISP, STIX 2.1, or CSV. Markdown for a wiki, PDF for
people who want an attachment, STIX or MISP for another platform.

### Sharing

**Share** generates a public link, viewable without a login. That is exactly as
open as it sounds: anyone with the URL can read it, and there is no access
control past the link itself. Fine for a partner org; not fine for anything you
wouldn't email unencrypted.

More on this in [Notes and sharing](notes-and-sharing.md).
