# Entities and profiles

An **entity** is a thing IntelFeed tracks across articles rather than inside
one: a threat actor, a malware family, a CVE, an ATT&CK technique, a weakness
(CWE), a vendor, a product, a country, a tool, a mitigation, a ransomware
victim, and an observable (an indicator — an IP, domain, hash, command line).

Every article that arrives is scanned against a dictionary of known entity names
and aliases. Matches become links in the article body and rows in the database,
which is what makes a profile page accumulate.

## Profile pages

Click any linked name in an article, or browse by type under **Workbench →
Entities**. Every type shares the same page shape:

**The header** carries the name, aliases, a description, and outbound pivot
links — MITRE ATT&CK, VirusTotal, MalwareBazaar, Hybrid Analysis and so on,
chosen per entity type. Those are outbound searches, not data IntelFeed holds.
Click the name itself to rename the entity.

**Overview** is the substance, and what's in it depends on the type. A CVE shows
severity, exploitation status and KEV listing; an actor shows attribution,
targeting and the toolset; everything shows the timeline of when it was first
seen, when it was last active, and what happened in between.

**Relationships** shows what this entity is connected to and *why* — the
evidence behind each link, not just the link. See below.

**Articles** lists everything mentioning it, newest first.

**Notes** are yours to write and everyone's to read.

## Where the facts come from

Profile fields are filled from several places, and the profile tells you which.
Hover a value for its provenance popover: which source claimed it, when, and
whether other sources agree. A field two sources agree on and a field one blog
asserted look different on the page, deliberately.

Enrichment sources an admin can turn on under **Settings → Engine**, enrich
stage:

| Source | What it adds |
|---|---|
| NVD | CVE metadata, CVSS scores, timelines |
| EPSS | Probability a CVE gets exploited |
| CISA KEV | Known-exploited catalogue flags and due dates |
| MITRE ATT&CK | The technique and tactic catalogue |
| VulnCheck / CVEDetails | Extended CVE intelligence (supports per-user keys) |
| OSV | Open-source vulnerability data |
| Malpedia | Actor and malware profiles and aliases |
| GitHub PoC | Proof-of-concept exploit references |
| Wikipedia | An article summary on the profile |

NVD, EPSS and KEV together are what make a CVE page worth opening: how bad,
how likely, and whether it's already happening.

Enrichment runs automatically when an entity is first created and caches its
results — the age is shown. The refresh icon re-queries. If Wikipedia matched
the wrong article, pick **None** in the profile's Wikipedia picker; that clears
it *and* stops it being re-matched later.

IntelFeed does not ship indicator-reputation sources — no VirusTotal, AbuseIPDB,
Shodan or GreyNoise lookups. For indicator reputation, use the outbound pivot
links in the profile header.

## Observables (indicators)

Observables are the one entity type that deliberately does **not** get created
by pattern matching. An IP-shaped string in an article is not an indicator; it
is a string. A row only appears when something with judgment puts it there: the
AI analysis confirming it as an indicator, a curated indicator-list feed, an
ATT&CK technique's host artifact, or you promoting it yourself.

What the scan *does* produce is **candidates** — suggestions shown against the
article, which you promote or dismiss from the reader. Hashes and public IPs are
always nominated; domains, URLs and emails are nominated only when the author
defanged them (`evil[.]com`, `hxxps://`), because defanging is the author
telling you it's an indicator.

Every observable carries where it came from, the sentence that justified it, and
a confidence that **decays** — an IP halves every 30 days, a URL every 60, a
domain every 90, while hashes and host artifacts never decay, because behaviour
and math persist while infrastructure rotates. A fresh sighting resets the
clock.

Browse them under **Workbench → Entities → Observables**. Dual-use infrastructure (shared
hosting, CDNs, URL shorteners) is kept but tagged, so it stays visible as intel
without ever reaching a blocklist. If your administrator has turned on
publishing, the ledger is also served as EDL blocklists, SIEM lookup CSVs and a
TAXII 2.1 collection.

## Relationships

Relationships between entities — "this actor uses that malware", "this malware
exploits that CVE" — are typed, and each one carries the evidence that produced
it: which articles said so, and how confidently.

They come from a few places: the MITRE ATT&CK catalogue, extraction from article
text, and analyst assertions. A relationship asserted by one article and one
confirmed by MITRE plus eleven articles are not shown as equals.

The graph view draws them as a network. Clicking a cluster filters the page to
that cluster, which is usually the fastest way to answer "what is the group of
things involved in this story?"

## Watching and muting

The **⋯** menu on any profile has **Watch** and **Mute**. Both are per-user —
nothing you do here affects anyone else's view.

- **Watch** — articles mentioning this entity get a priority boost in *your*
  Priority Queue, and surface there even when they'd otherwise fall below the
  threshold.
- **Mute** — articles mentioning it are suppressed from your Priority Queue
  entirely. They still appear in normal feed views and in search.

Watch the handful of things you're actually responsible for: your vendors, your
products, the actors that target your sector. Watching forty things is the same
as watching none. Automation rules can also fire on "entity is watchlisted", so
a watch can become a notification — see [Automation and AI](automation-and-ai.md).

The **Watchlist** section under Workbench → Intelligence lists what you're
watching in one place.

## Duplicates and mistakes

Entity extraction produces duplicates. Two names for one group, a malware family
that also got created as a tool, a vendor recorded twice with different
capitalisation.

**Merging** — from the **⋯** menu on a profile, choose Merge and pick the
duplicate. Articles, relationships and aliases are unioned onto the survivor.
Merging is admin-only, and it's same-type only.

**Converting** — when the type itself is wrong (something recorded as a tool
that is really a product), convert it rather than deleting and recreating.
Converting writes a tombstone so extraction doesn't just recreate the wrong one
within the hour; deleting doesn't, which is why the deleted thing keeps coming
back.

**Wrong links** — if the problem is the *linking* rather than the entity, fix it
in the reader with the **Wrong?** control on the link, described in
[Reading and triage](reading-and-triage.md).

## Glossary

Hover an unfamiliar term — a technique ID, an acronym — for a definition
popover. The glossary behind it is editable under **Workbench → Glossary**, so
house terms and internal shorthand can live there too.
