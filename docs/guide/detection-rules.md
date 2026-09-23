# Writing detection rules

Turning an article into something that actually fires in your SIEM, and keeping
what you write.

## Formats

Nine, all validated for syntax when you save:

| Format | Where it runs |
|---|---|
| Sigma | Vendor-neutral YAML, converted downstream |
| Splunk SPL | Splunk |
| CrowdStrike QL | CrowdStrike Falcon |
| Elastic QL | Elastic |
| KQL | Microsoft Sentinel / Defender |
| Snort / Suricata | Network IDS |
| YARA | File and memory scanning |
| Nuclei | Vulnerability scanning templates |
| Panther | Panther |

Sigma is the sensible default if you're not sure — it's the one that travels.

## From an article to a rule

Detection content is extracted from articles automatically: when a write-up
contains rules, or describes behaviour concretely enough to derive one, that
shows up on the article and feeds the *detection content* signal in the
[Priority Queue](priority-queue.md).

To work on one deliberately, open the article and use the AI panel (`a`), or
start from the **Threats** board where the drafting controls sit next to the
threat you're responding to. Pick a format and a focus — malware, campaign,
vulnerability, or let it choose — and you get a draft, which will include:

- the indicators it found (hashes, paths, registry keys, process names),
- the ATT&CK techniques it mapped,
- a feasibility read: whether this is detectable with ordinary telemetry or
  needs something you probably don't collect.

**The draft is a draft.** It has read one article. It doesn't know your
environment, your naming conventions, or what's normal on your network. Treat it
as a first pass that saves you the boilerplate, not as a rule.

## The editor

Syntax highlighting, bracket matching and auto-indent per format, with
validation errors inline as you type — an undefined YARA variable or a malformed
Sigma condition is flagged before you save, not after.

## Saving to the library

**Save → Library**, with a title, a description, tags, and the ATT&CK techniques
(pre-filled from the draft). The description is worth writing properly: in six
months it's the only thing that explains why the rule exists.

Every edit creates a new version. The rule's detail page has the history, and
you can revert — which is what you want the first time a tuning change makes a
rule noisy at 3am.

## The library

**Workbench → Rules Library.** A faceted table: search in the box and the rail's
counts narrow with you across format, severity, tactic, technique, log source,
repo, author, license, tags, and the actors, malware, tools, vendors and
products the rule's source article mentioned.

Ticking two formats widens the list rather than emptying it — facets within a
dimension are OR, across dimensions are AND.

## Coverage and gaps

**ATT&CK Matrix** colours the technique grid by what you've seen in your feeds
and what you have rules for. The interesting cells are the ones where those two
disagree: techniques showing up in your reading with nothing detecting them.

**Telemetry Sources** is what makes this honest. Record what log sources you
actually collect, and the app can tell the difference between "we have no rule"
and "we have a rule that cannot possibly fire here". A rule's data sources are
matched against your telemetry, so gap analysis reflects your environment rather
than a generic one.

## Exporting

From a rule, or from a multi-select in the library: the native format
(`.yml`, `.spl`, `.kql`, `.yar`, …), or an **ATT&CK Navigator layer** (`.json`)
for visualising coverage in Navigator itself.

Rules can also be attached to campaigns and pulled into reports — see
[Campaigns and reports](campaigns-and-reports.md).
