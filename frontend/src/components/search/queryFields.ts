import { getEntityCssVar } from "@/utils/entityTheme";

/**
 * The query language, as data — the single source for everything that shows it.
 *
 * Three surfaces used to describe the grammar independently: the reference card
 * listed the fields, the header autocomplete had its own dictionary, and each
 * picked its own colours. They drifted immediately — the workbench autocomplete
 * still offered five fields after the language grew to ninety-four, and a `cve:`
 * completion was a different colour from the `cve:` in the reference beside it.
 * Everything below is now derived from this file.
 */

export interface QueryField {
  token: string;
  hint: string;
  /** Known completions, offered after the colon. */
  values?: string[];
}

export interface QueryFieldGroup {
  label: string;
  /**
   * The group's colour rule. Set only for groups that name an entity — the
   * palette is the workbench's entity vocabulary, so colouring `Articles` or
   * `Operators` would say something untrue about them. Groups are split one
   * per entity type precisely so the colour can live on the group rather than
   * on every token inside it.
   */
  accent?: string;
  fields: QueryField[];
}

const SEVERITIES = ["critical", "high", "medium", "low"];
const BOOLEANS = ["true", "false"];

export const FIELD_GROUPS: QueryFieldGroup[] = [
  {
    label: "Articles",
    fields: [
      { token: "title:", hint: "Entry title" },
      { token: "content:", hint: "Entry body" },
      { token: "author:", hint: "Author name" },
      { token: "feed:", hint: "Feed name" },
      { token: "category:", hint: "Feed folder" },
      { token: "tag:", hint: "Tag name" },
      {
        token: "type:",
        hint: "Content type",
        values: ["rss", "atom", "youtube", "podcast", "reddit", "github_repo", "telegram", "web_scraper"],
      },
      { token: "media:", hint: "Media type", values: ["audio", "video", "image", "document"] },
      { token: "lang:", hint: "Language code" },
      { token: "date:", hint: "> or .. range" },
      { token: "url:", hint: "Link contains" },
      { token: "words:", hint: "Length, e.g. >1500" },
      {
        token: "is:",
        hint: "Entry state",
        values: ["unread", "read", "starred", "bookmarked", "noted", "muted", "translated", "image"],
      },
      {
        token: "sort:",
        hint: "Result order",
        values: ["relevance", "newest", "oldest", "radar", "title_asc", "title_desc", "shortest", "longest"],
      },
    ],
  },
  {
    label: "Signals & sources",
    fields: [
      {
        token: "signal:",
        hint: "Why the engine ranked it",
        // Mirrors SIGNAL_FAMILIES in backend/app/intelligence/signals.py — the
        // engine's registry, not a selection from it. This list sat four
        // signals behind for as long as those four existed.
        values: [
          "correlation_event",
          "critical_cvss",
          "detection_content",
          "entity_resurgence",
          "epss_high",
          "epss_jump",
          "feed_echo",
          "kev_added",
          "new_pairing",
          "novel_entity",
          "pir_match",
          "research_depth",
          "scoop",
          "source_convergence",
          "under_reported",
          "weaponized_poc",
        ],
      },
      { token: "feed.reliability:", hint: "Source grade (A–F)" },
      { token: "feed.timeliness:", hint: "Source grade (A–F)" },
      { token: "feed.relevance:", hint: "Source grade (A–F)" },
    ],
  },
  {
    label: "CVEs",
    accent: "var(--entity-cve)",
    fields: [
      { token: "cve:", hint: "CVE identifier" },
      { token: "cve.severity:", hint: "Severity", values: SEVERITIES },
      { token: "cve.cvss:", hint: "CVSS score (e.g. >7.0)" },
      { token: "cve.kev:", hint: "In CISA KEV", values: BOOLEANS },
      { token: "cve.epss:", hint: "EPSS probability (e.g. >0.5)" },
      { token: "cve.epss_percentile:", hint: "EPSS percentile" },
      { token: "cve.poc:", hint: "Public PoC count (e.g. >0)" },
      { token: "cve.exploit:", hint: "Exploitation status", values: ["kev"] },
      { token: "cve.product:", hint: "Affected vendor or product" },
    ],
  },
  {
    label: "TTPs",
    accent: "var(--entity-ttp)",
    fields: [
      { token: "ttp:", hint: "MITRE technique ID or name" },
      { token: "ttp.tactic:", hint: "ATT&CK tactic" },
      { token: "ttp.platform:", hint: "Windows, Linux, macOS…" },
      { token: "ttp.data_source:", hint: "Required telemetry" },
      { token: "ttp.domain:", hint: "Matrix", values: ["enterprise", "mobile", "ics"] },
      { token: "ttp.subtechnique:", hint: "Sub-techniques only", values: BOOLEANS },
    ],
  },
  {
    label: "Mitigations",
    accent: "var(--entity-mitigation)",
    fields: [{ token: "mitigation:", hint: "Mitigation name or MITRE ID" }],
  },
  {
    label: "Observables",
    accent: "var(--entity-ioc)",
    fields: [
      { token: "ioc:", hint: "Observable value or label — ioc:45.155.204.119, ioc:amsi bypass" },
      { token: "ioc.kind:", hint: "ipv4, domain, url, sha256, cmdline, registry, script, …" },
      { token: "ioc.role:", hint: "c2, delivery, payload, phishing, exfil, exploit, scanning" },
      { token: "ioc.status:", hint: "active, aging, expired" },
    ],
  },
  {
    label: "Weaknesses",
    accent: "var(--entity-cwe)",
    fields: [
      { token: "cwe:", hint: "CWE id or name — cwe:CWE-416, cwe:use after free" },
      { token: "cwe.abstraction:", hint: "Pillar, Class, Base, Variant, Compound" },
      { token: "cwe.usage:", hint: "MITRE mapping guidance — Allowed, Discouraged, Prohibited" },
      { token: "cwe.parent:", hint: "Parent weakness id" },
      { token: "cwe.deprecated:", hint: "true / false" },
    ],
  },
  {
    label: "Threat Actors",
    accent: "var(--entity-actor)",
    fields: [
      { token: "threat_actor:", hint: "Threat actor name" },
      { token: "threat_actor.country:", hint: "Actor origin country" },
      {
        token: "threat_actor.motivation:",
        hint: "Motivation",
        values: ["espionage", "financial", "hacktivism", "disruption"],
      },
      { token: "threat_actor.sector:", hint: "Sector the actor targets" },
      { token: "threat_actor.type:", hint: "Actor classification" },
    ],
  },
  {
    label: "Malware",
    accent: "var(--entity-malware)",
    fields: [
      { token: "malware:", hint: "Malware family" },
      { token: "malware.type:", hint: "ransomware, rat, etc." },
      { token: "malware.sector:", hint: "Sector the family targets" },
    ],
  },
  {
    label: "Tools",
    accent: "var(--entity-tool)",
    fields: [
      { token: "tool:", hint: "Tool name" },
      { token: "tool.type:", hint: "Tool type" },
      { token: "tool.platform:", hint: "Windows, Linux, macOS…" },
    ],
  },
  {
    label: "Countries",
    accent: "var(--entity-country)",
    fields: [
      { token: "country:", hint: "Country name" },
      { token: "country.region:", hint: "Region name" },
      { token: "country.iso:", hint: "ISO code, e.g. RU" },
    ],
  },
  {
    label: "Sectors",
    accent: "var(--entity-sector)",
    fields: [
      { token: "sector:", hint: "Targeted industry, by name or alias (banks, hospitals)" },
      { token: "sector.slug:", hint: "Canonical slug, e.g. financial-services" },
    ],
  },
  {
    label: "Vendors",
    accent: "var(--entity-vendor)",
    fields: [
      { token: "vendor:", hint: "Vendor name" },
      { token: "vendor.type:", hint: "Vendor type" },
    ],
  },
  {
    label: "Products",
    accent: "var(--entity-product)",
    fields: [
      { token: "product:", hint: "Product name" },
      { token: "product.type:", hint: "Product type" },
      { token: "product.vendor:", hint: "Vendor that makes it" },
    ],
  },
  {
    label: "Detection Rules",
    accent: "var(--entity-rule)",
    fields: [
      { token: "rule:", hint: "Detection rule title" },
      {
        token: "rule.type:",
        hint: "Rule format",
        values: ["sigma", "splunk_spl", "crowdstrike_ql", "elastic_ql", "kql", "yara", "snort_suricata"],
      },
      { token: "rule.severity:", hint: "Severity", values: [...SEVERITIES, "informational"] },
      { token: "rule.data_source:", hint: "Log source the rule needs" },
      { token: "rule.tactic:", hint: "ATT&CK tactic" },
      { token: "rule.tag:", hint: "Rule tag" },
      { token: "rule.draft:", hint: "Drafts only", values: BOOLEANS },
    ],
  },
  {
    label: "Campaigns",
    accent: "var(--entity-campaign)",
    fields: [
      { token: "campaign:", hint: "Campaign name" },
      { token: "campaign.status:", hint: "Status", values: ["active", "monitoring", "closed"] },
    ],
  },
  {
    label: "Requirements",
    accent: "var(--entity-pir)",
    fields: [
      { token: "pir:", hint: "Intelligence requirement title" },
      { token: "pir.priority:", hint: "Priority", values: SEVERITIES },
      { token: "pir.category:", hint: "Category", values: ["strategic", "operational", "tactical"] },
    ],
  },
  {
    label: "Reports",
    accent: "var(--accent-intel)",
    fields: [
      { token: "intel_report:", hint: "Report title" },
      { token: "intel_report.status:", hint: "Report status" },
      { token: "intel_report.tlp:", hint: "TLP marking", values: ["clear", "green", "amber", "red"] },
    ],
  },
  {
    label: "Notes",
    accent: "var(--entity-note)",
    fields: [
      { token: "note:", hint: "Note title or body" },
      { token: "note.tag:", hint: "Note tag" },
      {
        token: "note.type:",
        hint: "Entity note type",
        values: ["annotation", "analysis", "action_taken", "false_positive", "context"],
      },
      {
        token: "note.about:",
        hint: "What the note is on",
        values: [
          "entry",
          "standalone",
          "threat_actor",
          "malware",
          "cve",
          "ttp",
          "campaign",
          "vendor",
          "product",
        ],
      },
      { token: "note.pinned:", hint: "Pinned notes", values: BOOLEANS },
    ],
  },
  {
    label: "Ransomware Victims",
    accent: "var(--entity-victim)",
    fields: [
      { token: "ransomware_victim:", hint: "Victim organization" },
      { token: "ransomware_victim.sector:", hint: "Victim sector" },
      { token: "ransomware_victim.domain:", hint: "Victim domain" },
      { token: "ransomware_victim.group:", hint: "Group that posted the victim" },
    ],
  },
  {
    label: "Any entity",
    fields: [
      { token: "threat_actor.articles:", hint: "Linked articles, e.g. >100" },
      { token: "malware.seen:", hint: "Last seen, e.g. >2026-01-01" },
      { token: "cve.first_seen:", hint: "First seen date" },
      { token: "threat_actor.review:", hint: "Flagged for curation", values: BOOLEANS },
      { token: "cve.via:", hint: "How it was created", values: ["ai_extraction"] },
    ],
  },
  {
    label: "Operators",
    fields: [
      { token: "AND", hint: "Both conditions" },
      { token: "OR", hint: "Either condition" },
      { token: "NOT", hint: "Exclude" },
      { token: "*", hint: "Wildcard" },
      { token: '"…"', hint: "Exact phrase" },
      { token: "()", hint: "Grouping" },
    ],
  },
];

export const EXAMPLE_QUERIES = [
  "cve.kev:true cve.epss:>0.5",
  "signal:under_reported sort:radar",
  "rule.data_source:sysmon rule.tactic:persistence",
  "ttp.platform:Windows ttp.data_source:process",
  "threat_actor.motivation:espionage threat_actor.sector:healthcare",
  "ransomware_victim.group:lockbit",
];

/** Every completable field, flattened. Operators are excluded — they take no value. */
export const ALL_FIELDS: QueryField[] = FIELD_GROUPS.filter((g) => g.label !== "Operators").flatMap(
  (g) => g.fields,
);

export const FIELD_VALUES: Record<string, string[]> = Object.fromEntries(
  ALL_FIELDS.filter((f) => f.values?.length).map((f) => [f.token.replace(/:$/, ""), f.values!]),
);

export const FIELD_HINTS: Record<string, string> = Object.fromEntries(
  ALL_FIELDS.map((f) => [f.token.replace(/:$/, ""), f.hint]),
);

// ── Colour ────────────────────────────────────────────────────────────────

/** Field namespace → entity type, for the ones whose names differ. */
const NAMESPACE_ENTITY: Record<string, string> = {
  cve: "cve",
  ttp: "ttp",
  threat_actor: "threat_actor",
  malware: "malware",
  tool: "tool",
  vendor: "vendor",
  product: "product",
  country: "country",
  sector: "sector",
  mitigation: "mitigation",
  cwe: "cwe",
  observable: "observable",
  ioc: "observable",
  campaign: "campaign",
  rule: "detection_rule",
  ransomware_victim: "ransomware_victim",
};

/** Entry-grammar fields — the feeds domain, not an entity. */
const ENTRY_FIELDS = new Set([
  "title", "content", "author", "feed", "category", "tag", "type", "media",
  "lang", "date", "is", "url", "words", "signal",
]);

/**
 * The colour a query field wears, wherever it appears — the autocomplete dot,
 * the reference token, the group rule.
 *
 * `token` may be a bare field (`cve.severity:`), a completed `field:value`
 * pair, or an operator. Anything unrecognised takes the muted text colour
 * rather than inventing one.
 */
export function queryFieldColor(token: string): string {
  const namespace = token.trim().split(":")[0].split(".")[0].toLowerCase();
  if (ENTRY_FIELDS.has(namespace)) return "var(--accent-feeds)";
  // PIRs are a first-class domain vocabulary with their own token, but have no
  // entry in ENTITY_THEMES, so they are named directly.
  if (namespace === "pir") return "var(--entity-pir)";
  if (namespace === "intel_report") return "var(--accent-intel)";
  // Notes are analyst writing rather than an intelligence entity, so they have
  // no ENTITY_THEMES row either.
  if (namespace === "note") return "var(--entity-note)";
  const entity = NAMESPACE_ENTITY[namespace];
  // The CSS variable, not the frozen hex behind it — these follow the theme
  // like every other entity colour in the app.
  if (entity) return getEntityCssVar(entity);
  // `sort:`, AND / OR / NOT, wildcards, grouping — grammar, not subject matter.
  return "var(--text-secondary)";
}
