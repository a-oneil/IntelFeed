/**
 * entityProfileConfig — the single source of truth for the unified entity profile.
 *
 * Each entity type declares which tabs it shows, which signal badges appear in the
 * header, which editable identity fields render in the Overview, which Overview
 * "signal panels" to surface, its external pivot links, cascade-delete type, and
 * which header/⋯ actions apply. Adding a field/type/tab is a config change here —
 * not an edit to a monolithic component.
 */
import type { EntityType } from "@/stores/intelStore";
import type { EntitySearchResult } from "@/api/types";
import type { EntityContextBadge } from "@/hooks/useEntityContext";
import { getPivotLinks, type PivotLink } from "@/utils/pivotLinks";
import { observablePivotLinks } from "@/utils/entityPopoverMeta";

// ── Tabs ──────────────────────────────────────────────────────────────────
export type TabKey =
  | "overview"
  | "vulnerabilities"
  | "weaknesses"
  | "relationships"
  | "detection"
  | "geography"
  | "victimology"
  // Not in any tabs array — reachable only via the rail's "Review gaps"
  // action; ProfileTabs appends it as an ephemeral tab while active.
  | "detection_gaps";

export const TAB_LABELS: Record<TabKey, string> = {
  overview: "Overview",
  vulnerabilities: "Vulnerabilities",
  weaknesses: "Weaknesses",
  relationships: "Relationships",
  detection: "Detection",
  geography: "Geography",
  victimology: "Victimology",
  detection_gaps: "Detection Gaps",
};

/**
 * Hover cards for the tabs whose name doesn't say what's behind it. Tabs absent
 * from this map get no card — "Overview" explains itself.
 */
export const TAB_HINTS: Partial<Record<TabKey, { title: string; body: string; aside?: string }>> = {
  relationships: {
    title: "Relationships",
    body: "Who this is tied to and how strongly, built only from articles that named both.",
  },
  victimology: {
    title: "Victimology",
    body: "Who targets this industry — reported in articles vs asserted as a claim — and the leak-site victims posted in it.",
    aside: "Leak-site claims are the gang's claims, not confirmed breaches.",
  },
  detection_gaps: {
    title: "Detection Gaps",
    body: "Techniques this entity uses that nothing in your rule library covers yet.",
    aside: "You can generate a rule straight from a gap.",
  },
};

// ── Signal badges (header) ────────────────────────────────────────────────
export type BadgeTone =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "neutral"
  | "success"
  | "danger";

export interface BadgeSpec {
  label: string;
  tone: BadgeTone;
  title?: string;
  /** When set, the badge is click-to-edit for this entity field (it replaces
   * the old identity-row editor). An empty label renders a ghost chip with the
   * placeholder. `editKind: "country"` links to the country profile when the
   * country id is resolvable, mirroring the old identity-field behavior. */
  editKey?: string;
  editKind?: "text" | "country" | "sector";
  placeholder?: string;
  /** Entity field this badge represents, for the "who says so" provenance
   * marker. Defaults to `editKey`; set it explicitly on badges that display a
   * field without editing it (targeted sectors), or leave both unset on badges
   * that aren't a field at all. */
  provenanceKey?: string;
  /** Heading for the provenance popover, when the badge's own `title` is not a
   *  clean field name (the sector badge's title carries the whole list). */
  provenanceLabel?: string;
  /** Raw stored value when it differs from the display label (e.g. enum vs
   * pretty label) — the inline editor edits this, not the label. */
  editValue?: string;
}

export function severityTone(severity: string | null | undefined): BadgeTone {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "neutral";
  }
}

/** Manifest badges (GET …/context `badges[]`) as header chips, after the
 * hand-written ones. Quiet on purpose: only red/amber tones keep their color —
 * "benign" or "info" is not something to look at, so it renders neutral. */
export function contextBadgeSpecs(badges: EntityContextBadge[] | undefined): BadgeSpec[] {
  return (badges ?? []).map((b) => {
    const tone = b.tone?.toLowerCase();
    return {
      label: b.label,
      tone:
        tone === "critical" || tone === "high" || tone === "danger"
          ? tone
          : tone === "medium" || tone === "warning"
            ? "medium"
            : "neutral",
      title: b.source_type,
      ...(b.field ? { provenanceKey: b.field } : {}),
    };
  });
}

/** KEV = the CISA flag OR an exploit_status that already says known-exploited.
 * The retired KEVBadge honored both; keying on `is_kev` alone reads a CVE whose
 * enrichment wrote the status but never set the flag as "Not listed". */
export function isKnownExploited(e: {
  is_kev?: boolean | null;
  exploit_status?: string | null;
}): boolean {
  return Boolean(e.is_kev) || /kev|known[_\s-]?exploited/i.test(e.exploit_status ?? "");
}

/** Exploit availability → tone/label. Shared by CVE badges + KEV logic. */
function exploitBadge(avail: string | null | undefined): BadgeSpec | null {
  switch (avail?.toLowerCase()) {
    case "active_exploitation":
      return { label: "Active Exploitation", tone: "critical", title: "Known exploited in the wild" };
    case "weaponized":
      return { label: "Weaponized", tone: "high", title: "Weaponized exploit available" };
    case "poc":
      return { label: "PoC", tone: "medium", title: "Proof-of-concept available" };
    default:
      return null;
  }
}

// ── Identity fields (Overview meta rows) ──────────────────────────────────
export type IdentityFieldKind = "text" | "vendor";

export interface IdentityFieldDef {
  label: string;
  /** key on the entity object */
  key: string;
  kind: IdentityFieldKind;
  placeholder?: string;
}

// ── Overview signal panels ────────────────────────────────────────────────
export type OverviewPanelKey =
  | "cve_affected"
  | "ttp_mitre"
  | "ttp_family"
  | "ttp_mitigations"
  | "cwe_catalog"
  | "cwe_family"
  | "cwe_mitigations"
  | "cwe_affected_vendors"
  | "cwe_vendors"
  | "observable_provenance"
  | "observable_backlinks"
  | "infrastructure"
  /** Manifest-driven enrichment context (ContextPanel) — every type has it. */
  | "context";

// ── Actions ───────────────────────────────────────────────────────────────
export type ActionKey =
  | "add_to_campaign"
  | "generate_report"
  | "ai_summary"
  | "convert"
  | "merge"
  | "fetch_wikipedia"
  | "rescan"
  | "unlink_all"
  | "clear_timeline"
  | "delete";

// ── Config shape ──────────────────────────────────────────────────────────
export interface EntityProfileConfig {
  tabs: TabKey[];
  signalBadges: (e: EntitySearchResult) => BadgeSpec[];
  identityFields: IdentityFieldDef[];
  hasAliases: boolean;
  hasDescription: boolean;
  /** Whether the display name is user-editable (click-to-edit in the header).
   * False for cve/cwe/ttp/mitigation whose identity is an external id, not a name. */
  nameEditable: boolean;
  /** Entity field holding an external catalog id that should render in mono
   * ahead of the name ("T1059.001 Command and Scripting Interpreter",
   * "CWE-416 Use After Free"). Set only for types whose identity IS the id. */
  monoIdKey?: "technique_id" | "cwe_id" | "value";
  overviewPanels: OverviewPanelKey[];
  externalLinks?: (e: EntitySearchResult) => PivotLink[];
  /** backend entity_type for cascade-delete preview (null = unsupported) */
  cascadeType?: string;
  actions: ActionKey[];
}


/** Targeted sectors as read-only chips.
 *
 * Sectors are rolled up from the victim sectors on an entity's articles, so
 * they belong with the other observed signals rather than in an editable field.
 * Capped so a broadly-targeting actor doesn't push the identity badges off the
 * row; the full list stays in the title attribute.
 */
function sectorBadges(sectors: string[] | undefined): BadgeSpec[] {
  if (!sectors?.length) return [];
  const all = sectors.join(", ");
  return sectors.slice(0, 4).map((s, i) => ({
    label: s,
    tone: "neutral" as BadgeTone,
    title: sectors.length > 4 ? `Targeted sectors: ${all}` : "Targeted sector",
    // Not editable — the kind only tells SignalBadges to link the chip to the
    // sector profile (resolved by display name).
    editKind: "sector" as const,
    // One marker for the whole group — the claim is about the list, not each chip.
    ...(i === 0 ? { provenanceKey: "targeted_sectors", provenanceLabel: "Targeted sectors" } : {}),
  }));
}

export const ENTITY_PROFILE_CONFIG: Record<EntityType, EntityProfileConfig> = {
  // A campaign is the one profile type nobody extracted — it is a curated case
  // file. It still pivots (its articles are a seed like any other), so it earns
  // the same four tabs the actors have, and the tabs it used to carry on its own
  // page collapse into shell surfaces: Timeline into the activity readout,
  // Entities into the associates strip, Searches and Suggestions into the rail.
  campaign: {
    tabs: ["overview", "relationships", "detection"],
    signalBadges: (e) => [
      {
        label: e.status || "",
        tone: e.status === "closed" || e.status === "historical" ? "neutral" : "success",
        title: "Status",
        editKey: "status",
        editKind: "text",
        placeholder: "set status",
      },
      ...(e.tlp_marking ? [{ label: e.tlp_marking, tone: "info" as BadgeTone, title: "TLP marking" }] : []),
      ...(e.tags || []).slice(0, 4).map((t) => ({ label: t, tone: "neutral" as BadgeTone, title: "Tag" })),
    ],
    identityFields: [],
    hasAliases: false,
    hasDescription: true,
    nameEditable: true,
    overviewPanels: ["context", "infrastructure"],
    // Campaigns are internal objects; there is nothing to look them up in.
    externalLinks: () => [],
    // No cascadeType: the preview counts extraction links that would be severed,
    // and deleting a campaign severs nothing — the articles and entities it held
    // all outlive it. Nothing to deny-list either; extraction never made it.
    cascadeType: undefined,
    actions: ["generate_report", "ai_summary", "delete"],
  },
  threat_actor: {
    tabs: ["overview", "relationships", "detection"],
    // Badges are the single representation of motivation/origin — editable
    // in place (the identity row keeps only fields with no badge twin).
    signalBadges: (e) => [
      { label: e.motivation || "", tone: "info", title: "Motivation", editKey: "motivation", editKind: "text", placeholder: "set motivation" },
      { label: e.country || "", tone: "neutral", title: "Origin country", editKey: "country", editKind: "country", placeholder: "set origin" },
      ...(e.mitre_id
        ? [{ label: `MITRE ${e.mitre_id}`, tone: "neutral" as BadgeTone, title: "MITRE ATT&CK group", provenanceKey: "mitre_id", provenanceLabel: "MITRE ID" }]
        : []),
      ...sectorBadges(e.targeted_sectors),
    ],
    identityFields: [],
    hasAliases: true,
    hasDescription: true,
    nameEditable: true,
    // Techniques/attribution now live in the hero (associates strip, badges) —
    // no overview panels repeat them.
    overviewPanels: ["context", "infrastructure"],
    externalLinks: (e) => getPivotLinks("threat_actor", e.name || ""),
    cascadeType: "threat_actor",
    actions: ["add_to_campaign", "generate_report", "ai_summary", "convert", "merge", "fetch_wikipedia", "rescan", "unlink_all", "clear_timeline", "delete"],
  },

  malware: {
    tabs: ["overview", "relationships", "detection"],
    signalBadges: (e) => [
      { label: e.malware_type || "", tone: "info", title: "Malware type", editKey: "malware_type", editKind: "text", placeholder: "set type" },
      ...sectorBadges(e.targeted_sectors),
    ],
    identityFields: [],
    hasAliases: true,
    hasDescription: true,
    nameEditable: true,
    // Malpedia moved into the Sources rail card.
    overviewPanels: ["context", "infrastructure"],
    externalLinks: (e) => getPivotLinks("malware", e.name || ""),
    cascadeType: "malware",
    actions: ["add_to_campaign", "generate_report", "ai_summary", "convert", "merge", "fetch_wikipedia", "rescan", "unlink_all", "clear_timeline", "delete"],
  },

  cve: {
    tabs: ["overview", "weaknesses", "relationships", "detection"],
    signalBadges: (e) => {
      const out: BadgeSpec[] = [];
      // KEV first — it's the strongest exploitation signal
      if (isKnownExploited(e)) {
        out.push({
          label: "KEV",
          tone: "critical",
          title: `CISA Known Exploited Vulnerability${e.kev_date_added ? ` — added ${e.kev_date_added}` : ""}${e.kev_due_date ? `, remediation due ${e.kev_due_date}` : ""}`,
        });
      }
      // Qualitative headline only — the numbers (CVSS score, EPSS, PoC count)
      // live in the Overview's Snapshot card, their single home.
      out.push({
        label: e.severity ? e.severity.toUpperCase() : "",
        tone: severityTone(e.severity),
        title: "Severity",
        editKey: "severity",
        editKind: "text",
        editValue: e.severity || "",
        placeholder: "set severity",
      });
      const ex = exploitBadge(e.exploit_availability);
      const manual = e.exploit_status_source === "manual" ? " — set manually, enrichment won't overwrite" : "";
      out.push({
        ...(ex ?? { label: "", tone: "neutral" as BadgeTone }),
        title: (ex?.title ?? "Exploit availability") + manual,
        editKey: "exploit_availability",
        editKind: "text",
        editValue: e.exploit_availability || "",
        placeholder: "set exploit status",
      });
      return out;
    },
    // Severity/exploit are NVD/KEV-derived and already shown as signal badges.
    identityFields: [],
    hasAliases: false,
    hasDescription: true,
    nameEditable: false,
    // Exploitation/EPSS/KEV numbers live in the Snapshot rail card; PoC links
    // in the Exploit & PoC card; references in Sources. Only the structured
    // CPE affected-products list keeps a panel of its own.
    overviewPanels: ["context", "cve_affected"],
    externalLinks: (e) => getPivotLinks("cve", e.cve_id || ""),
    cascadeType: "cve",
    actions: ["add_to_campaign", "generate_report", "ai_summary", "convert", "fetch_wikipedia", "rescan", "unlink_all", "clear_timeline", "delete"],
  },

  cwe: {
    // TTP's tab set plus Vulnerabilities: unlike a technique, a weakness has an
    // authoritative CVE list behind it, and a count with nothing to open is a
    // dead end.
    tabs: ["overview", "vulnerabilities", "relationships", "detection"],
    signalBadges: (e) => {
      const out: BadgeSpec[] = [];
      if (e.abstraction) {
        out.push({
          label: e.abstraction,
          tone: "neutral",
          title: "Abstraction level — Pillar is broadest, Variant most specific",
        });
      }
      if (e.kind === "category") {
        out.push({
          label: "Category",
          tone: "neutral",
          title: "A MITRE grouping, not a weakness — never a valid CVE mapping target",
        });
      }
      if (e.likelihood_of_exploit) {
        out.push({ label: `Exploit ${e.likelihood_of_exploit}`, tone: "info", title: "MITRE likelihood of exploit" });
      }
      if (e.kev_count) {
        out.push({
          label: `${e.kev_count} KEV`,
          tone: "critical",
          title: "CVEs carrying this weakness that are in CISA KEV",
        });
      }
      // Mapping guidance is the quality signal that makes a count honest: a CVE
      // tagged with a Discouraged or Prohibited id is imprecisely classified,
      // and MITRE says so in the catalog.
      if (e.mapping_usage && e.mapping_usage !== "Allowed") {
        out.push({
          label: e.mapping_usage,
          tone: e.mapping_usage === "Prohibited" ? "danger" : "medium",
          title: `MITRE mapping guidance: ${e.mapping_usage} — NVD tagging a CVE with this id is imprecise`,
        });
      }
      if (e.is_deprecated) {
        out.push({
          label: e.superseded_by ? `Retired → ${e.superseded_by}` : "Retired",
          tone: "danger",
          title: e.superseded_by
            ? `Retired from the CWE catalog — replaced by ${e.superseded_by}`
            : "Retired from the CWE catalog",
        });
      }
      return out;
    },
    identityFields: [],
    // The catalog's alternate terms are shown in the Catalog panel, not as
    // editable aliases: they come from MITRE and nothing should write them back.
    hasAliases: false,
    hasDescription: true,
    nameEditable: false,
    monoIdKey: "cwe_id",
    overviewPanels: ["context", "cwe_family", "cwe_catalog", "cwe_mitigations", "cwe_affected_vendors"],
    // The catalog page keys on the bare number.
    externalLinks: (e) => getPivotLinks("cwe", (e.cwe_id || "").replace(/^CWE-/i, "")),
    cascadeType: "cwe",
    // No convert or merge — a weakness is catalog-keyed, so it is neither a
    // mis-filed other type nor a duplicate of one. No delete either: rows come
    // from the seeder and a re-seed would just bring them back.
    actions: ["add_to_campaign", "generate_report", "ai_summary", "rescan", "unlink_all", "clear_timeline"],
  },

  ttp: {
    tabs: ["overview", "relationships", "detection"],
    signalBadges: (e) => {
      // Catalog techniques can span multiple tactics — the first one stays
      // click-to-edit (it maps to the primary `tactic` field), the rest render
      // as read-only chips.
      const tactics = e.tactics?.length ? e.tactics : e.tactic ? [e.tactic] : [];
      const out: BadgeSpec[] = [
        { label: tactics[0] || "", tone: "info", title: "Tactic", editKey: "tactic", editKind: "text", placeholder: "set tactic" },
        ...tactics.slice(1).map((t): BadgeSpec => ({ label: t, tone: "info", title: "Tactic" })),
      ];
      if (e.matrix_domain && e.matrix_domain !== "enterprise") {
        out.push({
          label: e.matrix_domain === "ics" ? "ICS" : "Mobile",
          tone: "neutral",
          title: "ATT&CK matrix",
        });
      }
      if (e.is_deprecated) {
        out.push({
          label: e.superseded_by ? `Revoked → ${e.superseded_by}` : "Deprecated",
          tone: "danger",
          title: e.superseded_by
            ? `Revoked by MITRE — replaced by ${e.superseded_by}`
            : "Deprecated by MITRE — no longer part of ATT&CK",
        });
      }
      return out;
    },
    identityFields: [],
    hasAliases: false,
    hasDescription: true,
    nameEditable: false,
    monoIdKey: "technique_id",
    overviewPanels: ["context", "ttp_mitre", "ttp_family", "ttp_mitigations"],
    externalLinks: (e) => getPivotLinks("ttp", e.technique_id || ""),
    cascadeType: "ttp",
    actions: ["add_to_campaign", "generate_report", "ai_summary", "convert", "fetch_wikipedia", "rescan", "unlink_all", "clear_timeline", "delete"],
  },

  country: {
    tabs: ["overview", "relationships", "geography"],
    signalBadges: (e) => [
      { label: e.region || "", tone: "neutral", title: "Region", editKey: "region", editKind: "text", placeholder: "set region" },
    ],
    identityFields: [
      { label: "ISO Code", key: "iso_code", kind: "text", placeholder: "Set ISO code" },
    ],
    hasAliases: true,
    hasDescription: true,
    nameEditable: true,
    overviewPanels: ["context"],
    externalLinks: (e) => getPivotLinks("country", e.name || ""),
    cascadeType: "country",
    actions: ["add_to_campaign", "generate_report", "ai_summary", "convert", "merge", "fetch_wikipedia", "rescan", "unlink_all", "clear_timeline", "delete"],
  },

  // A sector is a closed vocabulary, not an extracted entity: no create, merge,
  // convert, delete, or rescan (sectors are never autolinked). Its name and
  // slug are the vocabulary itself; aliases and description are editable.
  sector: {
    tabs: ["overview", "victimology", "relationships"],
    signalBadges: (e) =>
      e.slug ? [{ label: e.slug, tone: "neutral", title: "Canonical slug — what sector.slug: searches" }] : [],
    identityFields: [],
    hasAliases: true,
    hasDescription: true,
    nameEditable: false,
    overviewPanels: ["context"],
    externalLinks: (e) => getPivotLinks("sector", e.name || ""),
    actions: ["add_to_campaign", "generate_report", "ai_summary"],
  },

  tool: {
    tabs: ["overview", "relationships"],
    // Tool type is read-only — the badge is its single representation.
    signalBadges: (e) =>
      e.tool_type
        ? [{ label: e.tool_type.replace(/_/g, " "), tone: "info", title: "Tool type", provenanceKey: "tool_type" }]
        : [],
    identityFields: [],
    hasAliases: true,
    hasDescription: true,
    nameEditable: true,
    // Malpedia/GitHub moved into the Sources rail card.
    overviewPanels: ["context", "infrastructure"],
    cascadeType: "tool",
    actions: ["add_to_campaign", "generate_report", "ai_summary", "convert", "merge", "fetch_wikipedia", "rescan", "unlink_all", "clear_timeline", "delete"],
  },

  // The IOC ledger's profile: the lightest in the app. Identity is the
  // (kind, value) pair — value renders as the mono hero name via
  // entityDisplayName's `e.value` fallback — and every badge is a lifecycle
  // fact (kind, role, decayed confidence, state) rather than an editable field.
  observable: {
    tabs: ["overview", "relationships"],
    signalBadges: (e) => [
      ...(e.kind ? [{ label: e.kind, tone: "info" as BadgeTone, title: "Observable kind" }] : []),
      ...(e.role ? [{ label: `role · ${e.role}`, tone: "neutral" as BadgeTone, title: "What this value was doing, per the capturing door" }] : []),
      ...(typeof e.current_confidence === "number"
        ? [{
            label: `confidence ${Math.round(e.current_confidence * 100)}%`,
            tone: (e.current_confidence >= 0.5 ? "success" : e.current_confidence >= 0.15 ? "warning" : "neutral") as BadgeTone,
            title: "Current confidence — decays with age for network kinds, resets on a new sighting",
          }]
        : []),
      ...(e.status && e.status !== "active"
        ? [{ label: e.status, tone: "warning" as BadgeTone, title: "Lifecycle state" }]
        : []),
      ...(e.created_via ? [{ label: `via ${String(e.created_via).replace(/_/g, " ")}`, tone: "neutral" as BadgeTone, title: "What created this row" }] : []),
    ],
    identityFields: [],
    hasAliases: false,
    hasDescription: true,
    nameEditable: false,
    monoIdKey: "value",
    overviewPanels: ["context", "observable_provenance", "observable_backlinks"],
    externalLinks: (e) =>
      e.kind && e.value
        ? observablePivotLinks(e.kind, e.value).map((l) => ({ platform: l.label, url: l.url }))
        : [],
    cascadeType: "observable",
    // Delete drops the row outright; the delete popover's "never capture it
    // again" option swaps in the deny tombstone instead, which keeps the row
    // so every capture door can go on refusing the value.
    actions: ["add_to_campaign", "generate_report", "ai_summary", "unlink_all", "delete"],
  },

  mitigation: {
    tabs: ["overview", "relationships"],
    // MITRE id is read-only — the badge is its single representation.
    signalBadges: (e) => (e.mitre_id ? [{ label: e.mitre_id, tone: "neutral", title: "MITRE ID" }] : []),
    identityFields: [],
    hasAliases: false,
    hasDescription: true,
    nameEditable: false,
    overviewPanels: ["context"],
    actions: ["add_to_campaign", "generate_report", "ai_summary", "fetch_wikipedia", "rescan", "unlink_all", "clear_timeline", "delete"],
  },

  vendor: {
    tabs: ["overview", "vulnerabilities", "relationships"],
    signalBadges: (e) => [
      { label: e.vendor_type || "", tone: "info", title: "Vendor type", editKey: "vendor_type", editKind: "text", placeholder: "set type" },
    ],
    identityFields: [
      { label: "Website", key: "website", kind: "text", placeholder: "Set website" },
    ],
    hasAliases: true,
    hasDescription: true,
    nameEditable: true,
    // Website lives in the Snapshot/Sources cards, not a one-link panel.
    overviewPanels: ["context", "cwe_vendors"],
    cascadeType: "vendor",
    actions: ["add_to_campaign", "generate_report", "ai_summary", "convert", "merge", "fetch_wikipedia", "rescan", "unlink_all", "clear_timeline", "delete"],
  },

  product: {
    tabs: ["overview", "vulnerabilities", "relationships"],
    signalBadges: (e) => [
      { label: e.product_type || "", tone: "info", title: "Product type", editKey: "product_type", editKind: "text", placeholder: "set type" },
    ],
    identityFields: [
      { label: "Vendor", key: "vendor_id", kind: "vendor" },
      { label: "Website", key: "website", kind: "text", placeholder: "Set website" },
    ],
    hasAliases: true,
    hasDescription: true,
    nameEditable: true,
    overviewPanels: ["context", "cwe_vendors"],
    cascadeType: "product",
    actions: ["add_to_campaign", "generate_report", "ai_summary", "convert", "merge", "fetch_wikipedia", "rescan", "unlink_all", "clear_timeline", "delete"],
  },
};

export function getEntityProfileConfig(type: EntityType): EntityProfileConfig {
  return ENTITY_PROFILE_CONFIG[type];
}

/** Route path to an entity's full-width profile page. */
export function entityProfilePath(type: EntityType, id: string): string {
  return `/workbench/${type}/${id}`;
}

/** Best-effort display name across entity types. */
export function entityDisplayName(e: EntitySearchResult | undefined, fallback = ""): string {
  if (!e) return fallback;
  return (
    // CWE carries both an id and a name and reads as one label, the same way a
    // technique does — so it is checked before the bare-name fallback.
    (e.cwe_id ? `${e.cwe_id}${e.name && e.name !== e.cwe_id ? ` ${e.name}` : ""}` : "") ||
    e.name ||
    e.cve_id ||
    // Skip the name when it just mirrors the ID (un-hydrated stub rows)
    (e.technique_id
      ? `${e.technique_id}${e.technique_name && e.technique_name !== e.technique_id ? ` ${e.technique_name}` : ""}`
      : "") ||
    e.value ||
    fallback
  );
}

// re-export for convenience
