/**
 * relationshipBrowser — pure helpers for the profile Relationships browser:
 * flattening pivot payloads into uniform rows, verb labeling, the trust
 * ladder, and verb grouping. Kept free of React so the logic is unit-testable.
 */
import type { EntitySearchResult, PivotResponse } from "@/api/types";
import type { EntityType } from "@/stores/intelStore";

export interface RelRow {
  type: EntityType;
  item: EntitySearchResult;
  label: string;
  meta?: string;
}

const TYPE_KEYS: Array<[EntityType, string]> = [
  ["threat_actor", "threat_actors"],
  ["malware", "malwares"],
  ["cve", "cves"],
  ["ttp", "ttps"],
  ["country", "countrys"],
  ["vendor", "vendors"],
  ["product", "products"],
  ["tool", "tools"],
  ["mitigation", "mitigations"],
  ["cwe", "cwes"],
  ["observable", "observables"],
];

export const RELATED_KEY: Record<string, string> = Object.fromEntries(TYPE_KEYS);
export const TYPE_ORDER: EntityType[] = TYPE_KEYS.map(([t]) => t);

/** Stable identity for a related-entity row across list, folds, and map. */
export const rowKey = (r: RelRow): string => `${r.type}-${r.item.id}`;

/**
 * Mirror of the backend semantic matrix (app/intelligence/relationship_matrix.py),
 * keyed "source>target" as stored. The API rejects triples outside it and flips
 * reversed ones, so creation UIs should only offer verbs from this map.
 */
const ALLOWED_MATRIX: Record<string, readonly string[]> = {
  "threat_actor>malware": ["uses", "delivers", "related_to"],
  "threat_actor>tool": ["uses"],
  "threat_actor>ttp": ["uses"],
  "threat_actor>cve": ["exploits"],
  "threat_actor>country": ["targets", "attributed_to"],
  "threat_actor>vendor": ["targets"],
  "threat_actor>product": ["targets"],
  "threat_actor>threat_actor": ["related_to", "communicates_with", "successor_of", "subgroup_of", "overlaps_with"],
  "malware>threat_actor": ["attributed_to", "related_to"],
  "malware>malware": ["variant_of", "delivers", "drops", "communicates_with", "related_to", "successor_of", "overlaps_with"],
  "malware>tool": ["uses", "related_to"],
  "malware>ttp": ["uses"],
  "malware>cve": ["exploits"],
  "malware>country": ["targets"],
  "malware>vendor": ["targets"],
  "malware>product": ["targets"],
  "tool>malware": ["delivers"],
  "tool>ttp": ["related_to"],
  "tool>cve": ["exploits"],
  "cve>ttp": ["related_to"],
  "campaign>threat_actor": ["attributed_to"],
  "campaign>malware": ["uses"],
  "campaign>tool": ["uses"],
  "campaign>ttp": ["uses"],
  "campaign>cve": ["exploits"],
  "campaign>country": ["targets"],
  "campaign>vendor": ["targets"],
  "campaign>product": ["targets"],
  "vendor>vendor": ["related_to"],
  "vendor>product": ["related_to"],
  "product>product": ["related_to"],
};

/**
 * Verbs valid between two entity types in either orientation (the API stores
 * a reversed triple in its canonical direction automatically). Empty result
 * means the pair is not a tracked combination.
 */
export function allowedVerbsForPair(a: string, b: string): string[] {
  const fwd = ALLOWED_MATRIX[`${a}>${b}`] ?? [];
  const rev = a === b ? [] : (ALLOWED_MATRIX[`${b}>${a}`] ?? []);
  return [...new Set([...fwd, ...rev])];
}

export function rowLabel(type: EntityType, item: EntitySearchResult): string {
  if (type === "cve") return item.cve_id || item.name || item.id;
  if (type === "ttp") return [item.technique_id, item.technique_name].filter(Boolean).join(" ") || item.id;
  if (type === "mitigation") return item.name || item.mitre_id || item.id;
  if (type === "cwe") return [item.cwe_id, item.name].filter(Boolean).join(" ") || item.id;
  if (type === "observable") return item.value || item.label || item.id;
  return item.name || item.id;
}

export function rowMeta(type: EntityType, item: EntitySearchResult): string | undefined {
  switch (type) {
    case "threat_actor": return item.country ?? undefined;
    case "malware": return item.malware_type ?? undefined;
    case "cve": return item.severity ?? undefined;
    case "country": return item.region ?? undefined;
    case "vendor": return item.vendor_type ?? undefined;
    case "product": return item.product_type ?? undefined;
    case "tool": return item.tool_type ?? undefined;
    case "mitigation": return item.mitre_id ?? undefined;
    default: return undefined;
  }
}

/** Flatten a pivot `related` dict into uniform rows (same-type groups stay
 * hidden except CVEs, matching the previous tab behavior). */
export function flattenRelated(
  related: PivotResponse["related"],
  viewedType: EntityType,
): RelRow[] {
  const rows: RelRow[] = [];
  const rel = related as unknown as Record<string, EntitySearchResult[] | undefined>;
  for (const [type, key] of TYPE_KEYS) {
    if (type === viewedType && type !== "cve") continue;
    for (const item of rel[key] ?? []) {
      rows.push({ type, item, label: rowLabel(type, item), meta: rowMeta(type, item) });
    }
  }
  return rows;
}

export function verbKeyOf(item: EntitySearchResult): string {
  return item.country_relationship ?? item.relationship_type ?? "co_mentioned";
}

/**
 * Verb forms keyed by relationship type, read from the VIEWED entity's
 * perspective: `active` when the viewed entity is the SUBJECT (viewed <verb>
 * other), `passive` when the viewed entity is the OBJECT (other <verb> viewed
 * → "viewed <passive> other"). Symmetric verbs use the same form for both.
 */
const VERB_CHIP: Record<string, { active: string; passive: string }> = {
  uses: { active: "uses", passive: "used by" },
  exploits: { active: "exploits", passive: "exploited by" },
  targets: { active: "targets", passive: "targeted by" },
  attributed_to: { active: "attributed to", passive: "attribution of" },
  variant_of: { active: "variant of", passive: "has variant" },
  communicates_with: { active: "communicates with", passive: "communicates with" },
  delivers: { active: "delivers", passive: "delivered by" },
  drops: { active: "drops", passive: "dropped by" },
  hosts: { active: "hosts", passive: "hosted by" },
  related_to: { active: "related to", passive: "related to" },
  // ATT&CK catalog technique↔mitigation mappings, synthesized into the pivot.
  mitigated_by: { active: "mitigated by", passive: "mitigates" },
  mitigates: { active: "mitigates", passive: "mitigated by" },
  operates_from: { active: "operates from", passive: "origin of" },
  infrastructure: { active: "infrastructure in", passive: "infrastructure for" },
  co_mentioned: { active: "co-mentioned", passive: "co-mentioned" },
};

/**
 * Chip text for a row, read from the VIEWED entity's perspective. Outbound
 * relationships (viewed → other) read actively ("[APT28] uses Cobalt Strike");
 * inbound (other → viewed) read with the inverse form ("[Pegasus] used by
 * NSO Group"). Country annotations always describe the actor acting on the
 * viewed country, so the country is the object ("[Germany] targeted by APT28").
 */
export function verbChipLabel(item: EntitySearchResult): string {
  const key = verbKeyOf(item);
  const v = VERB_CHIP[key] ?? { active: key.replace(/_/g, " "), passive: key.replace(/_/g, " ") };
  if (item.country_relationship) return v.passive;
  return item.relationship_direction === "inbound" ? v.passive : v.active;
}

/** Full sentence for tooltips: "APT28 targets Germany". */
export function verbSentence(item: EntitySearchResult, otherLabel: string, viewedLabel: string): string {
  const key = verbKeyOf(item);
  const v = VERB_CHIP[key] ?? { active: key.replace(/_/g, " "), passive: "" };
  if (key === "co_mentioned") return `${otherLabel} co-mentioned with ${viewedLabel}`;
  if (item.country_relationship || item.relationship_direction !== "outbound") {
    return `${otherLabel} ${v.active} ${viewedLabel}`;
  }
  return `${viewedLabel} ${v.active} ${otherLabel}`;
}

export function isConfirmed(item: EntitySearchResult): boolean {
  return item.relationship_confidence === "confirmed";
}

// ─── Trust ladder (Direction A) ────────────────────────────────────────────
// Trust is machine-earned: corroborated = confirmed by an authority (MITRE),
// the AI adjudicator, or an analyst pin; reported = evidence-backed claim
// awaiting corroboration; signal = engine inference only.

export type TrustTier = "corroborated" | "reported" | "signal";

export interface Trust {
  tier: TrustTier;
  /** Where the corroboration came from: "MITRE", "AI ×4", "you" — corroborated only. */
  provenance?: string;
}

export function trustOf(item: EntitySearchResult): Trust | null {
  if (!item.relationship_id) return null; // co-mention context, not a claim
  const conf = item.relationship_confidence;
  if (conf === "confirmed") {
    const src = item.relationship_source;
    let provenance = "AI";
    if (src === "external_feed") {
      // MITRE ATT&CK is currently the only authority minting external_feed
      // edges; differentiate via description if a second source ever ships.
      provenance = "MITRE";
    } else if (src === "analyst_confirmed" || src === "analyst_created") {
      provenance = "you";
    } else if (item.relationship_adjudication === "corroborated") {
      // Only the adjudicator's verdict earns the ×N evidence claim — a
      // legacy ingest-time confirmation shows plain "AI".
      provenance = `AI ×${item.relationship_evidence_count || 1}`;
    }
    return { tier: "corroborated", provenance };
  }
  if (conf === "probable") return { tier: "reported" };
  return { tier: "signal" };
}

const TRUST_RANK: Record<TrustTier, number> = { corroborated: 2, reported: 1, signal: 0 };

// ─── Evidence structure (story clustering over evidence entries) ───────────
// The backend clusters each edge's evidence into stories; the shape says what
// the reporting record looks like. Rows are earned by their shape; thin and
// scattered claims fold. Absent structure (feature off / no embeddings)
// degrades to article counts.

export type EvidenceShape = "recurring" | "single_story" | "scattered" | "thin";

/** Lower = better evidence. Unknown structure ranks between story-backed and story-less. */
const SHAPE_RANK: Record<EvidenceShape, number> = { recurring: 0, single_story: 1, scattered: 3, thin: 4 };

export function shapeRank(item: EntitySearchResult): number {
  const s = item.evidence_structure?.shape;
  return s ? SHAPE_RANK[s] : 2;
}

function spanLabel(es: NonNullable<EntitySearchResult["evidence_structure"]>): string | null {
  const dates = es.stories.flatMap((s) => [s.first, s.last]).filter(Boolean) as string[];
  if (dates.length < 2) return null;
  const months = Math.round(
    (new Date(dates.reduce((a, b) => (a > b ? a : b))).getTime() -
      new Date(dates.reduce((a, b) => (a < b ? a : b))).getTime()) /
      (30 * 86_400_000),
  );
  if (months < 2) return null;
  return months < 12 ? `${months} months` : `${Math.round(months / 12)}y`;
}

export interface StructurePhrase {
  /** The bold shape word ("recurring", "one story"). */
  lead: string;
  /** The muted remainder ("— 4 incidents over 6 months"). */
  rest: string;
}

/**
 * Evidence phrase for a row, split so the row can bold the shape word and
 * mute the rest ("**recurring** — 2 incidents over 6 months"). Null for thin
 * rows (their fold label already says it) and when no structure is available.
 */
export function structurePhrase(item: EntitySearchResult): StructurePhrase | null {
  const es = item.evidence_structure;
  if (!es) return null;
  switch (es.shape) {
    case "recurring": {
      const span = spanLabel(es);
      return {
        lead: "recurring",
        rest: `— ${es.stories.length} incidents${span ? ` over ${span}` : ""}`,
      };
    }
    case "single_story": {
      const st = es.stories[0];
      if (!st) return { lead: "one story", rest: "" };
      if (st.title) {
        return {
          lead: "one story",
          rest: `— “${st.title}”${st.sources && st.sources > 1 ? ` · ${st.sources} outlets` : ""}`,
        };
      }
      if (st.sources && st.sources >= 10) {
        return { lead: "one story", rest: `— a single ${st.sources}-outlet wave` };
      }
      if (st.sources && st.sources > 1) {
        return { lead: "one story", rest: `· ${st.sources} outlets` };
      }
      return { lead: "one story", rest: `· ${st.entries} of ${es.sampled} articles` };
    }
    case "scattered":
      return { lead: "no shared story", rest: "— scattered co-mentions" };
    case "thin":
      return null;
  }
}

/**
 * A row is earned when its evidence carries an actual story (or an authority /
 * analyst corroborated it, or it's a deliberate claim with no co-occurrence
 * evidence at all — MITRE imports, manual links). Everything else folds into
 * the per-group "claims without a story" line.
 */
export function isEarnedRow(row: RelRow): boolean {
  const item = row.item;
  if (trustOf(item)?.tier === "corroborated") return true;
  const ev = item.proximity_entries ?? [];
  if (ev.length === 0) return true;
  const shape = item.evidence_structure?.shape;
  if (shape) return shape === "recurring" || shape === "single_story";
  return (item.strength?.articles ?? ev.length) >= 2;
}

export function partitionEarned(rows: RelRow[]): { earned: RelRow[]; folded: RelRow[] } {
  const earned: RelRow[] = [];
  const folded: RelRow[] = [];
  for (const r of rows) (isEarnedRow(r) ? earned : folded).push(r);
  return { earned, folded };
}

/**
 * Implausible CVE ids — extraction junk that should never rank with real
 * vulnerabilities: a year outside CVE's existence, a 7+ digit sequence, or a
 * modern-era sequence past anything MITRE has assigned (the pre-2020 DWF
 * blocks legitimately used 7-digit-looking 101xxxx ids, so old years pass).
 */
export function isImplausibleCveId(label: string): boolean {
  const m = /^CVE-(\d{4})-(\d+)$/i.exec(label.trim());
  if (!m) return false;
  const year = Number(m[1]);
  const seq = m[2];
  if (year < 1999 || year > new Date().getFullYear() + 1) return true;
  if (seq.length >= 8) return true;
  if (year >= 2020 && Number(seq) > 99_999) return true;
  return false;
}

/**
 * Everyday software named in passing — ubiquitous tools (GitHub, Notepad++)
 * whose asserted edge is riding coverage volume, not tradecraft. Uses the
 * specificity (IDF) the pivot already computes; recurring or corroborated
 * edges always stay rows (Cobalt Strike is ubiquitous AND tradecraft — the
 * evidence shape is what separates the two).
 */
export function isEverydaySoftware(row: RelRow): boolean {
  if (row.type !== "tool") return false;
  const item = row.item;
  if (trustOf(item)?.tier === "corroborated") return false;
  if (item.evidence_structure?.shape === "recurring") return false;
  const spec = item.strength?.specificity;
  return spec != null && spec < 0.45;
}

/** Region names that sometimes get mis-filed as countries by extraction. */
export const REGION_NAMES = new Set([
  "europe",
  "asia",
  "africa",
  "oceania",
  "north america",
  "south america",
  "latin america",
  "middle east",
  "western europe",
  "eastern europe",
  "southeast asia",
]);

// ─── Story map (the graph's operations clusters) ───────────────────────────
// Each earned row's evidence stories carry their entry ids; stories from
// different rows that share articles (or a thread slug) are the same incident.
// Union-find merges them into clusters — an operations map assembled entirely
// from data the pivot already returns.

export interface StoryMapMember {
  row: RelRow;
  entryIds: string[];
}

export interface StoryMapCluster {
  title: string | null;
  /** Lead headline from the cluster's own evidence — the fallback name when
   * no story thread has titled this incident. */
  headline: string | null;
  slug: string | null;
  first: string | null;
  last: string | null;
  entryIds: string[];
  corroborated: boolean;
  members: StoryMapMember[];
}

/** Display heading for a story cluster: thread title, else the lead
 * headline from its evidence, else a date range — so clusters are never a
 * wall of anonymous "Story" labels. */
export function clusterHeading(c: StoryMapCluster): string {
  if (c.title) return c.title;
  if (c.headline) return c.headline.length > 60 ? `${c.headline.slice(0, 59)}…` : c.headline;
  const monthOf = (iso: string | null) =>
    iso ? new Date(iso).toLocaleDateString(undefined, { month: "short", year: "numeric" }) : "";
  const a = monthOf(c.first);
  const b = monthOf(c.last);
  return a && b && a !== b ? `Story · ${a} – ${b}` : `Story · ${a || b || "undated"}`;
}

export function buildStoryMap(earned: RelRow[]): StoryMapCluster[] {
  type Frag = { row: RelRow; ids: string[]; slug: string | null; title: string | null; first: string | null; last: string | null };
  const frags: Frag[] = [];
  const entryTitles = new Map<string, { title: string; published: string }>();
  for (const row of earned) {
    for (const pe of row.item.proximity_entries ?? []) {
      if (pe.title && !entryTitles.has(pe.entry_id)) {
        entryTitles.set(pe.entry_id, { title: pe.title, published: pe.published_at ?? "" });
      }
    }
    for (const st of row.item.evidence_structure?.stories ?? []) {
      if ((st.entry_ids ?? []).length === 0) continue;
      frags.push({ row, ids: st.entry_ids, slug: st.slug, title: st.title, first: st.first, last: st.last });
    }
  }
  if (frags.length === 0) return [];

  // Union-find over fragments: same slug or any shared entry id → same story.
  const parent = frags.map((_, i) => i);
  const find = (i: number): number => (parent[i] === i ? i : (parent[i] = find(parent[i])));
  const union = (a: number, b: number) => {
    parent[find(a)] = find(b);
  };
  const byEntry = new Map<string, number>();
  const bySlug = new Map<string, number>();
  frags.forEach((f, i) => {
    if (f.slug) {
      const prev = bySlug.get(f.slug);
      if (prev !== undefined) union(i, prev);
      else bySlug.set(f.slug, i);
    }
    for (const id of f.ids) {
      const prev = byEntry.get(id);
      if (prev !== undefined) union(i, prev);
      else byEntry.set(id, i);
    }
  });

  const groups = new Map<number, Frag[]>();
  frags.forEach((f, i) => {
    const root = find(i);
    (groups.get(root) ?? groups.set(root, []).get(root)!).push(f);
  });

  const clusters: StoryMapCluster[] = [];
  for (const group of groups.values()) {
    const entryIds = [...new Set(group.flatMap((f) => f.ids))];
    const memberByKey = new Map<string, StoryMapMember>();
    for (const f of group) {
      const key = `${f.row.type}-${f.row.item.id}`;
      const existing = memberByKey.get(key);
      if (existing) existing.entryIds = [...new Set([...existing.entryIds, ...f.ids])];
      else memberByKey.set(key, { row: f.row, entryIds: [...f.ids] });
    }
    const dates = group.flatMap((f) => [f.first, f.last]).filter(Boolean) as string[];
    let headline: string | null = null;
    let headlineDate = "";
    for (const id of entryIds) {
      const t = entryTitles.get(id);
      if (t && t.published >= headlineDate) {
        headline = t.title;
        headlineDate = t.published;
      }
    }
    clusters.push({
      title: group.find((f) => f.title)?.title ?? null,
      headline,
      slug: group.find((f) => f.slug)?.slug ?? null,
      first: dates.length ? dates.reduce((a, b) => (a < b ? a : b)) : null,
      last: dates.length ? dates.reduce((a, b) => (a > b ? a : b)) : null,
      entryIds,
      corroborated: group.some((f) => trustOf(f.row.item)?.tier === "corroborated"),
      members: [...memberByKey.values()],
    });
  }

  clusters.sort((a, b) => b.entryIds.length - a.entryIds.length);

  // A node lives in its strongest cluster only — the one holding most of its
  // evidence — so the map shows each entity once.
  const homeOf = new Map<string, StoryMapCluster>();
  for (const c of clusters) {
    for (const m of c.members) {
      const key = `${m.row.type}-${m.row.item.id}`;
      const current = homeOf.get(key);
      if (!current) homeOf.set(key, c);
      else {
        const here = m.entryIds.length;
        const there = current.members.find((x) => `${x.row.type}-${x.row.item.id}` === key)?.entryIds.length ?? 0;
        if (here > there) homeOf.set(key, c);
      }
    }
  }
  for (const c of clusters) {
    c.members = c.members.filter((m) => homeOf.get(`${m.row.type}-${m.row.item.id}`) === c);
  }
  return clusters.filter((c) => c.members.length > 0);
}

export interface VerbGroup {
  /** Group key: `${direction}:${verb}` */
  key: string;
  verb: string;
  direction: "outbound" | "inbound";
  /** Heading text after the entity name ("uses") or standalone ("used by"). */
  label: string;
  rows: RelRow[];
}

const VERB_ORDER = [
  "uses",
  "exploits",
  "targets",
  "delivers",
  "drops",
  "attributed_to",
  "variant_of",
  "successor_of",
  "subgroup_of",
  "overlaps_with",
  "communicates_with",
  "hosts",
  "related_to",
  "mitigates",
  "mitigated_by",
];

/** Split rows into asserted (typed claims) and co-mention context. */
export function splitAssertedContext(rows: RelRow[]): { asserted: RelRow[]; context: RelRow[] } {
  const asserted: RelRow[] = [];
  const context: RelRow[] = [];
  for (const r of rows) (r.item.relationship_id ? asserted : context).push(r);
  return { asserted, context };
}

/** Group asserted rows by (direction, verb); rows sorted trust-then-strength. */
export function groupByVerb(asserted: RelRow[]): VerbGroup[] {
  const groups = new Map<string, VerbGroup>();
  for (const r of asserted) {
    const verb = r.item.relationship_type || "related_to";
    const direction = r.item.relationship_direction === "inbound" ? "inbound" : "outbound";
    const key = `${direction}:${verb}`;
    let g = groups.get(key);
    if (!g) {
      const forms = VERB_CHIP[verb] ?? { active: verb.replace(/_/g, " "), passive: verb.replace(/_/g, " ") };
      g = { key, verb, direction, label: direction === "inbound" ? forms.passive : forms.active, rows: [] };
      groups.set(key, g);
    }
    g.rows.push(r);
  }
  const orderOf = (v: string) => {
    const i = VERB_ORDER.indexOf(v);
    return i === -1 ? VERB_ORDER.length : i;
  };
  const out = [...groups.values()];
  for (const g of out) {
    g.rows.sort((a, b) => {
      const t =
        TRUST_RANK[trustOf(b.item)?.tier ?? "signal"] - TRUST_RANK[trustOf(a.item)?.tier ?? "signal"];
      if (t !== 0) return t;
      const s = shapeRank(a.item) - shapeRank(b.item);
      if (s !== 0) return s;
      return (b.item.proximity_score ?? 0) - (a.item.proximity_score ?? 0);
    });
  }
  out.sort((a, b) => {
    if (a.direction !== b.direction) return a.direction === "outbound" ? -1 : 1;
    return orderOf(a.verb) - orderOf(b.verb);
  });
  return out;
}

export function timeAgo(iso: string | null | undefined): string {
  if (!iso) return "";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "";
  const days = Math.floor((Date.now() - then) / 86_400_000);
  if (days <= 0) return "today";
  if (days < 30) return `${days}d ago`;
  if (days < 365) return `${Math.floor(days / 30)}mo ago`;
  return `${Math.floor(days / 365)}y ago`;
}
