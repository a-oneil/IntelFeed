/**
 * cveRefs — shared helpers for reading a CVE's NVD blob and reference set.
 * Used by the Overview's Snapshot/Sources rail cards and the affected panel.
 */

export interface RefLink {
  url: string;
  tags: string[];
}

// Best-effort extraction from the NVD JSON blob (shape varies by source).
export function extractNvd(nvd: Record<string, unknown> | undefined | null): {
  vector: string | null;
  cwe: string | null;
  references: RefLink[];
  /** NVD publication date — the lifecycle strip's "Disclosed" stage. */
  published: string | null;
} {
  if (!nvd) return { vector: null, cwe: null, references: [], published: null };
  /* eslint-disable @typescript-eslint/no-explicit-any */
  const n: any = nvd;
  const root = n.cve ?? n;
  const metrics = root.metrics ?? n.metrics;
  const vector =
    metrics?.cvssMetricV40?.[0]?.cvssData?.vectorString ??
    metrics?.cvssMetricV31?.[0]?.cvssData?.vectorString ??
    metrics?.cvssMetricV30?.[0]?.cvssData?.vectorString ??
    metrics?.cvssMetricV2?.[0]?.cvssData?.vectorString ??
    n.vector ??
    null;
  let cwe: string | null = null;
  const weaknesses = root.weaknesses ?? n.weaknesses;
  if (Array.isArray(weaknesses)) {
    for (const w of weaknesses) {
      const d = (w?.description ?? []).find((x: any) => typeof x?.value === "string" && x.value.startsWith("CWE-"));
      if (d) { cwe = d.value; break; }
    }
  }
  const refsRaw = root.references ?? n.references ?? [];
  const references: RefLink[] = Array.isArray(refsRaw)
    ? refsRaw
        .map((r: any) => (typeof r === "string" ? { url: r, tags: [] } : { url: r?.url, tags: Array.isArray(r?.tags) ? r.tags : [] }))
        .filter((r: any): r is RefLink => typeof r.url === "string")
    : [];
  const published =
    (typeof root.published === "string" && root.published) ||
    (typeof n.publishedDate === "string" && n.publishedDate) ||
    null;
  /* eslint-enable @typescript-eslint/no-explicit-any */
  return { vector, cwe, references, published };
}

// Group references into advisory / patch / analysis / other buckets based on
// NVD reference tags, labeled by source domain instead of "ref 1..N".
const REF_GROUP_ORDER = ["Advisories", "Patches", "Analysis", "Other"] as const;

export function refDomain(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url.slice(0, 40);
  }
}

function refGroup(tags: string[]): (typeof REF_GROUP_ORDER)[number] {
  const t = tags.map((x) => x.toLowerCase());
  if (t.some((x) => x.includes("patch"))) return "Patches";
  if (t.some((x) => x.includes("advisory") || x.includes("mitigation") || x.includes("government resource"))) return "Advisories";
  if (t.some((x) => x.includes("exploit") || x.includes("technical") || x.includes("vdb") || x.includes("press"))) return "Analysis";
  return "Other";
}

export function groupReferences(refs: RefLink[]): Array<{ group: string; links: RefLink[] }> {
  // Dedupe by URL. No cap here — the Sources card caps its render and offers
  // an "all N references" expansion, so nothing is silently dropped.
  const seen = new Set<string>();
  const buckets = new Map<string, RefLink[]>();
  for (const r of refs) {
    if (!r.url || seen.has(r.url)) continue;
    seen.add(r.url);
    const g = refGroup(r.tags);
    if (!buckets.has(g)) buckets.set(g, []);
    buckets.get(g)!.push(r);
  }
  return REF_GROUP_ORDER
    .filter((g) => buckets.has(g))
    .map((g) => ({ group: g, links: buckets.get(g)! }));
}

export function dedupeProducts(raw: unknown[] | undefined): string[] {
  if (!raw) return [];
  const seen = new Map<string, string>();
  for (const p of raw) {
    const label = typeof p === "string" ? p : String((p as Record<string, unknown>)?.product || (p as Record<string, unknown>)?.name || "");
    const key = label.trim().toLowerCase();
    if (key && !seen.has(key)) seen.set(key, label);
  }
  return Array.from(seen.values());
}
