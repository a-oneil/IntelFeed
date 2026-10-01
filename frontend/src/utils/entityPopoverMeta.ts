// Build the generic popover metadata (description + key facts + links + Wikipedia
// thumbnail) for each entity type. All fields come from entity payloads already
// fetched for highlighting (entry-entity endpoints or the public shared-entry
// response), so no extra request is made.

import type { ThreatActor, MalwareFamily, Vendor, Product, OffensiveTool, Country, Sector, Mitigation, CWEResponse } from "@/api/types";
import type { HighlightEntityMeta } from "@/components/InlineEntityHighlighter";

type MetaLink = { label: string; url: string };

/** Append a Wikipedia reference link when the entity has been enriched with one. */
function withWiki(links: MetaLink[], url?: string | null): MetaLink[] {
  if (url) links.push({ label: "Wikipedia", url });
  return links;
}

export function actorMeta(a: ThreatActor): HighlightEntityMeta {
  const facts: NonNullable<HighlightEntityMeta["facts"]> = [];
  if (a.motivation) facts.push({ label: "Motivation", value: a.motivation });
  if (a.country) facts.push({ label: "Origin", value: a.country });
  if (a.targeted_sectors?.length)
    facts.push({ label: "Targets", value: a.targeted_sectors.slice(0, 3).join(", ") });
  const links: MetaLink[] = [];
  if (a.mitre_id) links.push({ label: "MITRE ATT&CK", url: `https://attack.mitre.org/groups/${a.mitre_id}/` });
  return { description: a.description, facts, aliases: a.aliases, links: withWiki(links, a.wikipedia_url), image_url: a.wikipedia_image_url, article_count: a.article_count, first_seen_at: a.first_seen_at };
}

export function malwareMeta(m: MalwareFamily): HighlightEntityMeta {
  const facts: NonNullable<HighlightEntityMeta["facts"]> = [];
  if (m.malware_type) facts.push({ label: "Type", value: m.malware_type });
  const links: MetaLink[] = [];
  if (m.malpedia_url) links.push({ label: "Malpedia", url: m.malpedia_url });
  return { description: m.description, facts, aliases: m.aliases, links: withWiki(links, m.wikipedia_url), image_url: m.wikipedia_image_url, article_count: m.article_count, first_seen_at: m.first_seen_at };
}

export function vendorMeta(v: Vendor): HighlightEntityMeta {
  const facts: NonNullable<HighlightEntityMeta["facts"]> = [];
  if (v.vendor_type) facts.push({ label: "Type", value: v.vendor_type });
  const links: MetaLink[] = [];
  if (v.website) links.push({ label: "Website", url: v.website });
  return { description: v.description, facts, aliases: v.aliases, links: withWiki(links, v.wikipedia_url), image_url: v.wikipedia_image_url, article_count: v.article_count, first_seen_at: v.first_seen_at };
}

export function productMeta(p: Product): HighlightEntityMeta {
  const facts: NonNullable<HighlightEntityMeta["facts"]> = [];
  if (p.vendor_name) facts.push({ label: "Vendor", value: p.vendor_name });
  if (p.product_type) facts.push({ label: "Type", value: p.product_type });
  const links: MetaLink[] = [];
  if (p.website) links.push({ label: "Website", url: p.website });
  return { description: p.description, facts, aliases: p.aliases, links: withWiki(links, p.wikipedia_url), image_url: p.wikipedia_image_url, article_count: p.article_count, first_seen_at: p.first_seen_at };
}

export function toolMeta(t: OffensiveTool): HighlightEntityMeta {
  const facts: NonNullable<HighlightEntityMeta["facts"]> = [];
  if (t.tool_type) facts.push({ label: "Type", value: t.tool_type });
  if (t.platforms?.length) facts.push({ label: "Platforms", value: t.platforms.slice(0, 3).join(", ") });
  const links: MetaLink[] = [];
  if (t.github_url) links.push({ label: "GitHub", url: t.github_url });
  if (t.malpedia_url) links.push({ label: "Malpedia", url: t.malpedia_url });
  // Flatten detection_artifacts (hashes, registry keys, network signatures) into
  // a labelled list — directly actionable for a detection engineer.
  const artifacts: NonNullable<HighlightEntityMeta["artifacts"]> = [];
  for (const [key, raw] of Object.entries(t.detection_artifacts ?? {})) {
    const value = Array.isArray(raw) ? raw.join(", ") : String(raw ?? "");
    if (value && value !== "null" && value !== "{}")
      artifacts.push({ label: key.replace(/_/g, " "), value });
  }
  return { description: t.description, facts, aliases: t.aliases, links: withWiki(links, t.wikipedia_url), image_url: t.wikipedia_image_url, artifacts, article_count: t.article_count, first_seen_at: t.first_seen_at };
}

export function countryMeta(c: Country): HighlightEntityMeta {
  const facts: NonNullable<HighlightEntityMeta["facts"]> = [];
  if (c.region) facts.push({ label: "Region", value: c.region });
  return { description: c.description, facts, aliases: c.aliases, links: withWiki([], c.wikipedia_url), image_url: c.wikipedia_image_url, article_count: c.article_count, first_seen_at: c.first_seen_at };
}

export function sectorMeta(s: Sector): HighlightEntityMeta {
  const facts: NonNullable<HighlightEntityMeta["facts"]> = [];
  if (s.victim_count) facts.push({ label: "Leak-site victims (90d)", value: String(s.victim_count) });
  if (s.targeting_actor_count) facts.push({ label: "Targeted by", value: `${s.targeting_actor_count} actors` });
  return { description: s.description, facts, aliases: s.aliases, links: [], article_count: s.article_count, first_seen_at: s.first_seen_at };
}

export function mitigationMeta(m: Mitigation): HighlightEntityMeta {
  const facts: NonNullable<HighlightEntityMeta["facts"]> = [];
  if (m.mitre_id) facts.push({ label: "MITRE ID", value: m.mitre_id });
  const links: MetaLink[] = [];
  if (m.mitre_url) links.push({ label: "MITRE ATT&CK", url: m.mitre_url });
  return { description: m.description, facts, links: withWiki(links, m.wikipedia_url), image_url: m.wikipedia_image_url, article_count: m.article_count, first_seen_at: m.first_seen_at };
}

export function cweMeta(c: CWEResponse): HighlightEntityMeta {
  const facts: NonNullable<HighlightEntityMeta["facts"]> = [];
  if (c.abstraction) facts.push({ label: "Abstraction", value: c.abstraction });
  if (c.parent_cwe_id) facts.push({ label: "Parent", value: c.parent_cwe_id });
  // Only worth surfacing when it is a warning — "Allowed" is the silent default.
  if (c.mapping_usage && c.mapping_usage !== "Allowed") {
    facts.push({ label: "MITRE mapping", value: c.mapping_usage });
  }
  if (c.likelihood_of_exploit) facts.push({ label: "Likelihood", value: c.likelihood_of_exploit });
  const links: MetaLink[] = [];
  if (c.cwe_url) links.push({ label: "MITRE CWE", url: c.cwe_url });
  return {
    description: c.description,
    facts,
    aliases: c.alternate_terms,
    links: withWiki(links, c.wikipedia_url),
    image_url: c.wikipedia_image_url,
    article_count: c.article_count,
    first_seen_at: c.first_seen_at,
  };
}

/** External reputation pivots per observable kind. */
export function observablePivotLinks(kind: string, value: string): MetaLink[] {
  const v = encodeURIComponent(value);
  switch (kind) {
    case "ipv4":
    case "ipv6":
      return [
        { label: "VirusTotal", url: `https://www.virustotal.com/gui/ip-address/${v}` },
        { label: "Shodan", url: `https://www.shodan.io/host/${v}` },
        { label: "GreyNoise", url: `https://viz.greynoise.io/ip/${v}` },
        { label: "AbuseIPDB", url: `https://www.abuseipdb.com/check/${v}` },
      ];
    case "domain":
      return [
        { label: "VirusTotal", url: `https://www.virustotal.com/gui/domain/${v}` },
        { label: "urlscan", url: `https://urlscan.io/search/#page.domain%3A${v}` },
        { label: "Shodan", url: `https://www.shodan.io/search?query=hostname%3A${v}` },
      ];
    case "url":
      return [{ label: "urlscan", url: `https://urlscan.io/search/#page.url%3A%22${v}%22` }];
    case "md5":
    case "sha1":
    case "sha256":
      return [
        { label: "VirusTotal", url: `https://www.virustotal.com/gui/file/${v}` },
        { label: "MalwareBazaar", url: `https://bazaar.abuse.ch/browse.php?search=hash%3A${v}` },
      ];
    case "ja3":
    case "ja4":
      return [{ label: "ja4db", url: `https://ja4db.com/search?q=${v}` }];
    case "cert_fingerprint":
      return [{ label: "crt.sh", url: `https://crt.sh/?q=${v}` }];
    default:
      return [];
  }
}

export function observableMeta(o: {
  kind: string;
  value: string;
  label?: string | null;
  role?: string | null;
  status?: string;
  current_confidence?: number;
  sighting_count?: number;
  created_via?: string | null;
  evidence?: string | null;
  description?: string | null;
  article_count?: number;
  first_seen_at?: string;
  last_seen_at?: string;
  was_defanged?: boolean | null;
}): HighlightEntityMeta {
  const facts: NonNullable<HighlightEntityMeta["facts"]> = [];
  facts.push({ label: "Kind", value: o.kind });
  if (o.role) facts.push({ label: "Role", value: o.role });
  if (typeof o.current_confidence === "number")
    facts.push({
      label: "Confidence",
      value: `${Math.round(o.current_confidence * 100)}%${o.status && o.status !== "active" ? ` · ${o.status}` : ""}`,
    });
  if (o.sighting_count != null) facts.push({ label: "Sightings", value: String(o.sighting_count) });
  if (o.created_via) facts.push({ label: "Captured by", value: o.created_via.replace(/_/g, " ") });
  if (o.last_seen_at)
    facts.push({ label: "Last seen", value: new Date(o.last_seen_at).toLocaleDateString(undefined, { month: "short", day: "numeric" }) });
  // The evidence sentence is the "why does this exist" — show it where tools
  // show their detection artifacts.
  const artifacts: NonNullable<HighlightEntityMeta["artifacts"]> = [];
  if (o.evidence) artifacts.push({ label: "evidence", value: `“${o.evidence}”` });
  return {
    description: o.description,
    facts,
    links: observablePivotLinks(o.kind, o.value),
    artifacts,
    article_count: o.article_count,
    first_seen_at: o.first_seen_at,
  };
}
