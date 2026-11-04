/** Shared observable value helpers: defanging and client-side STIX export.
 *
 * One implementation for every surface (reader panel Copy-all, profile page
 * rail) — the two previously diverged and one defanged hashes and cmdlines
 * into unusable strings.
 */

/** Kinds where defanging means anything; everything else copies verbatim. */
const DEFANGABLE_KINDS = new Set(["ipv4", "ipv6", "domain", "url", "email"]);

/** Render a network value the way analysts share it: neutered. Non-network
 * kinds (hashes, cmdlines, registry keys, paths) pass through untouched. */
export function defangObservable(kind: string, value: string): string {
  if (!DEFANGABLE_KINDS.has(kind)) return value;
  let v = value.replace(/^http/i, "hxxp").replace(/\./g, "[.]");
  if (kind === "email") v = v.replace("@", "[@]");
  return v;
}

function stixEscape(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

/** Minimal client-side STIX 2.1 pattern per kind; unpatternable kinds skip.
 * Every value is escaped — observables are attacker-controlled strings. */
export const STIX_PATTERNS: Record<string, (v: string) => string> = {
  ipv4: (v) => `[ipv4-addr:value = '${stixEscape(v)}']`,
  ipv6: (v) => `[ipv6-addr:value = '${stixEscape(v)}']`,
  domain: (v) => `[domain-name:value = '${stixEscape(v)}']`,
  url: (v) => `[url:value = '${stixEscape(v)}']`,
  email: (v) => `[email-addr:value = '${stixEscape(v)}']`,
  md5: (v) => `[file:hashes.'MD5' = '${stixEscape(v)}']`,
  sha1: (v) => `[file:hashes.'SHA-1' = '${stixEscape(v)}']`,
  sha256: (v) => `[file:hashes.'SHA-256' = '${stixEscape(v)}']`,
  cmdline: (v) => `[process:command_line = '${stixEscape(v)}']`,
  registry: (v) => `[windows-registry-key:key = '${stixEscape(v)}']`,
  mutex: (v) => `[mutex:name = '${stixEscape(v)}']`,
  cert_fingerprint: (v) => `[x509-certificate:hashes.'SHA-1' = '${stixEscape(v)}']`,
};

/** RFC-4122 v4 id with a fallback: crypto.randomUUID only exists in secure
 * contexts, and self-hosted deployments run over plain HTTP on LAN IPs. */
export function uuid4(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") return crypto.randomUUID();
  const bytes =
    typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function"
      ? crypto.getRandomValues(new Uint8Array(16))
      : Uint8Array.from({ length: 16 }, () => Math.floor(Math.random() * 256));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const h = Array.from(bytes, (x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export interface StixIndicatorSource {
  id: string;
  kind: string;
  value: string;
  current_confidence: number;
  role?: string | null;
  first_seen_at?: string | null;
  last_seen_at?: string | null;
}

/** A valid STIX 2.1 bundle: indicators carry the REQUIRED created/modified/
 * valid_from (python-stix2 rejects a bundle without them). */
export function stixBundle(items: StixIndicatorSource[]): string {
  const now = new Date().toISOString();
  const objects = items
    .filter((i) => STIX_PATTERNS[i.kind])
    .map((i) => {
      const created = i.first_seen_at ?? now;
      return {
        type: "indicator",
        spec_version: "2.1",
        id: `indicator--${i.id}`,
        created,
        modified: i.last_seen_at ?? created,
        name: i.value,
        pattern: STIX_PATTERNS[i.kind](i.value),
        pattern_type: "stix",
        valid_from: created,
        confidence: Math.round(i.current_confidence * 100),
        labels: ["malicious-activity", ...(i.role ? [i.role] : [])],
      };
    });
  return JSON.stringify({ type: "bundle", id: `bundle--${uuid4()}`, objects }, null, 2);
}


/**
 * How many independent sources back an observable, in words an analyst reads
 * the way they mean it: reporting articles first, indicator feeds second. A
 * value on one feed's eighteen CSV variants is "1 feed", never "18 sightings".
 */
export function observableSourcesLabel(o: {
  report_count?: number | null;
  feed_source_count?: number | null;
  sighting_count?: number | null;
}): string {
  const reports = o.report_count ?? 0;
  const feeds = o.feed_source_count ?? 0;
  const parts: string[] = [];
  if (reports) parts.push(`${reports} report${reports === 1 ? "" : "s"}`);
  if (feeds) parts.push(`${feeds} feed${feeds === 1 ? "" : "s"}`);
  if (!parts.length) return (o.sighting_count ?? 0) ? `${o.sighting_count} sightings` : "no sources";
  return parts.join(" · ");
}

/** One-line enrichment summary for a table cell: reputation plus the network columns. */
export function reputationLabel(o: ObservableResponseLike): string {
  const r = o.reputation ?? {};
  const bits: string[] = [];
  if (r.gn_riot) bits.push("RIOT");
  if (o.noise_class && o.noise_class !== "not_seen") bits.push(`GN ${o.noise_class}`);
  if (r.vt_ratio) bits.push(`VT ${r.vt_ratio}`);
  if (o.asn != null) bits.push(`AS${o.asn}`);
  if (o.geo_country) bits.push(o.geo_country);
  if (o.popularity_rank != null) bits.push(`Tranco #${o.popularity_rank}`);
  if (r.ports) bits.push(`ports ${r.ports}`);
  if (r.tags) bits.push(String(r.tags));
  return bits.join(" · ");
}

/** "AS10439 · CARINET - CariNet, Inc., US · US" for a profile row. */
export function networkLabel(o: ObservableResponseLike): string {
  return [o.asn != null ? `AS${o.asn}` : null, o.asn_org, o.geo_country].filter(Boolean).join(" · ");
}

/** "Oct 29, 1996 — 30 years ago": a registration date with its age. */
export function registeredLabel(iso: string, now: Date = new Date()): string {
  const date = new Date(iso);
  if (isNaN(date.getTime())) return iso;
  const days = Math.floor((now.getTime() - date.getTime()) / 86_400_000);
  const years = Math.floor(days / 365.25);
  const age =
    days < 1 ? "today" : years >= 1 ? `${years} year${years === 1 ? "" : "s"} ago` : `${days} day${days === 1 ? "" : "s"} ago`;
  const shown = date.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric", timeZone: "UTC" });
  return `${shown} — ${age}`;
}

interface ObservableResponseLike {
  reputation?: {
    ports?: string | null;
    tags?: string | null;
    vt_ratio?: string | null;
    gn_riot?: boolean | null;
    enriched_at?: string | null;
  } | null;
  asn?: number | null;
  asn_org?: string | null;
  geo_country?: string | null;
  popularity_rank?: number | null;
  noise_class?: string | null;
}

/** Human labels for the ledger's capture doors (`Observable.created_via`). */
export const CAPTURED_BY_LABELS: Record<string, string> = {
  ai_extraction: "AI analysis",
  ttp_observable: "TTP observable",
  ioc_list: "indicator feed",
  publisher_ioc: "article IOC table",
  adjudicator: "adjudicator",
  manual: "analyst",
};

export function capturedByLabel(createdVia: string | null | undefined): string {
  if (!createdVia) return "";
  return CAPTURED_BY_LABELS[createdVia] ?? createdVia.replace(/_/g, " ");
}
