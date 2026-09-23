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
