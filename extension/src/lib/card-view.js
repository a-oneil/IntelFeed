// What the hover card shows for a highlighted entity, built from the entity payload /api/autolink/scan attaches to each match. Mirrors the app's popover: frontend/src/utils/entityPopoverMeta.ts (facts, aliases, links per type) and the CVE and technique grids in frontend/src/components/EntityPopover.tsx. No browser APIs.

const SEVERITY_COLORS = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#f59e0b",
  low: "#22c55e",
  info: "#3b82f6",
};
const DANGER = "#f85149";

const CVE_LINKS = [
  ["CVE.org", (id) => `https://www.cve.org/CVERecord?id=${id}`],
  ["NVD", (id) => `https://nvd.nist.gov/vuln/detail/${id}`],
  ["CVEDetails", (id) => `https://www.cvedetails.com/cve/${id}/`],
  ["MITRE", (id) => `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${id}`],
];

/** Reputation pivots per indicator kind (the app's observablePivotLinks). */
function observableLinks(kind, value) {
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

const short = (iso) =>
  new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });

/**
 * {badges, facts, aliases, description, descMax, links, artifacts, image}
 *   badges:    [{text, color, solid}] after the type badge (KEV, severity)
 *   facts:     [{label, value, tone?}] for the grid, before Articles / First seen
 *   firstSeen: ISO date or null; seenFirst puts it before Articles (CVEs, techniques)
 */
export function cardView(type, e, name) {
  e = e || {};
  const view = {
    badges: [],
    facts: [],
    firstSeen: e.first_seen_at || null,
    seenFirst: type === "cve" || type === "ttp",
    aliases: [],
    description: e.description || e.summary || e.short_description || "",
    descMax: 220,
    links: [],
    artifacts: [],
    image: e.wikipedia_image_url || null,
  };
  const fact = (label, value, tone) => value != null && value !== "" && view.facts.push({ label, value: String(value), tone });
  const link = (label, url) => url && view.links.push({ label, url: String(url) });

  switch (type) {
    case "cve": {
      if (e.is_kev) view.badges.push({ text: "KEV", color: DANGER, solid: true });
      if (e.severity) view.badges.push({ text: e.severity, color: SEVERITY_COLORS[e.severity.toLowerCase()] || "#888888" });
      if (e.cvss_score != null) fact("CVSS", e.cvss_score);
      if (e.epss_score != null) fact("EPSS", `${(Number(e.epss_score) * 100).toFixed(e.epss_score < 0.1 ? 1 : 0)}%`);
      const poc = [e.github_poc_count ? `${e.github_poc_count} GitHub` : null, e.metasploit_module ? "Metasploit" : null]
        .filter(Boolean)
        .join(" · ");
      fact("PoC", poc);
      fact("Exploit", e.exploit_status, "bad");
      view.descMax = 120;
      const id = e.cve_id || name;
      for (const [label, url] of CVE_LINKS) link(label, url(encodeURIComponent(id)));
      break;
    }
    case "ttp":
      fact("Technique", e.technique_id);
      fact("Tactic", e.tactic);
      break;
    case "threat_actor":
      fact("Motivation", e.motivation);
      fact("Origin", e.country);
      if (e.targeted_sectors?.length) fact("Targets", e.targeted_sectors.slice(0, 3).join(", "));
      if (e.mitre_id) link("MITRE ATT&CK", `https://attack.mitre.org/groups/${e.mitre_id}/`);
      break;
    case "malware":
      fact("Type", e.malware_type);
      link("Malpedia", e.malpedia_url);
      break;
    case "vendor":
      fact("Type", e.vendor_type);
      link("Website", e.website);
      break;
    case "product":
      fact("Vendor", e.vendor_name);
      fact("Type", e.product_type);
      link("Website", e.website);
      break;
    case "tool":
      fact("Type", e.tool_type);
      if (e.platforms?.length) fact("Platforms", e.platforms.slice(0, 3).join(", "));
      link("GitHub", e.github_url);
      link("Malpedia", e.malpedia_url);
      for (const [key, raw] of Object.entries(e.detection_artifacts || {})) {
        const value = Array.isArray(raw) ? raw.join(", ") : String(raw ?? "");
        if (value && value !== "null" && value !== "{}") view.artifacts.push({ label: key.replace(/_/g, " "), value });
      }
      break;
    case "country":
      fact("Region", e.region);
      break;
    case "sector":
      if (e.victim_count) fact("Leak-site victims, last 90 days", e.victim_count);
      if (e.targeting_actor_count) fact("Targeted by", `${e.targeting_actor_count} actors`);
      break;
    case "mitigation":
      fact("MITRE ID", e.mitre_id);
      link("MITRE ATT&CK", e.mitre_url);
      break;
    case "cwe":
      fact("Abstraction", e.abstraction);
      fact("Parent", e.parent_cwe_id);
      if (e.mapping_usage && e.mapping_usage !== "Allowed") fact("MITRE mapping", e.mapping_usage);
      fact("Likelihood", e.likelihood_of_exploit);
      link("MITRE CWE", e.cwe_url);
      break;
    case "observable":
      fact("Kind", e.kind);
      fact("Role", e.role);
      if (typeof e.current_confidence === "number")
        fact("Confidence", `${Math.round(e.current_confidence * 100)}%${e.status && e.status !== "active" ? ` · ${e.status}` : ""}`);
      if (e.last_seen_at) fact("Last seen", short(e.last_seen_at));
      if (e.evidence) view.artifacts.push({ label: "evidence", value: `“${e.evidence}”` });
      view.links.push(...observableLinks(e.kind, e.value || name));
      break;
  }
  if (type !== "cve" && type !== "ttp" && type !== "observable") link("Wikipedia", e.wikipedia_url);

  const aliases = type === "cwe" ? e.alternate_terms : e.aliases;
  view.aliases = (aliases || []).filter((a) => a && a.toLowerCase() !== String(name).toLowerCase()).slice(0, 6);
  // Entity fields can be filled by AI or by hand, so only https links are shown: the page script puts them on the visited site, where a javascript: link would run.
  view.links = view.links.filter((l) => /^https:\/\//i.test(l.url)).slice(0, 4);
  view.artifacts = view.artifacts.slice(0, 4);
  return view;
}
