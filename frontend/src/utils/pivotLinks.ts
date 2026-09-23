/**
 * Centralized external pivot link definitions for entity lookups.
 * Zero-cost analyst productivity: clickable URLs to external analysis platforms.
 */

export interface PivotLink {
  platform: string;
  url: string;
}

interface PivotLinkTemplate {
  platform: string;
  urlTemplate: string;
}

const PIVOT_LINK_MAP: Record<string, PivotLinkTemplate[]> = {
  threat_actor: [
    { platform: "MITRE ATT&CK", urlTemplate: "https://attack.mitre.org/groups/?search={value}" },
    { platform: "Google", urlTemplate: "https://www.google.com/search?q={value}+threat+actor" },
    { platform: "Mandiant", urlTemplate: "https://www.mandiant.com/resources/search?q={value}" },
    { platform: "CISA", urlTemplate: "https://www.cisa.gov/search#gsc.tab=0&gsc.q={value}&gsc.sort=" },
    { platform: "Recorded Future", urlTemplate: "https://app.recordedfuture.com/live/sc/search?q={value}" },
  ],
  malware: [
    { platform: "VirusTotal", urlTemplate: "https://www.virustotal.com/gui/search/{value}" },
    { platform: "MalwareBazaar", urlTemplate: "https://bazaar.abuse.ch/browse.php?search={value}" },
    { platform: "Hybrid Analysis", urlTemplate: "https://www.hybrid-analysis.com/search?query={value}" },
    { platform: "MITRE ATT&CK", urlTemplate: "https://attack.mitre.org/software/?search={value}" },
    { platform: "Google", urlTemplate: "https://www.google.com/search?q={value}+malware" },
  ],
  ttp: [
    { platform: "MITRE ATT&CK", urlTemplate: "https://attack.mitre.org/techniques/{value}/" },
    { platform: "Google", urlTemplate: "https://www.google.com/search?q=MITRE+{value}+detection" },
    { platform: "Sigma Rules", urlTemplate: "https://github.com/SigmaHQ/sigma/search?q={value}" },
  ],
  country: [
    { platform: "Wikipedia", urlTemplate: "https://en.wikipedia.org/wiki/{value}" },
    { platform: "Google", urlTemplate: "https://www.google.com/search?q={value}+cyber+threat" },
    { platform: "CISA", urlTemplate: "https://www.cisa.gov/search#gsc.tab=0&gsc.q={value}&gsc.sort=" },
  ],
  // The catalog page takes a bare number, so the profile passes the numeric
  // part; the other two want the full "CWE-416" form.
  cwe: [
    { platform: "MITRE CWE", urlTemplate: "https://cwe.mitre.org/data/definitions/{value}.html" },
    { platform: "CVEDetails", urlTemplate: "https://www.cvedetails.com/cwe-details/{value}/" },
    { platform: "Google", urlTemplate: "https://www.google.com/search?q=CWE-{value}+vulnerability" },
  ],
  cve: [
    { platform: "CVE.org", urlTemplate: "https://www.cve.org/CVERecord?id={value}" },
    { platform: "NVD", urlTemplate: "https://nvd.nist.gov/vuln/detail/{value}" },
    { platform: "CVEDetails", urlTemplate: "https://www.cvedetails.com/cve/{value}/" },
    { platform: "MITRE", urlTemplate: "https://cve.mitre.org/cgi-bin/cvename.cgi?name={value}" },
    { platform: "ExploitDB", urlTemplate: "https://www.exploit-db.com/search?cve={value}" },
  ],
};

export function getPivotLinks(type: string, value: string): PivotLink[] {
  const templates = PIVOT_LINK_MAP[type?.toLowerCase()] || [];
  return templates.map((t) => ({
    platform: t.platform,
    url: t.urlTemplate.replace("{value}", encodeURIComponent(value)),
  }));
}


