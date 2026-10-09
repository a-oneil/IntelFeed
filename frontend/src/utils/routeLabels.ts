/**
 * Human labels for routes, keyed by pathname (query string allowed).
 *
 * Two consumers share this: the command palette's "recently visited" list and
 * the route-loading fallback, which names the page it is fetching a chunk for.
 * Keep it in sync with the routes in `App.tsx` — an unmapped route degrades to
 * a plain "Loading…" rather than breaking.
 */

const EXACT: Record<string, string> = {
  "/": "Home",
  "/feeds": "All Feeds",
  "/priority-queue": "Priority Queue",
  "/search": "Search",
  "/settings": "Settings",
  "/automation": "Automation Rules",
  "/boards": "Dashboards",
  "/campaigns": "Campaigns",
  "/regions": "Regions & Countries",
  "/documentation": "Documentation",
  "/login": "Sign In",
  "/register": "Register",
  "/workbench": "Dashboard",
  "/workbench/dashboard": "Dashboard",
  "/workbench/explore": "Intelligence Workbench",
  "/workbench/threats": "Threats",
  "/workbench/report/new": "Report Builder",
};

// Prefix → label, for the id-carrying detail routes.
const PREFIXES: Array<[string, string]> = [
  ["/workbench/threat_actor/", "Threat Actor Profile"],
  ["/workbench/malware/", "Malware Profile"],
  ["/workbench/ttp/", "TTP Detail"],
  ["/workbench/cve/", "CVE Detail"],
  ["/workbench/cwe/", "Weakness Profile"],
  ["/workbench/tool/", "Tool Profile"],
  ["/workbench/mitigation/", "Mitigation Profile"],
  ["/workbench/vendor/", "Vendor Profile"],
  ["/workbench/product/", "Product Profile"],
  ["/workbench/country/", "Country Profile"],
  ["/workbench/sector/", "Sector Profile"],
  ["/workbench/campaign/", "Campaign Profile"],
  ["/workbench/rule/", "Detection Rule"],
  ["/workbench/report/", "Report Builder"],
  ["/intelligence/threat_actor/", "Threat Actor Profile"],
  ["/intelligence/malware/", "Malware Profile"],
  ["/countries/", "Country Profile"],
  ["/documentation/", "Documentation"],
  ["/shared/copilot/", "shared conversation"],
  ["/shared/", "shared article"],
];

// Mirrors WorkbenchPage.SECTION_CONFIG — the workbench rail is one route whose
// section rides in ?section= (older links used ?tab=).
const WORKBENCH_SECTIONS: Record<string, string> = {
  attack_matrix: "ATT&CK Matrix",
  rules: "Rules Library",
  telemetry: "Telemetry Sources",
  countries: "Countries",
  sectors: "Sectors",
  cves: "CVEs",
  cwes: "Weaknesses",
  malware: "Malware",
  mitigations: "Mitigations",
  observables: "Observables",
  products: "Products",
  threat_actors: "Threat Actors",
  tools: "Tools",
  ttps: "TTPs",
  vendors: "Vendors",
  campaigns: "Campaigns",
  glossary: "Glossary",
  ransomware: "Ransomware",
  reports: "Reports",
  requirements: "Requirements",
  telegram_mentions: "Telegram Mentions",
  watchlist: "Watchlist",
  // Retired section keys, still in old bookmarks.
  actors: "Threat Actors",
  report: "Report Builder",
  enrich: "Enrichment",
};

const SETTINGS_TABS: Record<string, string> = {
  feeds: "Feed Management",
  ai: "AI Providers",
  users: "User Management",
  system: "System Settings",
};

// Mirrors SettingsPage.NAV_GROUPS.
const SETTINGS_SECTIONS: Record<string, string> = {
  account: "Account Settings",
  appearance: "Appearance",
  reading: "Reading",
  tags: "Tags",
  feeds: "Feeds & Import",
  telegram: "Telegram Setup",
  skill: "Claude Code Skill",
  ai: "AI Configuration",
  system: "System Settings",
  users: "User Management",
  logs: "Logs",
};

/** Readable name for a route, or null when the path isn't one we name. */
export function getRouteLabel(path: string): string | null {
  if (EXACT[path]) return EXACT[path];

  const basePath = path.split("?")[0];
  if (EXACT[basePath]) return EXACT[basePath];

  // Tab-based routes are more specific than the bare path, so resolve them
  // before falling back to the prefix table.
  const tabMatch = path.match(/[?&]tab=(\w+)/);
  if (tabMatch && (basePath === "/workbench" || basePath === "/workbench/explore")) {
    return WORKBENCH_SECTIONS[tabMatch[1]] || "Intelligence Workbench";
  }
  if (tabMatch && basePath === "/settings") {
    return SETTINGS_TABS[tabMatch[1]] || "Settings";
  }
  const sectionMatch = path.match(/[?&]section=(\w+)/);
  if (sectionMatch && basePath === "/settings") {
    return SETTINGS_SECTIONS[sectionMatch[1]] || "Settings";
  }
  if (sectionMatch && (basePath === "/workbench" || basePath === "/workbench/explore")) {
    return WORKBENCH_SECTIONS[sectionMatch[1]] || "Intelligence Workbench";
  }

  for (const [prefix, label] of PREFIXES) {
    if (basePath.startsWith(prefix)) return label;
  }

  return null;
}
