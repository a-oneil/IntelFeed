import type { WorkspaceSection } from "@/stores/intelStore";

/**
 * The app's command vocabulary — everything ⌘K can take you to or do.
 *
 * The palette is a *command* launcher only: it never queries the server. Entity
 * and entry lookup lives on the /search route (reachable from here via the
 * "Search" command), so this list is the palette's entire universe and has to
 * stay in step with the routes in `App.tsx`, the workbench rail in
 * `WorkbenchPage.SECTION_CONFIG`, and the settings rail in
 * `SettingsPage.NAV_GROUPS`.
 *
 * Everything in this file is pure data or a pure function: how a command is
 * *performed* (navigate / open a modal / switch workbench section) stays with
 * whichever surface renders it.
 */

export interface QuickAction {
  label: string;
  path: string;
  icon: string;
  category: ActionCategory;
  keywords?: string[];
  /** If set, navigate to path AND set this workbench section before navigating */
  workbenchSection?: WorkspaceSection;
  /** Non-navigation action id, handled specially instead of navigating to `path`. */
  special?: SpecialAction;
  /** Hidden from non-admins — the destination would bounce them anyway. */
  adminOnly?: boolean;
  /** Keyboard shortcut shown on the right — the palette doubles as a cheat sheet. */
  shortcut?: string;
}

export type SpecialAction =
  | "open-copilot"
  | "open-add-feed"
  | "open-ingest"
  | "show-shortcuts";

export type ActionCategory = "run" | "create" | "navigate" | "browse" | "manage";

export const ACTION_CATEGORY_LABELS: Record<ActionCategory, string> = {
  run: "RUN",
  create: "CREATE",
  navigate: "GO TO",
  browse: "BROWSE",
  manage: "MANAGE",
};

/** Render order for the empty-query menu; also the order fuzzy ties break in. */
export const ACTION_CATEGORY_ORDER: ActionCategory[] = [
  "run",
  "create",
  "navigate",
  "browse",
  "manage",
];

// The workbench rail is a single route whose active section is store state, so
// its entries deep-link through ?section= — WorkbenchPage activates it and then
// strips the param.
const explore = (section: WorkspaceSection) => `/workbench/explore?section=${section}`;

export const QUICK_ACTIONS: QuickAction[] = [
  // --- Run -----------------------------------------------------------------
  { label: "Ask Copilot", icon: "✦", path: "", category: "run", special: "open-copilot", shortcut: "⌘⇧K", keywords: ["ask", "copilot", "chat", "ai", "assistant", "agent", "question", "help"] },
  { label: "Keyboard shortcuts", icon: "⌨", path: "", category: "run", special: "show-shortcuts", shortcut: "?", keywords: ["keys", "shortcut", "hotkey", "bindings", "help", "cheatsheet"] },

  // --- Create --------------------------------------------------------------
  { label: "Add feed", icon: "✚", path: "", category: "create", special: "open-add-feed", keywords: ["new", "feed", "rss", "subscribe", "youtube", "reddit", "github", "telegram", "bluesky", "mastodon", "scraper"] },
  { label: "Ingest a URL or PDF", icon: "✚", path: "", category: "create", special: "open-ingest", keywords: ["ingest", "url", "pdf", "upload", "import", "article", "one-off", "paste"] },
  { label: "Create detection rule", icon: "✚", path: "/workbench/rule/new", category: "create", keywords: ["new", "rule", "sigma", "spl", "kql", "yara", "detection", "add"] },
  { label: "Create campaign", icon: "✚", path: "/campaigns?create=true", category: "create", keywords: ["new", "campaign", "track", "add"] },
  { label: "Create automation rule", icon: "✚", path: "/automation?create=true", category: "create", keywords: ["new", "automation", "automate", "trigger", "add"] },
  { label: "Create report", icon: "✚", path: "/workbench/report/new", category: "create", keywords: ["new", "report", "export", "build", "brief"] },

  // --- Go to (top-level routes) --------------------------------------------
  { label: "Search", icon: "🔎", path: "/search", category: "navigate", shortcut: "/", keywords: ["search", "find", "lookup", "query", "entities", "entries", "articles"] },
  { label: "Feed reader", icon: "📰", path: "/", category: "navigate", keywords: ["home", "reader", "entries", "articles", "inbox", "unread"] },
  { label: "All feeds", icon: "📡", path: "/feeds", category: "navigate", keywords: ["feed", "sources", "subscriptions"] },
  { label: "Priority queue", icon: "🎯", path: "/priority-queue", category: "navigate", keywords: ["priority", "queue", "radar", "ranked", "signal", "triage"] },
  { label: "Dashboard", icon: "▣", path: "/workbench/dashboard", category: "navigate", keywords: ["dashboard", "board", "widgets", "overview", "triage", "charts"] },
  { label: "Intelligence workbench", icon: "🔬", path: "/workbench/explore", category: "navigate", keywords: ["intel", "intelligence", "analysis", "entities", "workbench"] },
  { label: "Campaigns", icon: "📁", path: "/campaigns", category: "navigate", keywords: ["campaign", "tracking", "operation"] },
  { label: "Automation rules", icon: "⚡", path: "/automation", category: "navigate", keywords: ["automation", "rules", "schedule", "trigger", "action"] },
  { label: "Regions & countries", icon: "🌐", path: "/regions", category: "navigate", keywords: ["country", "region", "geo", "geography", "map"] },
  { label: "Documentation", icon: "📚", path: "/documentation", category: "navigate", keywords: ["docs", "documentation", "handbook", "guide", "manual", "readme"] },
  { label: "Settings", icon: "⚙", path: "/settings", category: "navigate", keywords: ["config", "configure", "preferences", "options"] },
  { label: "Engine console", icon: "🛠", path: "/settings?section=engine", category: "navigate", adminOnly: true, keywords: ["engine", "pipeline", "ingest", "stages", "console", "processing"] },

  // --- Browse (workbench rail sections) ------------------------------------
  { label: "ATT&CK matrix", icon: "▦", path: explore("attack_matrix"), category: "browse", workbenchSection: "attack_matrix", keywords: ["attack", "mitre", "matrix", "coverage", "navigator", "heatmap"] },
  { label: "Rules library", icon: "🛡", path: explore("rules"), category: "browse", workbenchSection: "rules", keywords: ["rules", "sigma", "splunk", "elastic", "crowdstrike", "kql", "yara", "detection"] },
  { label: "Telemetry sources", icon: "🎚", path: explore("telemetry"), category: "browse", workbenchSection: "telemetry", keywords: ["telemetry", "log", "sources", "data sources", "coverage", "gaps"] },
  { label: "Threats", icon: "🎯", path: "/workbench/threats", category: "browse", keywords: ["threats", "threat board", "intel to rules", "coverage"] },
  { label: "Vendor watch", icon: "👁", path: "/workbench/threats?tab=vulns", category: "browse", keywords: ["exposure", "vendor watch", "watch", "stack", "surface", "vulnerabilities"] },
  { label: "Threat actors", icon: "👤", path: explore("threat_actors"), category: "browse", workbenchSection: "threat_actors", keywords: ["actor", "apt", "group", "adversary", "threat actor"] },
  { label: "Malware", icon: "🦠", path: explore("malware"), category: "browse", workbenchSection: "malware", keywords: ["malware", "ransomware", "trojan", "loader", "family"] },
  { label: "CVEs", icon: "🐛", path: explore("cves"), category: "browse", workbenchSection: "cves", keywords: ["vulnerability", "cve", "exploit", "patch", "kev", "epss"] },
  { label: "TTPs", icon: "📋", path: explore("ttps"), category: "browse", workbenchSection: "ttps", keywords: ["technique", "tactic", "ttp", "mitre", "attack"] },
  { label: "Tools", icon: "🧰", path: explore("tools"), category: "browse", workbenchSection: "tools", keywords: ["tool", "offensive", "utility", "cobalt", "mimikatz"] },
  { label: "Vendors", icon: "🏢", path: explore("vendors"), category: "browse", workbenchSection: "vendors", keywords: ["vendor", "company", "manufacturer"] },
  { label: "Products", icon: "📦", path: explore("products"), category: "browse", workbenchSection: "products", keywords: ["product", "software", "application", "appliance"] },
  { label: "Countries", icon: "🏳", path: explore("countries"), category: "browse", workbenchSection: "countries", keywords: ["country", "nation", "geo", "attribution"] },
  { label: "Mitigations", icon: "🧯", path: explore("mitigations"), category: "browse", workbenchSection: "mitigations", keywords: ["mitigation", "control", "defense", "countermeasure"] },
  { label: "Watchlist", icon: "⭐", path: explore("watchlist"), category: "browse", workbenchSection: "watchlist", keywords: ["watchlist", "watched", "tracking", "alerts"] },
  { label: "Ransomware tracker", icon: "🔒", path: explore("ransomware"), category: "browse", workbenchSection: "ransomware", keywords: ["ransomware", "victims", "leak site", "extortion"] },
  { label: "Intelligence requirements", icon: "🎓", path: explore("requirements"), category: "browse", workbenchSection: "requirements", keywords: ["requirement", "pir", "intelligence requirement", "priority"] },
  { label: "Reports", icon: "📄", path: explore("reports"), category: "browse", workbenchSection: "reports", keywords: ["report", "intel report", "findings", "writeup"] },
  { label: "Telegram mentions", icon: "✈", path: explore("telegram_mentions"), category: "browse", workbenchSection: "telegram_mentions", keywords: ["telegram", "mentions", "channel", "chatter"] },
  { label: "Glossary", icon: "📖", path: explore("glossary"), category: "browse", workbenchSection: "glossary", keywords: ["terms", "definitions", "glossary", "acronym"] },

  // --- Manage (settings rail + engine views) -------------------------------
  // Engine deep links go through the console's legacy ?tab= / ?section= map —
  // that mapping is the only URL surface EngineMatrix exposes for its views.
  { label: "Account settings", icon: "👥", path: "/settings?section=account", category: "manage", keywords: ["account", "profile", "password", "email", "api key", "token"] },
  { label: "Appearance & themes", icon: "🎨", path: "/settings?section=appearance", category: "manage", keywords: ["theme", "appearance", "dark", "light", "colors", "font", "look"] },
  { label: "Reading preferences", icon: "📖", path: "/settings?section=reading", category: "manage", keywords: ["reading", "reader", "translate", "tts", "read aloud", "speech", "density"] },
  { label: "Manage tags", icon: "🏷", path: "/settings?section=tags", category: "manage", keywords: ["tag", "tags", "label", "rename", "merge", "recolor"] },
  { label: "Feeds & export (OPML)", icon: "📥", path: "/settings?section=feeds", category: "manage", adminOnly: true, keywords: ["opml", "export", "backup", "subscriptions", "categories"] },
  { label: "Telegram setup", icon: "✈", path: "/settings?section=telegram", category: "manage", adminOnly: true, keywords: ["telegram", "login", "session", "channels"] },
  { label: "Claude Code skill", icon: "🤝", path: "/settings?section=skill", category: "manage", keywords: ["skill", "claude", "cli", "mcp", "integration"] },
  { label: "AI configuration", icon: "🤖", path: "/settings?section=ai", category: "manage", adminOnly: true, keywords: ["ai", "model", "ollama", "claude", "openai", "llm", "provider", "prompt", "cost"] },
  { label: "System settings", icon: "🔧", path: "/settings?section=system", category: "manage", adminOnly: true, keywords: ["system", "config", "configure", "flags", "thresholds"] },
  { label: "Manage users", icon: "👤", path: "/settings?section=users", category: "manage", adminOnly: true, keywords: ["user", "users", "admin", "invite", "permissions", "roles"] },
  { label: "Logs", icon: "📜", path: "/settings?section=logs", category: "manage", adminOnly: true, keywords: ["logs", "audit", "errors", "activity"] },
  { label: "Feed health", icon: "❤", path: "/settings?section=engine&tab=pipeline&stage=feeds", category: "manage", adminOnly: true, keywords: ["health", "status", "errors", "broken", "stale", "feeds"] },
  { label: "Scheduled jobs", icon: "⏱", path: "/settings?section=engine&tab=jobs", category: "manage", adminOnly: true, keywords: ["jobs", "schedule", "beat", "celery", "cron", "tasks"] },
  { label: "Pipeline plans", icon: "🧩", path: "/settings?section=engine&tab=plans", category: "manage", adminOnly: true, keywords: ["plans", "pipeline", "stages", "composition"] },
  { label: "Autolinking", icon: "🔗", path: "/settings?section=engine&tab=autolinking", category: "manage", adminOnly: true, keywords: ["autolink", "links", "relationships", "edges", "false positive"] },
  { label: "AI extraction review", icon: "🧪", path: "/settings?section=engine&tab=extraction", category: "manage", adminOnly: true, keywords: ["extraction", "ai entities", "review", "confirm", "provenance", "merge"] },
  { label: "Enrichment", icon: "✨", path: "/settings?section=enrichment", category: "manage", adminOnly: true, keywords: ["enrich", "enrichment", "augment", "sources", "profiles"] },
];

export function fuzzyScore(query: string, target: string, keywords?: string[]): number {
  const q = query.toLowerCase();
  const t = target.toLowerCase();

  // Exact substring match — highest score
  if (t.includes(q)) return 100;

  // Keyword match
  if (keywords) {
    for (const kw of keywords) {
      if (kw.startsWith(q)) return 80;
      if (kw.includes(q)) return 60;
    }
  }

  // Fuzzy: check if all query chars appear in order
  let qi = 0;
  let consecutiveBonus = 0;
  let lastMatchIndex = -2;
  for (let ti = 0; ti < t.length && qi < q.length; ti++) {
    if (t[ti] === q[qi]) {
      if (ti === lastMatchIndex + 1) consecutiveBonus += 10;
      lastMatchIndex = ti;
      qi++;
    }
  }

  if (qi === q.length) {
    // All chars matched — base score + consecutive bonus
    return 30 + consecutiveBonus + (q.length / t.length) * 20;
  }

  // Also check keywords for fuzzy match
  if (keywords) {
    for (const kw of keywords) {
      let kqi = 0;
      for (let ki = 0; ki < kw.length && kqi < q.length; ki++) {
        if (kw[ki] === q[kqi]) kqi++;
      }
      if (kqi === q.length) return 25;
    }
  }

  return 0;
}
