import type { SettingValue } from "@/hooks/useSystemSettings";

import type { BrowseView, MatrixView } from "./EngineMatrix";

/** Where in the console a setting lives. The Engine spreads its knobs across
 *  stage panels, table views and browse screens — this is the map back. */
export type EngineDest =
  | { kind: "stage"; stage: string }
  | { kind: "view"; view: MatrixView }
  | { kind: "browse"; browse: BrowseView }
  | { kind: "settings"; section: string; tab?: string };

export interface SettingHit {
  key: string;
  label: string;
  hint: string;
  /** Group label, or a hand-written origin for the non-setting panels. */
  origin: string;
  dest: EngineDest;
  score: number;
}

/** Setting group → the console surface that renders it. Mirrors every
 *  `<SystemSettings filterGroups={…}>` call under components/engine/ plus the
 *  two groups that only exist on the Settings page. */
const GROUP_DEST: Record<string, EngineDest> = {
  autolink: { kind: "stage", stage: "autolink" },
  ai: { kind: "stage", stage: "extract" },
  extraction: { kind: "stage", stage: "extract" },
  scoring: { kind: "stage", stage: "score" },
  threads: { kind: "stage", stage: "score" },
  intelligence: { kind: "stage", stage: "correlation" },
  observables: { kind: "stage", stage: "observables" },
  adjudication: { kind: "stage", stage: "adjudicate" },
  enrichment: { kind: "browse", browse: "enrichment" },
  api_keys: { kind: "browse", browse: "enrichment" },
  translation: { kind: "stage", stage: "translate" },
  feeds: { kind: "view", view: "feeds" },
  rate_limiting: { kind: "view", view: "feeds" },
  image_proxy: { kind: "view", view: "feeds" },
  feed_value: { kind: "view", view: "feeds" },
  plans: { kind: "browse", browse: "plans" },
  maintenance: { kind: "browse", browse: "maintenance" },
  retention: { kind: "browse", browse: "maintenance" },
  security: { kind: "settings", section: "users" },
  monitoring: { kind: "settings", section: "system" },
  backup: { kind: "settings", section: "system" },
  public_rss: { kind: "settings", section: "feeds" },
};

/** The `ai` group's people-facing keys: the personal-key policy, the
 *  per-person allowance and the share-link limit. They render on the User keys
 *  tab of AI Configuration and are excluded from the Analyze stage panel. */
export const USER_AI_SETTING_KEYS = [
  "allow_user_ai_providers",
  "require_user_ai_provider",
  "user_ai_provider_types",
  "user_ai_allow_private_endpoints",
  "user_ai_daily_request_cap",
  "site_ai_user_daily_requests",
  "share_ai_daily_requests",
] as const;

/** Key-level exceptions to GROUP_DEST: the observables publish knobs render
 *  on the Publishing browse screen, not the stage panel; the personal-key
 *  settings on the User keys tab. */
const KEY_DEST: Record<string, EngineDest> = {
  allow_user_ai_providers: { kind: "settings", section: "ai", tab: "keys" },
  require_user_ai_provider: { kind: "settings", section: "ai", tab: "keys" },
  user_ai_provider_types: { kind: "settings", section: "ai", tab: "keys" },
  user_ai_allow_private_endpoints: { kind: "settings", section: "ai", tab: "keys" },
  user_ai_daily_request_cap: { kind: "settings", section: "ai", tab: "keys" },
  site_ai_user_daily_requests: { kind: "settings", section: "ai", tab: "keys" },
  share_ai_daily_requests: { kind: "settings", section: "ai", tab: "keys" },
  observables_publish_enabled: { kind: "browse", browse: "publishing" },
  observables_publish_token: { kind: "browse", browse: "publishing" },
  observables_publish_min_confidence: { kind: "browse", browse: "publishing" },
  observables_publish_max_age_days: { kind: "browse", browse: "publishing" },
  observables_publish_never_suffixes: { kind: "browse", browse: "publishing" },
};

const STAGE_LABEL: Record<string, string> = {
  autolink: "Autolink stage",
  extract: "Extract stage",
  score: "Score stage",
  correlation: "Correlation stage",
  observables: "Observables stage",
  adjudicate: "Adjudicate stage",
  enrich: "Enrichment stage",
  translate: "Translate stage",
};

export function destLabel(dest: EngineDest): string {
  switch (dest.kind) {
    case "stage":
      return STAGE_LABEL[dest.stage] ?? `${dest.stage.replace(/_/g, " ")} stage`;
    case "view":
      return dest.view === "feeds" ? "Feeds view" : `${dest.view} view`;
    case "browse":
      return dest.browse === "jobs"
        ? "Scheduled jobs"
        : dest.browse === "plans"
          ? "Pipeline plans"
          : dest.browse === "enrichment"
            ? "Enrichment"
            : dest.browse === "publishing"
              ? "Publishing"
              : "Maintenance";
    case "settings":
      return `Settings → ${dest.section}`;
  }
}

/** Configuration that isn't a system setting — hand-written so "denylist" or
 *  "schedule" finds the panel that owns it. */
const PANELS: { label: string; hint: string; terms: string; dest: EngineDest }[] = [
  {
    label: "Extraction denylist",
    hint: "Names the AI extractor may never create as entities",
    terms: "denylist deny list blocklist banned entity names extraction",
    dest: { kind: "stage", stage: "extract" },
  },
  {
    label: "AI model for extraction",
    hint: "Provider, model and token budget for the entry_analysis task",
    terms: "model provider ollama claude openai token budget assignment extraction",
    dest: { kind: "stage", stage: "extract" },
  },
  {
    label: "False-positive names",
    hint: "Curated names the autolinker refuses to match",
    terms: "false positive fp names blocked surface forms autolinker dictionary",
    dest: { kind: "stage", stage: "autolink" },
  },
  {
    label: "Proximity scoring",
    hint: "Paragraph-distance decay for correlation relationship strength",
    terms: "proximity decay distance paragraph relationship strength correlation",
    dest: { kind: "stage", stage: "correlation" },
  },
  {
    label: "Enrichment sources",
    hint: "Per-source enable, order and rate limits for entity enrichment",
    terms: "enrichment sources rate limit order adapters otx virustotal",
    dest: { kind: "browse", browse: "enrichment" },
  },
  {
    label: "Scheduled jobs",
    hint: "Beat schedules, intervals and manual runs for every background job",
    terms: "jobs schedule cron interval beat celery run now",
    dest: { kind: "browse", browse: "jobs" },
  },
  {
    label: "Pipeline plans",
    hint: "Per-plan stage composition layered over the engine defaults",
    terms: "plans pipeline stages compose enable disable layer",
    dest: { kind: "browse", browse: "plans" },
  },
  {
    label: "Maintenance sweeps",
    hint: "Global rebuilds and destructive resets",
    terms: "maintenance sweep rebuild reset purge reindex vacuum",
    dest: { kind: "browse", browse: "maintenance" },
  },
  {
    label: "Observable publishing",
    hint: "Token-gated EDL blocklists, SIEM lookup CSVs and TAXII collections",
    terms: "publish publishing edl blocklist taxii stix lookup export observables indicators",
    dest: { kind: "browse", browse: "publishing" },
  },
  {
    label: "Feed health",
    hint: "Per-feed fetch errors, staleness and intel value",
    terms: "feed health errors stale broken fetch value",
    dest: { kind: "view", view: "feeds" },
  },
];

/** Underscores and hyphens read as spaces on both sides, so a pasted setting
 *  key ("thread_join_similarity") and its prose label both match. */
function norm(text: string): string {
  return text.toLowerCase().replace(/[_-]+/g, " ");
}

/** Substring rank: label start beats label contains beats key beats prose. */
function rank(q: string, label: string, key: string, prose: string): number {
  const l = norm(label);
  if (l.startsWith(q)) return 100;
  if (l.includes(q)) return 80;
  if (norm(key).includes(q)) return 60;
  if (norm(prose).includes(q)) return 30;
  return 0;
}

/** Rank every engine setting + config panel against the query. */
export function searchEngineSettings(
  query: string,
  settings: Record<string, SettingValue> | undefined,
  groups: Record<string, string> | undefined,
  limit = 12,
): SettingHit[] {
  const q = norm(query.trim());
  if (q.length < 2) return [];

  const hits: SettingHit[] = [];

  for (const panel of PANELS) {
    const score = rank(q, panel.label, "", `${panel.terms} ${panel.hint}`);
    if (score) hits.push({ key: "", label: panel.label, hint: panel.hint, origin: "Panel", dest: panel.dest, score });
  }

  for (const [key, meta] of Object.entries(settings ?? {})) {
    const dest = KEY_DEST[key] ?? GROUP_DEST[meta.group];
    if (!dest) continue;
    const origin = groups?.[meta.group] ?? meta.group;
    const score = rank(q, meta.label, key, `${meta.description} ${origin}`);
    if (score) hits.push({ key, label: meta.label, hint: meta.description, origin, dest, score });
  }

  // Off-console settings sort last: they leave the Engine to reach them.
  const weight = (h: SettingHit) => h.score - (h.dest.kind === "settings" ? 50 : 0);
  return hits.sort((a, b) => weight(b) - weight(a)).slice(0, limit);
}
