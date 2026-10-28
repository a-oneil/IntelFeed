export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export interface CursorPaginatedResponse<T> {
  items: T[];
  next_cursor: string | null;
  has_more: boolean;
}

export type ExtractionStatus = "success" | "ai_not_configured" | "provider_error" | "parse_error";

export interface ExtractionResponse<T> {
  items: T[];
  status: ExtractionStatus;
  error_message: string | null;
}

export interface User {
  id: string;
  username: string;
  role: string;
  is_active: boolean;
  settings: Record<string, unknown>;
  theme_id: string | null;
  custom_css: string | null;
  last_login: string | null;
  created_at: string;
  /** Feeds this account subscribes to. Only populated on the admin users list. */
  feed_count?: number;
  muted_feed_count?: number;
}

/** Why the health check paused a feed (backend services/feed_fetch_health.py). */
export interface FeedPauseReason {
  reason: string;
  last_error: string | null;
  status: number | null;
  failures: number | null;
  error_since: string | null;
  days: number | null;
  client: string | null;
  paused_at: string | null;
}

/** A reachable feed that has stopped delivering items. */
export interface FeedHealthWarning {
  kind: "redirected_no_items" | "no_items";
  since: string | null;
  days: number;
  redirected_to: string | null;
  content_type: string | null;
}

export interface Feed {
  id: string;
  title: string;
  url: string;
  feed_type: string;
  site_url: string | null;
  icon_url: string | null;
  description: string | null;
  language: string | null;
  last_fetched_at: string | null;
  fetch_interval_minutes: number;
  error_count: number;
  last_error: string | null;
  is_active: boolean;
  /** Start of the current failure streak; null once a fetch succeeds. */
  error_since?: string | null;
  /** Set when the health check paused the feed; null when a person did. */
  auto_paused_at?: string | null;
  pause_reason?: FeedPauseReason | null;
  health_warning?: FeedHealthWarning | null;
  adapter_config: Record<string, unknown>;
  intel_extraction_mode: "full" | "selective" | "manual" | "none";
  ai_analysis_enabled: boolean;
  auto_extract_on_ingest: boolean;
  extract_detection_rules: boolean;
  extract_tools: boolean;
  /** Phrases, one per line; an incoming article whose title contains one is
   * dropped before it is saved. Null = no filter. */
  exclude_title_patterns?: string | null;
  reliability_rating: string | null;
  timeliness_rating: string | null;
  relevance_rating: string | null;
  analyst_notes: string | null;
  last_reviewed_at: string | null;
  category_id: string | null;
  custom_title: string | null;
  is_muted: boolean;
  /** Shown in public read-only mode. Only an admin can change it. */
  visible_to_visitors?: boolean;
  retention_days: number | null;
  unread_count: number;
  /** True when per-user subscriptions are on: is_muted is your own state and
   * "unsubscribe" only affects you. */
  per_user?: boolean;
  created_at: string;
}

/** @deprecated Use Feed directly — subscriptions have been merged into Feed */
export type Subscription = Feed;

export interface Category {
  id: string;
  name: string;
  parent_id: string | null;
  position: number;
  created_at: string;
  children: Category[];
  feed_count: number;
  /** Pipeline settings a feed added to this category starts with. A key that
   * is absent falls back to the global default. */
  feed_defaults?: CategoryFeedDefaults;
}

export interface CategoryFeedDefaults {
  intel_extraction_mode?: "full" | "selective" | "manual" | "none";
  ai_analysis_enabled?: boolean;
  extract_tools?: boolean;
  auto_extract_on_ingest?: boolean;
  extract_detection_rules?: boolean;
}

export interface EntryMediaBrief {
  id: string;
  media_type: "audio" | "video" | "image" | "photo" | "document";
  url: string;
  thumbnail_url: string | null;
  duration_seconds: number | null;
}

export interface Entry {
  id: string;
  feed_id: string;
  guid: string | null;
  url: string | null;
  title: string;
  translated_title: string | null;
  author: string | null;
  summary: string | null;
  published_at: string | null;
  fetched_at: string;
  word_count: number | null;
  content_hash: string | null;
  image_url: string | null;
  feed_title: string | null;
  feed_type: string | null;
  metadata: Record<string, unknown> | null;
  media: EntryMediaBrief[];
  is_read: boolean;
  is_starred: boolean;
  is_bookmarked: boolean;
  tags: EntryTag[];
  // Signal engine (present only when surfaced and above the radar threshold)
  priority_score?: number | null;
  top_signals?: { type: string; explanation: string }[];
  is_echo?: boolean;
  // Exposure (read-time, per-user; present only for radar-sorted entries
  // whose CVEs affect the vendors/products the user runs)
  exposure?: EntryExposure | null;
  personal?: EntryPersonalization | null;
}

export type ExposurePosture = "blind" | "no_rule" | "defended";

/** Read-time lift from this analyst's own learned Radar weights, with the
 *  families that produced it. Only present when personalisation is active and
 *  the analyst's weights actually moved this entry. */
export interface EntryPersonalization {
  lift: number;
  families: { family: string; weight: number; delta: number }[];
}

export interface EntryExposure {
  lift: number;
  posture: ExposurePosture | null;
  asset_name: string | null;
  asset_type: "vendor" | "product" | null;
  cve_ids: string[];
  missing_data_sources: string[];
}

export interface PrioritySignal {
  type: string;
  family: string;
  /** Raw signal strength, before rarity weighting. */
  score: number;
  /** What this signal actually contributed to the score: raw × rarity weight ×
   *  family multiplier. Negative for feed_echo. Absent on older payloads. */
  weighted?: number;
  explanation: string;
}

export interface EntryDetail extends Entry {
  content_html: string | null;
  content_text: string | null;
  duplicates: EntryDuplicate[];
  translated_html: string | null;
  translation_source_language: string | null;
  translation_target_language: string | null;
  translated_at: string | null;
  // Full signal breakdown for the reader's "Why it's ranked" card
  priority_signals?: PrioritySignal[];
  // The raw signal sum priority_score (0–10) was scaled from — what the
  // priority_signals' `weighted` values add up to
  priority_raw?: number | null;
  // When is_echo is true, the earlier entry this one echoes (near-duplicate of)
  echo_of?: EchoOf | null;
}

export interface EchoOf {
  entry_id: string;
  title: string;
  feed_title: string;
  published_at?: string | null;
  shared?: number | null;
  total?: number | null;
}

export interface TranslateEntryResponse {
  entry_id: string;
  translated_html: string;
  translated_title: string | null;
  source_language: string;
  target_language: string;
  translated_at: string;
  cached: boolean;
}

export interface EntryDuplicate {
  entry_id: string;
  feed_title: string;
  feed_id: string;
}

export interface PodcastShow {
  id: string;
  feed_id: string;
  author: string | null;
  categories: string[];
  is_explicit: boolean;
  podcast_type: string;
  artwork_url: string | null;
  created_at: string;
  feed_title: string;
  feed_url: string;
  description: string | null;
  episode_count: number;
}

export interface PlaybackProgress {
  id: string;
  entry_media_id: string;
  position_seconds: number;
  is_completed: boolean;
  updated_at: string;
}

export interface PlaybackInProgressItem {
  entry_media_id: string;
  entry_id: string;
  entry_title: string;
  feed_title: string;
  media_type: string;
  media_url: string;
  thumbnail_url: string | null;
  duration_seconds: number | null;
  position_seconds: number;
  updated_at: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

// Phase 3: Search, Notes, Tags, Export

export interface SearchHit {
  id: string;
  title: string;
  content_text: string | null;
  summary: string | null;
  author: string | null;
  feed_title: string | null;
  feed_id: string | null;
  feed_type: string | null;
  published_at: string | number | null;
  url: string | null;
  tags: string[];
  /** Tags the viewer sees on this hit, with chip presentation: global tags plus their own personal assignments. */
  tag_details?: EntryTag[];
  word_count: number | null;
  is_read: boolean;
  is_starred: boolean;
  is_bookmarked: boolean;
  _matchesPosition?: Record<string, unknown>;
  _rankingScore?: number;
  _formatted?: Record<string, string>;
}

export interface SearchResponse {
  hits: SearchHit[];
  query: string;
  processingTimeMs: number;
  estimatedTotalHits: number;
  facetDistribution?: Record<string, Record<string, number>>;
  searchUnavailable?: boolean;
}

/**
 * The slice of the search UI a saved search restores alongside its query.
 *
 * Everything expressible in the query language lives in `query`; this carries
 * the state the rail owns but the query string cannot say — which halves of the
 * index are searched, and how the intelligence results are narrowed. `tags` is
 * the older structured form, still accepted and folded into `tag:` tokens.
 */
export interface SavedSearchFilters {
  scope?: "feeds" | "workbench" | "everything";
  entity_type?: string | null;
  match_kinds?: ("direct" | "mention")[];
  tags?: string[];
  [key: string]: unknown;
}

export interface SavedSearch {
  id: string;
  name: string;
  display_name: string | null;
  query: string | null;
  filters: SavedSearchFilters;
  unread_count: number;
  total_count: number;
  created_at: string;
}

// Unified search types

export interface UnifiedSearchResponse {
  entries: {
    hits: SearchHit[];
    estimatedTotalHits: number;
    facetDistribution?: Record<string, Record<string, number>>;
  };
  entities: {
    items: EntitySearchResult[];
    counts: Record<string, number>;
  };
  query: string;
  parsed_filters: ParsedFilterResponse[];
  /**
   * A corrected query, when the submitted one looks like a multi-word value that
   * split: `country:North Korea` proposes `country:"North Korea"`. Only set when
   * the extended value is a real value for that field, so it stays absent on a
   * deliberate filter-plus-search-term like `threat_actor:APT29 ransomware`.
   */
  did_you_mean?: string | null;
  /**
   * Names that parsed as `name:value` but are not fields — usually a typo like
   * `titel:`. Their values were searched as free text; the UI says so, because
   * a filter that silently is not a filter is worse than one that errors.
   */
  unknown_fields?: string[];
  processingTimeMs: number;
}

export interface EntitySearchResult {
  id: string;
  type: string;
  // TTP
  technique_id?: string;
  technique_name?: string;
  tactic?: string;
  platforms?: string[];
  data_sources?: string[];
  mitre_url?: string;
  detection?: string;
  is_subtechnique?: boolean;
  // CVE
  cve_id?: string;
  cvss_score?: number | null;
  severity?: string;
  description?: string;
  epss_score?: number | null;
  epss_percentile?: number | null;
  exploit_availability?: string;
  exploit_status?: string;
  // Threat Actor
  name?: string;
  aliases?: string[];
  country?: string;
  motivation?: string;
  mitre_id?: string;
  // Campaign (status / tlp_marking / tags already declared below)
  start_date?: string | null;
  end_date?: string | null;
  last_activity_at?: string | null;
  // Malware
  malware_type?: string;
  // Country
  iso_code?: string;
  region?: string;
  // Sector
  slug?: string;
  // Detection Rule
  title?: string;
  rule_type?: string;
  // PIR (Intelligence Requirement)
  priority?: string;
  category?: string;
  match_count?: number;
  // Tool
  tool_type?: string;
  // Ransomware victim
  sector?: string | null;
  domain?: string | null;
  disclosure_count?: number;
  // Campaign / Report
  tlp_marking?: string;
  template_type?: string;
  summary?: string;
  tags?: string[];
  // Observable (kind is shared with CWE's weakness/category kind)
  kind?: string;
  label?: string | null;
  role?: string | null;
  current_confidence?: number;
  sighting_count?: number;
  created_via?: string | null;
  evidence?: string | null;
  // Common
  value?: string;
  status?: string;
  confidence?: number | null;
  article_count?: number;
  co_occurrence_count?: number;
  proximity_score?: number | null;
  first_seen_at?: string;
  last_seen_at?: string;
}

export interface ParsedFilterResponse {
  field: string;
  value: string;
  exact: boolean;
  negated: boolean;
  raw: string;
}

export interface AutocompleteSuggestion {
  type: "field" | "value";
  text: string;
  description?: string;
  category?: string;
  field?: string;
  insert: string;
}

export interface Note {
  id: string;
  created_by: string | null;
  entry_id: string | null;
  title: string;
  content_markdown: string;
  content_html: string | null;
  tags: string[];
  is_pinned: boolean;
  created_at: string;
  updated_at: string;
  creator_username?: string | null;
  entry_title?: string | null;
  feed_title?: string | null;
}

export interface Tag {
  id: string;
  name: string;
  color: string;
  /** Promoted tags render as chips in the entry's badge row. */
  display_as_chip: boolean;
  /** Chip tooltip. */
  description: string | null;
  /**
   * Global: one shared assignment per entry that everyone sees. Personal (the
   * default): each user's assignments are their own and nobody else sees them.
   */
  is_global: boolean;
  /** Entries carrying the tag as the viewer sees them: their own for a personal tag, everyone's for a global one. */
  entry_count: number;
  created_at: string;
}

/** A tag as it sits on one entry, from the viewer's point of view. */
export interface EntryTag {
  id?: string;
  name: string;
  color: string;
  display_as_chip?: boolean;
  description?: string | null;
  is_global?: boolean;
  /** The viewer's own assignment of a personal tag; false for a global tag's shared row. */
  personal?: boolean;
}

// Phase 4: AI & Threat Intelligence

export interface AIProvider {
  id: string;
  name: string;
  provider_type: "claude" | "claude_code" | "ollama" | "openai_compatible";
  base_url: string | null;
  models: string[];
  is_active: boolean;
  config: Record<string, unknown>;
  /** Whether this provider type can execute tool calls (agent harness). */
  supports_tools: boolean;
  paused_until: string | null;
  paused_reason: string | null;
  /** null = the instance's provider; set = a personal key owned by that user. */
  user_id: string | null;
  /** Only on the admin's user-keys listing. */
  owner_username?: string | null;
  /** When the key last answered a test, and what the last test said if it failed. */
  last_tested_at?: string | null;
  last_test_error?: string | null;
  created_at: string;
  updated_at: string;
}

export interface AIProviderTestResult {
  success: boolean;
  message: string;
  models: string[];
}

export interface AITask {
  id: string;
  name: string;
  display_name: string;
  description: string | null;
  category: string | null;
  variables: string[];
  is_system: boolean;
  /** Agentic task — only works on a tool-capable provider (Claude Code CLI). */
  requires_tools: boolean;
  is_deprecated: boolean;
  show_in_entry_actions: boolean;
  entry_action_order: number | null;
  /** Renders as an action row on entity profile AI tabs. */
  show_in_entity_actions: boolean;
  /** Shipped default structured-output schema (null = free-form text task). */
  output_schema: Record<string, unknown> | null;
  /** UI-set replacement; providers use override ?? default. */
  output_schema_override: Record<string, unknown> | null;
  /** A person's own key may answer this task. */
  allows_user_provider: boolean;
  /** Pipeline tasks: the flag can't be turned on. */
  user_provider_locked: boolean;
  created_at: string;
}

export interface AITaskAssignment {
  id: string;
  created_by: string | null;
  task_id: string;
  provider_id: string;
  model_name: string;
  is_enabled: boolean;
  config: Record<string, unknown>;
  task_name?: string;
  provider_name?: string;
}

export interface AIPromptTemplate {
  id: string;
  task_id: string;
  created_by: string | null;
  name: string;
  template_text: string;
  // Optional cacheable system block. Null/undefined = no system prompt
  // (legacy flat-prompt mode).
  system_text: string | null;
  variables: string[];
  is_active: boolean;
  version: number;
  created_at: string;
}

export interface AIResult {
  id: string;
  entry_id: string | null;
  target_type: string | null;
  target_id: string | null;
  is_current: boolean;
  task_id: string;
  task_name: string | null;
  provider_id: string | null;
  model_name: string | null;
  parsed_result: Record<string, unknown> | null;
  tokens_input: number | null;
  tokens_output: number | null;
  cost_estimate: string | null;
  processing_time_ms: number | null;
  /** Who asked and who answered. provider_name outlives the provider row. */
  caller_kind: "user" | "system" | "automation" | "share" | null;
  user_id: string | null;
  /** Set when a personal key paid for this result. */
  key_owner_id: string | null;
  provider_name: string | null;
  created_at: string;
}

// --- Personal AI (Settings → My AI) ---

export interface UserAIRoute {
  id: string;
  task_id: string | null;
  task_name: string | null;
  /** Both null on a per-task row = this task goes to the instance's provider by choice. */
  provider_id: string | null;
  provider_name: string | null;
  model_name: string | null;
  config: Record<string, unknown>;
  updated_at: string;
}

export interface UserAIPolicy {
  allow_user_ai_providers: boolean;
  require_user_ai_provider: boolean;
  provider_types: string[];
  allow_private_endpoints: boolean;
  daily_request_cap: number;
  site_allowance_per_user: number;
}

export interface UserAIKeyUsage {
  provider_id: string;
  provider_name: string;
  provider_type: string;
  month_cost: string;
  month_requests: number;
}

export interface UserAIUsage {
  month_cost: string;
  monthly_cap_usd: string;
  requests_today: number;
  daily_request_cap: number;
  site_requests_today: number;
  site_allowance_per_user: number;
  month_resets_at: string;
  by_key: UserAIKeyUsage[];
}

/** Why a person's key can't answer right now (the backend's FALLBACK_REASONS). */
export type UserAIBlockedReason =
  | "no_key"
  | "key_disabled"
  | "key_paused"
  | "type_not_allowed"
  | "endpoint_blocked"
  | "monthly_cap"
  | "daily_cap";

export interface UserAIPromptRow {
  task_id: string;
  task_name: string;
  display_name: string;
  category: string | null;
  requires_tools: boolean;
  site_provider_name: string | null;
  site_model_name: string | null;
  route: UserAIRoute | null;
  month_cost: string;
  /** What a click on this task does right now, by the same lookup the server runs. */
  will_run_on: "user" | "site" | "refused";
  /** Set when the person's key can't answer: why the click falls back or is refused. */
  blocked_reason: UserAIBlockedReason | null;
}

export interface UserAIPolicyStatus extends UserAIPolicy {
  // Whether this person has any routing set up. False means no personal key
  // can touch a task, so a reader panel need not fetch the overview.
  has_routes: boolean;
}

export interface UserAIOverview {
  policy: UserAIPolicy;
  fallback_to_site: boolean;
  monthly_cap_usd: string | null;
  usage: UserAIUsage;
  tasks: UserAIPromptRow[];
  /** The default key route (task_id null), whether or not any task row still shows it. */
  default_route: UserAIRoute | null;
}

// --- AI Conversations ---

export type AIConversationScope = "entry" | "multi_entry" | "entity" | "global";

export interface AIConversationMessage {
  role: "user" | "assistant";
  content: string;
  created_at?: string;
  meta?: Record<string, unknown> | null;
}

export interface AIConversationSummary {
  id: string;
  title: string | null;
  scope_type: AIConversationScope;
  scope_id: string | null;
  message_count: number;
  updated_at: string;
}

export interface AIConversation {
  id: string;
  title: string | null;
  scope_type: AIConversationScope;
  scope_id: string | null;
  entry_ids: string[];
  messages: AIConversationMessage[];
  created_at: string;
  updated_at: string;
}

export interface TTP {
  id: string;
  technique_id: string;
  technique_name: string;
  tactic: string | null;
  tactics: string[];
  description: string | null;
  platforms: string[];
  data_sources: string[];
  mitre_url: string | null;
  detection: string | null;
  is_subtechnique: boolean;
  parent_technique_id: string | null;
  is_deprecated: boolean;
  superseded_by: string | null;
  matrix_domain: string | null;
  first_seen_at: string;
  last_seen_at: string;
  article_count: number;
  confidence?: string | null;
  source_text?: string | null;
}

export interface TTPFamilyRef {
  id: string;
  technique_id: string;
  technique_name: string;
  is_deprecated: boolean;
}

export interface TTPRelatedTechniques {
  parent: TTPFamilyRef | null;
  subtechniques: TTPFamilyRef[];
  replacement: TTPFamilyRef | null;
}

export interface CVEReference {
  url: string;
  source?: string | null;
  tags?: string[];
}

/**
 * KEV enrichment appends a record object; Metasploit enrichment appends a bare
 * slug string. Use `exploitSourceNames()` to render either shape.
 */
export type ExploitSource = string | { source?: string; name?: string; type?: string; [key: string]: unknown };

export interface CVE {
  id: string;
  cve_id: string;
  cvss_score: number | null;
  severity: string | null;
  description: string | null;
  affected_products: Array<Record<string, unknown>>;
  exploit_status: string | null;
  exploit_availability: string | null;
  exploit_status_source?: string | null;
  exploit_sources: ExploitSource[];
  references_?: Array<CVEReference | string>;
  nvd_data: Record<string, unknown>;
  timeline: Array<{ date: string; event: string }>;
  first_seen_at: string;
  updated_at: string;
  article_count?: number;
  // EPSS
  epss_score?: number | null;
  epss_percentile?: number | null;
  epss_updated_at?: string | null;
  epss_previous_score?: number | null;
  epss_changed_at?: string | null;
  // Exploit tracking
  github_poc_count?: number | null;
  github_poc_urls?: string[];
  metasploit_module?: string | null;
  // CISA KEV
  is_kev?: boolean;
  kev_date_added?: string | null;
  kev_due_date?: string | null;
  // Computed
  priority?: string | null;
  risk_tier?: "critical" | "high" | "medium" | "low" | null;
}

export interface ThreatActor {
  id: string;
  name: string;
  aliases: string[];
  description: string | null;
  mitre_id: string | null;
  country: string | null;
  origin_country_id: string | null;
  motivation: string | null;
  actor_type?: string | null;
  associated_ttps: Array<Record<string, unknown>>;
  targeted_sectors: string[];
  first_seen_at: string;
  last_seen_at: string;
  article_count: number;
  matched_names?: string[] | null;
  wikipedia_url?: string | null;
  wikipedia_image_url?: string | null;
  created_via?: string | null;
  created_confidence?: string | null;
  needs_review?: boolean;
}

export interface Mitigation {
  id: string;
  mitre_id: string | null;
  name: string;
  description: string | null;
  mitre_url: string | null;
  cis_controls: string[];
  nist_controls: string[];
  article_count: number;
  first_seen_at: string;
  last_seen_at: string;
  wikipedia_url?: string | null;
  wikipedia_image_url?: string | null;
  confidence?: string | null;
  source?: string | null;
}

export interface OffensiveTool {
  id: string;
  name: string;
  aliases: string[];
  description: string | null;
  tool_type: string | null;
  platforms: string[];
  malpedia_url: string | null;
  github_url: string | null;
  detection_artifacts: Record<string, unknown>;
  mitre_id?: string | null;
  article_count: number;
  first_seen_at: string;
  last_seen_at: string;
  wikipedia_url?: string | null;
  wikipedia_image_url?: string | null;
  created_via?: string | null;
  created_confidence?: string | null;
  needs_review?: boolean;
  confidence?: string | null;
  matched_names?: string[] | null;
}

export interface Vendor {
  id: string;
  name: string;
  aliases: string[];
  description: string | null;
  website: string | null;
  vendor_type: string | null;
  article_count: number;
  first_seen_at: string;
  last_seen_at: string;
  confidence?: string | null;
  source?: string | null;
  matched_names?: string[] | null;
  wikipedia_url?: string | null;
  wikipedia_image_url?: string | null;
}

export interface Product {
  id: string;
  vendor_id: string | null;
  vendor_name: string | null;
  name: string;
  aliases: string[];
  description: string | null;
  product_type: string | null;
  website: string | null;
  article_count: number;
  first_seen_at: string;
  last_seen_at: string;
  confidence?: string | null;
  source?: string | null;
  matched_names?: string[] | null;
  wikipedia_url?: string | null;
  wikipedia_image_url?: string | null;
}


export interface MalwareFamily {
  id: string;
  name: string;
  aliases: string[];
  description: string | null;
  malpedia_url: string | null;
  malware_type: string | null;
  mitre_id?: string | null;
  associated_actors: Array<Record<string, unknown>>;
  targeted_sectors: string[];
  first_seen_at: string;
  last_seen_at: string;
  article_count: number;
  matched_names?: string[] | null;
  wikipedia_url?: string | null;
  wikipedia_image_url?: string | null;
  created_via?: string | null;
  created_confidence?: string | null;
  needs_review?: boolean;
}

export interface Country {
  id: string;
  name: string;
  iso_code: string | null;
  aliases: string[];
  region: string | null;
  description: string | null;
  first_seen_at: string;
  last_seen_at: string;
  article_count: number;
  targeting_actor_count?: number;
  wikipedia_url?: string | null;
  wikipedia_image_url?: string | null;
}

export interface EntryCountry extends Country {
  role: string | null;
  confidence: string | null;
  source: string | null;
  matched_names?: string[] | null;
}

export interface CountryProfileActorSummary {
  id: string;
  name: string;
  aliases: string[];
  motivation: string | null;
  last_seen_at: string | null;
  article_count: number;
}

export interface CountryProfileCampaign {
  id: string;
  name: string;
  status: string;
  role: string;
  start_date: string | null;
}

export interface CountryProfileEntry {
  id: string;
  title: string;
  published_at: string | null;
  role: string | null;
}

export interface CountryProfileRelated {
  id: string;
  name: string;
  iso_code: string | null;
  shared_entries: number;
}

export interface CountryProfile {
  country: Country;
  origin_actors: CountryProfileActorSummary[];
  targeting_actors: CountryProfileActorSummary[];
  campaigns: CountryProfileCampaign[];
  recent_entries: CountryProfileEntry[];
  role_breakdown: Record<string, number>;
  related_countries: CountryProfileRelated[];
}

export interface Sector {
  id: string;
  slug: string;
  name: string;
  aliases: string[];
  description: string | null;
  first_seen_at: string;
  last_seen_at: string;
  article_count: number;
  /** Actors / malware with an asserted targets-sector claim (list endpoint). */
  targeting_actor_count?: number;
  targeting_malware_count?: number;
  /** Leak-site victim disclosures in the last 90 days (list endpoint). */
  victim_count?: number;
}

/** A sector linked to an entry. `sector`/`label` are the pre-entity spellings of `slug`/`name`. */
export interface EntrySector {
  id: string;
  slug: string;
  name: string;
  sector: string;
  label: string;
  confidence: string | null;
  source: string | null;
}

export interface SectorProfileNamed {
  id: string;
  name: string;
  article_count: number;
}

export interface SectorProfileClaim extends SectorProfileNamed {
  /** rollup | enrichment | seed | analyst */
  source: string;
}

export interface SectorProfileCampaign {
  id: string;
  name: string;
  status: string;
  start_date: string | null;
}

export interface SectorProfileVictim {
  id: string;
  victim_id: string;
  victim_name: string;
  group: string | null;
  country: string | null;
  country_code: string | null;
  posted_at: string | null;
}

export interface SectorProfileCountry {
  id: string;
  name: string;
  iso_code: string | null;
  article_count: number;
  victim_count: number;
}

export interface MonthCount {
  month: string;
  count: number;
}

export interface SectorProfile {
  sector: Sector;
  window_days: number;
  reported_actors: SectorProfileNamed[];
  reported_malware: SectorProfileNamed[];
  asserted_actors: SectorProfileClaim[];
  asserted_malware: SectorProfileClaim[];
  campaigns: SectorProfileCampaign[];
  victims: {
    total: number;
    in_window: number;
    monthly: MonthCount[];
    top_groups: Array<{ group: string; victims: number }>;
    recent: SectorProfileVictim[];
  };
  countries: SectorProfileCountry[];
  intel_profiles: Array<{ id: string; name: string }>;
  recent_entries: Array<{ id: string; title: string; published_at: string | null; confidence: string | null }>;
  articles_monthly: MonthCount[];
}

export interface DetectionRule {
  id: string;
  entry_id: string | null;
  created_by: string | null;
  rule_type: string;
  title: string;
  description: string | null;
  rule_content: string;
  severity: string | null;
  tags: string[];
  source_ttps: unknown[];
  source_cves: unknown[];
  is_draft: boolean;
  log_sources: Record<string, unknown> | null;
  mitre_tactics: string[];
  data_sources: string[];
  notes: string | null;
  metadata: Record<string, unknown> | null;
  source_entries: string[];
  source_actors: string[];
  source_campaigns: string[];
  /** Parent rule this one was converted or extended from. */
  derived_from: string | null;
  // Provenance / reuse (research redesign, phase 1)
  license: string | null;
  upstream_updated_at: string | null;
  references: string[];
  source_products: unknown[];
  source_repo: string | null;
  source_author: string | null;
  is_authored_local: boolean;
  telemetry: RuleTelemetry | null;
  created_at: string;
  updated_at: string;
  entry_title: string | null;
  entry_url: string | null;
}

/** Lightweight list-row shape returned by GET /detection-rules (no rule_content). */
export interface DetectionRuleListItem {
  id: string;
  entry_id: string | null;
  rule_type: string;
  title: string;
  severity: string | null;
  tags: string[];
  source_ttps: unknown[];
  source_cves: unknown[];
  source_products: unknown[];
  mitre_tactics: string[];
  data_sources: string[];
  is_draft: boolean;
  source_repo: string | null;
  source_author: string | null;
  license: string | null;
  is_authored_local: boolean;
  linked_entry_count: number;
  linked_actor_count: number;
  telemetry: RuleTelemetry | null;
  created_at: string;
  updated_at: string;
  upstream_updated_at: string | null;
  entry_title: string | null;
  entry_url: string | null;
}

export interface RuleTelemetry {
  required: string[];
  collected: string[];
  missing: string[];
  coverage_pct: number | null;
}

export interface FacetBucket {
  value: string;
  count: number;
}

/** Distribution counts for the rule library's faceted rail (GET /detection-rules/facets). */
export interface DetectionRuleFacets {
  rule_types: FacetBucket[];
  repos: FacetBucket[];
  tactics: FacetBucket[];
  products: FacetBucket[];
}

/** Facet distribution from GET /detection-rules/search, keyed by index attribute.
 *  Counts are self-excluded per facet, so the group you filtered on still lists
 *  its other values. */
export interface RuleSearchFacets {
  rule_type?: FacetBucket[];
  source_repo?: FacetBucket[];
  source_author?: FacetBucket[];
  mitre_tactics?: FacetBucket[];
  source_products?: FacetBucket[];
  data_sources?: FacetBucket[];
  /** Required telemetry across every rule format — what the rail's group faces. */
  telemetry_tokens?: FacetBucket[];
  severity?: FacetBucket[];
  license?: FacetBucket[];
  tags?: FacetBucket[];
  actors?: FacetBucket[];
  malware?: FacetBucket[];
  tools?: FacetBucket[];
  vendors?: FacetBucket[];
  products?: FacetBucket[];
  techniques?: FacetBucket[];
}

/** The rule library's Telemetry facet values, split by feasibility. */
export interface RuleTelemetryVocabulary {
  /** Values the enabled telemetry inventory answers. */
  collected: string[];
  /** Values nothing enabled can answer. */
  missing: string[];
}

export interface RuleSearchResponse {
  items: DetectionRuleListItem[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
  facets: RuleSearchFacets;
}

export interface DetectionRuleVersion {
  id: string;
  rule_id: string;
  version_number: number;
  rule_content: string;
  rule_type: string | null;
  change_description: string | null;
  changed_by: string;
  created_at: string;
}

export interface RuleValidationError {
  line: number | null;
  column: number | null;
  severity: string;
  message: string;
}

export interface RuleValidationResult {
  valid: boolean;
  errors: RuleValidationError[];
  suggestions: string[];
}

export interface FeasibilityResult {
  feasible: string[];
  missing: string[];
  coverage_pct: number;
}

export type DataSourceTaxonomy = Record<string, string[]>;

export interface AICostSummary {
  total_cost_30d: number;
  total_requests_30d: number;
  total_tokens_30d: { input: number; output: number };
}

// Phase 5: Automation

export interface AutomationRule {
  id: string;
  created_by: string | null;
  name: string;
  description: string | null;
  is_enabled: boolean;
  trigger_type: string;
  trigger_config: Record<string, unknown>;
  conditions: Record<string, unknown>;
  actions: Array<Record<string, unknown>>;
  labels: string[];
  last_triggered_at: string | null;
  run_count: number;
  created_at: string;
  updated_at: string;
}

export interface AutomationVariable {
  name: string;
  description: string;
}

export interface AutomationVariableGroup {
  group: string;
  variables: AutomationVariable[];
}

export interface AutomationVariableContext {
  label: string;
  note: string;
  groups: AutomationVariableGroup[];
}

export interface AutomationVariableContexts {
  /** Keyed by execution mode: "per_entry" | "batch" */
  ai_prompt: Record<string, AutomationVariableContext>;
  notification_template: AutomationVariable[];
}

export interface AutomationLog {
  id: string;
  rule_id: string;
  entry_id: string | null;
  trigger_type: string;
  status: string;
  actions_executed: Array<Record<string, unknown>>;
  error_message: string | null;
  executed_at: string;
  rule_name: string | null;
}

export interface RuleExportItem {
  name: string;
  description: string | null;
  trigger_type: string;
  trigger_config: Record<string, unknown>;
  conditions: Record<string, unknown>;
  actions: Array<Record<string, unknown>>;
  labels: string[];
}

export interface RuleExportPayload {
  intelfeed_rule_export: {
    version: number;
    exported_at: string;
    source_instance: string | null;
  };
  rules: RuleExportItem[];
}

export interface RuleImportResponse {
  imported: number;
  skipped: number;
  errors: string[];
  warnings: string[];
  rules: AutomationRule[];
}

export interface WebhookPreset {
  id: string;
  created_by: string | null;
  name: string;
  preset_type: string;
  url: string;
  payload: string;
  headers: Record<string, string>;
  config: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

// Sidebar customization

// The sidebar's reorderable sections. A closed set — the sidebar used to also
// accept user-made groups of external links, which are gone.
export type SidebarSectionId = "nav" | "saved_searches" | "feeds";

// Phase 6: Dashboards & Themes

export interface Theme {
  id: string;
  name: string;
  css_variables: Record<string, string>;
  is_system: boolean;
  is_default: boolean;
  created_by: string | null;
  created_at: string;
}

export interface Dashboard {
  id: string;
  created_by: string | null;
  name: string;
  is_default: boolean;
  sort_order: number;
  created_at: string;
  widgets: DashboardWidget[];
}

export interface DashboardWidget {
  id: string;
  dashboard_id: string;
  widget_type: string;
  title: string | null;
  config: Record<string, unknown>;
  position_x: number;
  position_y: number;
  width: number;
  height: number;
}

export interface WidgetStats {
  entries: { count: number; trend: number };
  cves: { count: number; trend: number };
  unread: { count: number };
}

export interface FeedActivityItem {
  date: string;
  count: number;
}

export interface CVESeverityItem {
  severity: string;
  count: number;
}

export interface TrendingCVEItem {
  id: string;
  cve_id: string;
  cvss_score: number | null;
  description: string | null;
  mention_count: number;
}

export interface AttackHeatmapItem {
  technique_id: string;
  name: string;
  tactic: string | null;
  count: number;
}

export interface ThreatTimelineItem {
  actor: string;
  date: string;
  count: number;
}

export interface AttackTechnique {
  technique_id: string;
  name: string;
  tactic: string | null;
  count: number;
  latest: string | null;
}

// Correlation Events

export interface CorrelationEvent {
  id: string;
  event_type: string;
  entry_id: string | null;
  source_entity_type: string;
  source_entity_id: string;
  source_entity_label: string;
  related_entity_type: string;
  related_entity_id: string;
  related_entity_label: string;
  context: string;
  is_read: boolean;
  created_at: string;
}

export interface CorrelationEventListResponse {
  items: CorrelationEvent[];
  total: number;
  unread_count: number;
}

export interface GroupedCorrelationEventsEntry {
  entry_id: string | null;
  entry_title: string | null;
  entry_url: string | null;
  events: CorrelationEvent[];
  unread_count: number;
  highest_severity: string;
  latest_at: string;
}

export interface CategoryCount {
  category: string;
  count: number;
  unread: number;
}

export interface GroupedCorrelationEventListResponse {
  groups: GroupedCorrelationEventsEntry[];
  categories: CategoryCount[];
  total: number;
  unread_count: number;
}

// Phase 8: Intelligence Correlation & Detection Engineering

/** A row from /cwes — the MITRE weakness catalog plus this corpus's counts. */
export interface ObservableResponse {
  id: string;
  kind: string;
  value: string;
  label?: string | null;
  content?: string | null;
  language?: string | null;
  role?: string | null;
  status: string;
  description?: string | null;
  evidence?: string | null;
  base_confidence: number;
  current_confidence: number;
  confidence_pinned: boolean;
  is_denied: boolean;
  /** Dual-use infrastructure label (vpn/proxy/tor/rmm/kvm/scanner/phish_sim); tagged rows never publish. */
  infra_tag?: string | null;
  needs_review: boolean;
  created_via?: string | null;
  /** Raw junction count — every entry carrying the value, indicator-list files included. */
  sighting_count: number;
  /** Corroboration: distinct reporting entries (articles/advisories/rules) and distinct indicator feeds. */
  report_count: number;
  feed_source_count: number;
  /** Compact enrichment summary (Shodan / GreyNoise / VT) written by the updater. */
  reputation?: {
    asn?: number | string | null;
    country?: string | null;
    ports?: string | null;
    tags?: string | null;
    hostnames?: string | null;
    vt_ratio?: string | null;
    gn_classification?: string | null;
    gn_riot?: boolean | null;
    enriched_at?: string | null;
  } | null;
  first_seen_at: string;
  last_seen_at: string;
  // Decay projection.
  decay_half_life_days?: number | null;
  expires_at?: string | null;
  // Per-entry link context, present only on entry-scoped listings.
  link_source?: string | null;
  link_confidence?: string | null;
  surface_form?: string | null;
  was_defanged?: boolean | null;
}

export interface ObservableCandidateRow {
  kind: string;
  value: string;
  entry_count: number;
  was_defanged: boolean;
  sample_surface?: string | null;
  latest_entry_id?: string | null;
  latest_entry_title?: string | null;
  latest_seen_at?: string | null;
}

export interface ObservableCandidate {
  kind: string;
  value: string;
  surface_form: string;
  was_defanged: boolean;
  paragraph_index: number;
}

export interface ObservableEntryPayload {
  items: ObservableResponse[];
  candidates: ObservableCandidate[];
}

export interface CWEResponse {
  id: string;
  cwe_id: string;
  name: string;
  kind: string;
  abstraction: string | null;
  status: string | null;
  mapping_usage: string | null;
  description: string | null;
  extended_description: string | null;
  parent_cwe_id: string | null;
  likelihood_of_exploit: string | null;
  alternate_terms: string[];
  capec_ids: string[];
  consequences: Array<{ scope?: string | null; impacts?: string[]; note?: string | null }>;
  mitigations: Array<{ phase?: string | null; strategy?: string | null; description?: string | null }>;
  detection_methods: Array<{ method?: string | null; description?: string | null; effectiveness?: string | null }>;
  cwe_url: string | null;
  wikipedia_url: string | null;
  wikipedia_image_url: string | null;
  is_deprecated: boolean;
  superseded_by: string | null;
  article_count: number;
  first_seen_at: string;
  last_seen_at: string;
  /** Direct links only. `cve_count_rolled` includes every descendant, which is
   * the number that means anything at Class/Pillar level. */
  cve_count: number;
  cve_count_rolled: number | null;
  kev_count: number;
  /** Rolled KEV, so it reads against cve_count_rolled rather than beside it. */
  kev_count_rolled: number | null;
  /** Vendor shipping the most CVEs with this weakness. Null is normal —
   * cve_affected resolves only part of the corpus's CPE strings. */
  top_vendor: string | null;
  top_vendor_count: number | null;
}

/** A vendor shipping this weakness. Inverse of CWEVendorRow. */
export interface CWEAffectedVendorRow {
  vendor_id: string;
  name: string;
  cve_count: number;
  kev_count: number;
}

export interface CWEFamilyRef {
  id: string | null;
  cwe_id: string;
  name: string;
  abstraction: string | null;
  cve_count: number;
}

export interface CWEFamilyResponse {
  /** Root-first: pillar → … → parent. */
  lineage: CWEFamilyRef[];
  parent: CWEFamilyRef | null;
  children: CWEFamilyRef[];
  siblings: CWEFamilyRef[];
  replacement: CWEFamilyRef | null;
}

/** One NVD weakness assignment on a CVE. `cwe_id` is null for the
 * NVD-CWE-noinfo / NVD-CWE-Other sentinels, which are kept, not filtered. */
export interface CVEWeaknessRow {
  cwe_ref: string;
  cwe_id: string | null;
  name: string | null;
  description: string | null;
  abstraction: string | null;
  kind: string | null;
  mapping_usage: string | null;
  is_primary: boolean;
  assigner: string | null;
  pillar_cwe_id: string | null;
  pillar_name: string | null;
}

export interface CWEVendorRow {
  cwe_id: string;
  name: string;
  abstraction: string | null;
  cve_count: number;
  share: number;
}

export interface EntitySearchResult {
  id: string;
  type: string;
  match_field?: string;
  /** "direct" = the query matched this entity's name/alias/identifier;
   *  "mention" = it matched its prose, tags or type. Set by the backend. */
  match_kind?: "direct" | "mention";
  // TTP fields
  technique_id?: string;
  technique_name?: string;
  tactic?: string;
  tactics?: string[];
  platforms?: string[];
  data_sources?: string[];
  mitre_url?: string;
  detection?: string;
  is_subtechnique?: boolean;
  parent_technique_id?: string | null;
  is_deprecated?: boolean;
  superseded_by?: string | null;
  matrix_domain?: string | null;
  // CVE fields
  cve_id?: string;
  cvss_score?: number | null;
  severity?: string;
  description?: string;
  epss_score?: number | null;
  epss_percentile?: number | null;
  exploit_availability?: string;
  exploit_status_source?: string | null;
  affected_products?: unknown[];
  github_poc_count?: number | null;
  github_poc_urls?: string[];
  metasploit_module?: string | null;
  is_kev?: boolean;
  kev_date_added?: string | null;
  kev_due_date?: string | null;
  risk_tier?: string | null;
  // CWE fields
  cwe_id?: string;
  kind?: string;
  abstraction?: string | null;
  mapping_usage?: string | null;
  parent_cwe_id?: string | null;
  likelihood_of_exploit?: string | null;
  alternate_terms?: string[];
  capec_ids?: string[];
  consequences?: Array<{ scope?: string | null; impacts?: string[]; note?: string | null }>;
  mitigations?: Array<{ phase?: string | null; strategy?: string | null; description?: string | null }>;
  detection_methods?: Array<{ method?: string | null; description?: string | null; effectiveness?: string | null }>;
  cwe_url?: string | null;
  cve_count?: number;
  cve_count_rolled?: number | null;
  kev_count?: number;
  // Actor/Malware fields
  name?: string;
  aliases?: string[];
  country?: string;
  motivation?: string;
  mitre_id?: string;
  malware_type?: string;
  targeted_sectors?: string[];
  actor_type?: string | null;
  // Country fields
  iso_code?: string;
  region?: string;
  // OffensiveTool fields
  tool_type?: string;
  malpedia_url?: string;
  github_url?: string;
  // Vendor fields
  vendor_type?: string;
  website?: string;
  // Product fields
  product_type?: string;
  vendor_id?: string;
  vendor_name?: string;
  // Rule fields
  rule_type?: string;
  title?: string;
  // Campaign / Report fields
  tlp_marking?: string;
  template_type?: string;
  summary?: string;
  tags?: string[];
  // Entry fields
  url?: string;
  published_at?: string;
  // Note fields. `note_source` says which of the two note tables the row came
  // from, which is what decides where clicking it goes.
  note_source?: 'note' | 'entity_note';
  note_type?: string;
  entry_id?: string | null;
  entry_title?: string | null;
  entity_type?: string;
  entity_id?: string;
  entity_name?: string | null;
  is_pinned?: boolean;
  // Shared
  value?: string;
  status?: string;
  confidence?: number | null;
  article_count?: number;
  co_occurrence_count?: number;
  proximity_score?: number | null;
  proximity_entries?: Array<{
    entry_id: string;
    title?: string;
    score: number;
    published_at?: string | null;
  }>;
  // Relationship strength components (pivot related items)
  strength?: RelationshipStrength;
  /** Story clustering over the evidence entries (relationship_evidence_structure). */
  evidence_structure?: EvidenceStructure;
  relationship_id?: string;
  relationship_type?: string;
  relationship_confidence?: string;
  relationship_source?: string;
  relationship_direction?: 'outbound' | 'inbound';
  relationship_description?: string | null;
  relationship_adjudication?: 'corroborated' | 'coincidental' | 'unsure' | null;
  relationship_evidence_count?: number;
  /** Ubiquitous vendors/products folded as reporting sources in context views. */
  context_role?: 'reporting_source';
  country_relationship?: 'targets' | 'operates_from' | 'infrastructure';
  origin_country_id?: string | null;
  first_seen_at?: string;
  last_seen_at?: string;
  // Wikipedia
  wikipedia_url?: string | null;
  wikipedia_content?: string | null;
  wikipedia_image_url?: string | null;
}

export interface EntitySearchResponse {
  results: EntitySearchResult[];
  total: number;
}

/** One story cluster inside a relationship's evidence. */
export interface EvidenceStory {
  entries: number;
  entry_ids: string[];
  /** Distinct feeds among the story's entries. */
  sources?: number | null;
  first: string | null;
  last: string | null;
  /** Story-thread identity when the cluster's entries belong to a thread. */
  slug: string | null;
  title: string | null;
}

/**
 * Story clustering over a relationship's evidence entries — how the evidence
 * hangs together: recurring (2+ incidents), single_story (one reporting
 * wave), scattered (roundup co-mentions, no shared story), thin (1-2 loose
 * mentions). Absent when the feature is off or the evidence has no embeddings.
 */
export interface EvidenceStructure {
  shape: 'recurring' | 'single_story' | 'scattered' | 'thin';
  stories: EvidenceStory[];
  /** Evidence entries outside any asserting story. */
  loose: number;
  /** Evidence entries the shape was computed from (newest, capped). */
  sampled: number;
}

export interface RelationshipStrength {
  score: number;
  tier: 'weak' | 'moderate' | 'strong';
  closeness: number;
  /** IDF-style counterpart specificity in [0,1]; ubiquitous entities near 0. */
  specificity?: number | null;
  articles: number;
  sources: number;
  first_seen: string | null;
  last_seen: string | null;
  trend: number[];
}

export interface PivotResponse {
  entity: EntitySearchResult;
  related: {
    ttps: EntitySearchResult[];
    cves: EntitySearchResult[];
    threat_actors: EntitySearchResult[];
    malwares: EntitySearchResult[];
    countrys: EntitySearchResult[];
    sectors?: EntitySearchResult[];
    mitigations?: EntitySearchResult[];
    cwes?: EntitySearchResult[];
    tools?: EntitySearchResult[];
    vendors?: EntitySearchResult[];
    products?: EntitySearchResult[];
    observables?: EntitySearchResult[];
    detection_rules: Array<{
      id: string;
      title: string;
      rule_type: string;
      severity: string | null;
      created_at: string;
      /** What the rule detects — powers the graph's coverage badges. */
      source_ttps?: string[];
      source_cves?: string[];
    }>;
  };
  // Pre-truncation totals per related key (e.g. { cves: 870 }); the related
  // arrays themselves are ranked by strength and truncated server-side.
  related_counts?: Record<string, number>;
  /** Library-wide detection coverage over every related technique/CVE:
   *  how many rules in the whole library reference each id. */
  rule_coverage?: { ttps?: Record<string, number>; cves?: Record<string, number> };
  entries: Array<{
    id: string;
    title: string;
    url: string | null;
    published_at: string | null;
    feed_id: string;
  }>;
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  size: number;
  data: Record<string, unknown>;
}

export interface GraphEdgeEntry {
  entry_id: string;
  title: string;
  score: number;
}

export interface GraphEdge {
  source: string;
  target: string;
  weight: number;
  label: string;
  proximity_score?: number | null;
  confidence?: string | null;
  provenance?: string | null;
  relationship_id?: string | null;
  entries?: GraphEdgeEntry[];
}

export interface GraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface TimelineEvent {
  entry_id: string | null;
  title: string;
  url: string | null;
  date: string | null;
  event_type?: "article" | "correlation" | "enrichment" | "detection_rule" | "relationship" | "campaign" | "milestone" | "status_change" | "story";
  /** Client-synthesized story rows only: the thread this event points at. */
  thread_slug?: string;
  severity?: string | null;
  event_subtype?: string | null;
  nav_context?: {
    url?: string;
    entity_type?: string;
    entity_id?: string;
  } | null;
}

export interface TimelineResponse {
  entity: EntitySearchResult;
  events: TimelineEvent[];
}

export interface DetectionSummaryRequest {
  entry_ids: string[];
  include_existing_intelligence?: boolean;
  rule_formats?: string[];
  focus?: "campaign" | "vulnerability" | "malware" | "actor";
}

export interface AttackChainStep {
  step: number;
  phase: string;
  technique: string;
  description: string;
  detection_opportunity: string;
  log_sources: string[];
  detection_feasibility: "high" | "medium" | "low";
}

export interface DetectionIndicator {
  type: string;
  value?: string;
  description?: string;
  context?: string;
  detection_note?: string;
  log_field?: string;
  log_sources?: string[];
  detection_logic?: string;
}

export interface GeneratedRule {
  rule_type: string;
  title: string;
  content: string;
  severity?: string;
}

// Campaigns

export interface Campaign {
  id: string;
  created_by: string | null;
  name: string;
  description: string | null;
  status: string;
  tlp_marking: string;
  start_date: string | null;
  end_date: string | null;
  tags: string[];
  created_at: string;
  updated_at: string;
  entry_count: number;
  entity_count: number;
  /** Publish date of the newest article — what "gone quiet" is measured from. */
  last_activity_at?: string | null;
  /** Publish date of the oldest article — when the coverage actually begins. */
  first_activity_at?: string | null;
}

export interface CampaignCreate {
  name: string;
  description?: string;
  status?: string;
  tlp_marking?: string;
  start_date?: string;
  end_date?: string;
  tags?: string[];
  entry_ids?: string[];
  pivot_entity?: { type: string; id: string };
}

export interface CampaignUpdate {
  name?: string;
  description?: string;
  status?: string;
  tlp_marking?: string;
  start_date?: string;
  end_date?: string;
  tags?: string[];
}

export interface CampaignTimelineEntry {
  entry_id: string;
  title: string;
  url: string | null;
  published_at: string | null;
  notes: string | null;
  /** Set when the thread sweeper folded this article into a story. */
  thread_id: string | null;
  thread_slug: string | null;
  thread_title: string | null;
  /** origin | beat | echo */
  thread_role: string | null;
}

export interface CampaignSuggestion {
  entry_id: string;
  title: string;
  url: string | null;
  published_at: string | null;
  overlap_count: number;
  overlapping_entities: Array<{ type: string; label: string }>;
  /** "same_story" when the campaign already holds part of this article's story. */
  reason: "same_story" | "shared_entities";
  thread_id: string | null;
  thread_slug: string | null;
  thread_title: string | null;
  thread_role: string | null;
  thread_article_count: number | null;
  thread_in_campaign: number | null;
}

// Campaign Saved Searches

export interface CampaignSavedSearch {
  id: string;
  campaign_id: string;
  saved_search_id: string;
  saved_search_name: string;
  saved_search_query: string | null;
  auto_sync: boolean;
  last_synced_at: string | null;
  entries_added: number;
  created_at: string;
}

export interface CampaignSavedSearchSyncResult {
  saved_search_id: string;
  new_entries_added: number;
  total_entries: number;
}

// Campaign Detection Gaps (telemetry-aware)

export interface CoverageRuleRef {
  id: string;
  name: string;
  rule_type: string;
  missing_data_sources: string[];
}

export interface CampaignDetectionGap {
  ttp_id: string;
  technique_id: string;
  technique_name: string;
  tactic: string;
  rule_count: number;
}

export interface CampaignDetectionCovered extends CampaignDetectionGap {
  rules: CoverageRuleRef[];
}

export interface CampaignDetectionLibraryOnly extends CampaignDetectionCovered {
  missing_data_sources: string[];
}

export interface CampaignDetectionGaps {
  total_ttps: number;
  covered_count: number;
  library_only_count: number;
  no_rule_count: number;
  gap_count: number;
  coverage_percentage: number;
  gaps: CampaignDetectionGap[];
  library_only: CampaignDetectionLibraryOnly[];
  covered: CampaignDetectionCovered[];
}

// Technique detection coverage (shared classify endpoint)

export type TechniqueCoverageStatus = 'covered' | 'library_only' | 'no_rule';

export interface TechniqueCoverageInfo {
  status: TechniqueCoverageStatus;
  rule_count: number;
  satisfiable_rule_count: number;
  missing_data_sources: string[];
  rules: CoverageRuleRef[];
}

export interface TechniqueCoverageSummary {
  total: number;
  covered: number;
  library_only: number;
  no_rule: number;
  coverage_percentage: number;
}

export interface TechniqueCoverageResponse {
  summary: TechniqueCoverageSummary;
  techniques: Record<string, TechniqueCoverageInfo>;
}

// Campaign Entities

export interface CampaignEntityResponse {
  id: string;
  campaign_id: string;
  entity_type: 'ttp' | 'cve' | 'threat_actor' | 'malware';
  entity_id: string;
  entity_name: string;
  role: 'primary' | 'secondary' | 'related';
  added_at: string;
}

// Campaign Statistics

export interface CampaignStats {
  entry_count: number;
  entity_counts: {
    ttp: number;
    cve: number;
    threat_actor: number;
    malware: number;
  };
  total_entity_count: number;
  detection_coverage_pct: number;
  date_range: {
    earliest_entry: string | null;
    latest_entry: string | null;
  };
  top_sources: Array<{ feed_name: string; entry_count: number }>;
  entries_over_time: Array<{ date: string; count: number }>;
  entries_over_time_bucket: 'day' | 'week' | 'month';
}

// Campaign Countries

export interface CampaignCountryResponse {
  country_id: string;
  country_name: string;
  country_code: string | null;
  role: 'origin' | 'target';
  added_at: string | null;
}

export interface CampaignCountrySuggestion {
  country_id: string;
  country_name: string;
  country_code: string | null;
  entry_count: number;
  suggested_role: 'origin' | 'target';
}

// Intelligence Requirements

export interface LinkedEntityRef {
  id: string;
  name: string;
}

/** Keys: threat_actors | malware | cves | ttps */
export type RequirementLinkedEntities = Record<string, LinkedEntityRef[]>;

export interface IntelligenceRequirement {
  id: string;
  created_by: string | null;
  title: string;
  description: string | null;
  priority: string;
  status: string;
  category: string;
  keywords: string[];
  linked_feed_ids: string[];
  linked_entities: RequirementLinkedEntities;
  min_relevance: string | null;
  auto_match: boolean;
  match_count: number;
  last_matched_at: string | null;
  expires_at: string | null;
  fulfilled_by_report_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface RequirementCreate {
  title: string;
  description?: string;
  priority?: string;
  category?: string;
  keywords?: string[];
  linked_entities?: RequirementLinkedEntities;
  min_relevance?: string | null;
  expires_at?: string;
}

export interface RequirementUpdate {
  title?: string;
  description?: string;
  priority?: string;
  status?: string;
  category?: string;
  keywords?: string[];
  linked_entities?: RequirementLinkedEntities;
  min_relevance?: string | null;
  expires_at?: string;
}

export interface RequirementMatch {
  requirement_id: string;
  entry_id: string;
  match_type: string;
  matched_on: string;
  matched_at: string;
  relevance: string | null;
  entry_title: string | null;
  entry_url: string | null;
  entry_published_at: string | null;
}

export interface RequirementCoverageBrief {
  id: string;
  title: string;
  priority: string;
  status: string;
  match_count: number;
  last_matched_at: string | null;
  linked_feeds: number;
}

export interface RequirementCoverageSummary {
  total_requirements: number;
  active: number;
  fulfilled: number;
  expired: number;
  draft: number;
  by_priority: Record<string, number>;
  by_category: Record<string, number>;
  with_recent_matches: number;
  stale: number;
  needs_review: RequirementCoverageBrief[];
  requirements: RequirementCoverageBrief[];
}

export interface RequirementEntities {
  ttps: Array<{ id: string; technique_id: string; name: string; tactic: string }>;
  cves: Array<{ id: string; cve_id: string; description: string | null; cvss_score: number | null }>;
  threat_actors: Array<{ id: string; name: string; aliases: string[] | null }>;
  malware: Array<{ id: string; name: string; type: string | null }>;
}

// Telemetry Sources

export interface TelemetrySource {
  id: string;
  created_by: string | null;
  name: string;
  category: string;
  vendor: string | null;
  product: string | null;
  log_types: string[];
  ingested_into: string | null;
  enabled: boolean;
  notes: string | null;
  created_at: string;
}

export interface TelemetrySourceCreate {
  name: string;
  category: string;
  vendor?: string;
  product?: string;
  log_types?: string[];
  ingested_into?: string;
  enabled?: boolean;
  notes?: string;
}

export interface TelemetrySourceUpdate {
  name?: string;
  category?: string;
  vendor?: string;
  product?: string;
  log_types?: string[];
  ingested_into?: string;
  enabled?: boolean;
  notes?: string;
}

export interface CatalogItem {
  category: string;
  name: string;
  vendor: string;
  product: string;
  log_types: string[];
}

export interface TelemetrySyncResponse {
  synced: Array<{
    id: string;
    name: string;
    category: string;
    vendor: string | null;
    product: string | null;
    enabled: boolean;
    action: string;
  }>;
  created_count: number;
  enabled_count: number;
  disabled_count: number;
  unchanged_count: number;
  total: number;
}

// Intel Reports

export interface IntelReport {
  id: string;
  created_by: string | null;
  title: string;
  template_type: string;
  tlp_marking: string;
  status: string;
  content: Record<string, unknown>;
  summary: string | null;
  version: number;
  entry_ids: string[];
  entity_ids: Record<string, unknown>;
  tags: string[];
  created_at: string;
  updated_at: string;
  published_at: string | null;
}

export interface IntelReportCreate {
  title: string;
  template_type: string;
  tlp_marking?: string;
  content?: Record<string, unknown>;
  summary?: string;
  entry_ids?: string[];
  entity_ids?: Record<string, unknown>;
  tags?: string[];
}

export interface IntelReportUpdate {
  title?: string;
  tlp_marking?: string;
  status?: string;
  content?: Record<string, unknown>;
  summary?: string;
  entry_ids?: string[];
  entity_ids?: Record<string, unknown>;
  tags?: string[];
  change_description?: string;
}

export interface IntelReportVersion {
  id: string;
  report_id: string;
  version: number;
  content: Record<string, unknown>;
  change_description: string | null;
  created_by: string;
  created_at: string;
}

export interface ReportTemplateSection {
  name: string;
  title: string;
  description: string;
  required: boolean;
  type: "narrative" | "data";
  ai_prompt_hint?: string;
}

export interface ReportTemplate {
  id: string;
  type: string;
  name: string;
  sections: ReportTemplateSection[];
  description: string;
  is_builtin: boolean;
  is_shared: boolean;
  created_by: string | null;
}

export interface SectionGenerateResponse {
  section_name: string;
  content: string;
}

export interface IntelReportFullGenerateRequest {
  source_type: "entry" | "entries" | "search" | "saved_search";
  entry_id?: string;
  entry_ids?: string[];
  search_query?: string;
  saved_search_id?: string;
  search_limit?: number;
  template_type: string;
  title?: string;
  tlp_marking?: string;
  focus?: string;
  audience?: string;
  tags?: string[];
}

export interface IntelReportFullGenerateResponse {
  report: IntelReport;
  task_id: string;
}

// Comments

export interface Comment {
  id: string;
  commentable_type: string;
  commentable_id: string;
  user_id: string;
  content: string;
  parent_id: string | null;
  created_at: string;
  updated_at: string;
  username: string | null;
  reply_count: number;
  mentions: string[];
}

export interface CommentCreate {
  commentable_type: string;
  commentable_id: string;
  content: string;
  parent_id?: string;
}

// Entity Notes

export interface EntityNote {
  id: string;
  entity_type: string;
  entity_id: string;
  user_id: string;
  title: string | null;
  content: string;
  note_type: string;
  tags: string[];
  created_at: string;
  updated_at: string;
  username: string | null;
  entity_name: string | null;
}

export interface EntityNoteCreate {
  entity_type: string;
  entity_id: string;
  title?: string | null;
  content: string;
  note_type?: string;
  tags?: string[];
}

// Glossary

export interface GlossaryTechnology {
  name: string;
  url: string | null;
}

export interface GlossaryTerm {
  id: string;
  name: string;
  category: string;
  maturity: string | null;
  description: string;
  long_description: string | null;
  technologies: GlossaryTechnology[];
  search_terms: string[];
  is_system: boolean;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface GlossaryTermCreate {
  name: string;
  category: string;
  maturity?: string;
  description: string;
  long_description?: string;
  technologies?: GlossaryTechnology[];
  search_terms?: string[];
}

export interface GlossaryTermUpdate {
  name?: string;
  category?: string;
  maturity?: string;
  description?: string;
  long_description?: string;
  technologies?: GlossaryTechnology[];
  search_terms?: string[];
}

export interface GlossaryMatch {
  term: GlossaryTerm;
  match_count: number;
}

export interface GlossaryCategory {
  name: string;
  is_nist: boolean;
  color: string;
}

export interface DetectionSummaryResponse {
  executive_summary: string;
  attack_chain: AttackChainStep[];
  indicators: {
    network?: DetectionIndicator[];
    host?: DetectionIndicator[];
    behavioral?: DetectionIndicator[];
  };
  generated_rules: GeneratedRule[];
  related_intelligence: {
    previous_articles?: Array<{ title: string; url?: string; published_at?: string }>;
    existing_detection_rules?: Array<{ rule_type: string; title: string }>;
    related_cves?: Array<{ cve_id: string; description?: string }>;
  };
  gaps_and_recommendations: string[];
}

// Feed Health

export interface FeedHealthSummary {
  healthy: number;
  stale: number;
  erroring: number;
  disabled: number;
  /** Auto-paused by the health check — distinct from switched off by hand. */
  dead: number;
  /** Answering 200 but no longer delivering items. */
  empty?: number;
  total: number;
}

/** A feed's subscriber, as returned to admins. */
export interface FeedSubscriber {
  user_id: string;
  username: string;
  is_muted: boolean;
}

/** Who a feed reaches. Present on feed-health rows for admins only. */
export interface FeedReach {
  subscriber_count: number;
  muted_count: number;
  subscribers: FeedSubscriber[];
}

export interface FeedHealthFeed {
  id: string;
  title: string;
  url: string;
  last_fetched_at: string | null;
  error_count: number;
  last_error: string | null;
  is_active: boolean;
  reliability_rating: string | null;
  /** Start of the current failure streak; null once a fetch succeeds. */
  error_since?: string | null;
  failing_for_days?: number | null;
  /** Set when the health check paused the feed (a 4xx streak past the window). */
  auto_paused_at?: string | null;
  pause_reason?: FeedPauseReason | null;
  health_warning?: FeedHealthWarning | null;
  reach?: FeedReach;
}

export interface FeedSubscribersResponse {
  feed_id: string;
  /** False when per-user subscriptions are off — everyone sees every feed. */
  per_user_active: boolean;
  subscriber_count: number;
  muted_count: number;
  subscribers: FeedSubscriber[];
  non_subscribers: { user_id: string; username: string }[];
}

export interface FeedHealthResponse {
  summary: FeedHealthSummary;
  stale_feeds: FeedHealthFeed[];
  erroring_feeds: FeedHealthFeed[];
  disabled_feeds: FeedHealthFeed[];
  dead_feeds: FeedHealthFeed[];
  empty_feeds?: FeedHealthFeed[];
}

// Feed Value Scoring

/** Resolved ingest pipeline for one feed, from GET /feeds/{id}/pipeline. */
/** GET /feeds/{id}/ai-usage */
export interface FeedAIUsage {
  feed_id: string;
  days: number;
  /** Calls that moved tokens; reuses from near-duplicates are not counted. */
  runs: number;
  tokens_input: number;
  tokens_output: number;
  last_run_at: string | null;
  ai_analysis_enabled: boolean;
}

/** POST /feeds/{id}/title-filter/preview */
export interface TitleFilterPreview {
  checked: number;
  dropped: number;
  examples: string[];
}

export interface FeedPipeline {
  engine_enabled: boolean;
  stages: Record<string, { enabled: boolean; config?: Record<string, unknown> }>;
  /** Per stage: "legacy" (the Feed booleans) or the plan scope that overrode it. */
  decided_by: Record<string, "legacy" | "global" | "category" | "feed">;
}

/** One feed's value score plus its rank, from GET /feeds/{id}/value. */
export interface FeedValueDetail {
  feed_id: string;
  scored: boolean;
  score?: number;
  tier?: string;
  articles?: number;
  entity_yield?: number;
  unique_entities?: number;
  entity_introductions?: number;
  correlation_events?: number;
  detection_rules?: number;
  pir_matches?: number;
  dimensions?: FeedValueDimensions;
  rank?: number | null;
  of?: number;
  days?: number;
}

export interface FeedValueDimensions {
  entity_introductions: number;
  correlation_events: number;
  detection_rules: number;
  pir_matches: number;
}

export interface FeedValueScore {
  feed_id: string;
  feed_title: string;
  feed_type: string;
  reliability_rating: string | null;
  score: number;
  tier: string;
  articles: number;
  unique_entities: number;
  entity_introductions: number;
  correlation_events: number;
  detection_rules: number;
  pir_matches: number;
  dimensions: FeedValueDimensions;
}

export interface FeedValueSummary {
  total: number;
  avg_score: number;
  scored: number;
  no_value: number;
}

export interface FeedReviewCandidate {
  feed_id: string;
  feed_title: string;
  feed_type: string;
  reliability_rating: string | null;
  articles: number;
}

export interface FeedValueResponse {
  feeds: FeedValueScore[];
  summary: FeedValueSummary;
  review_candidates: FeedReviewCandidate[];
}

// Analytics

export interface AnalyticsOverview {
  entity_counts: {
    cves: number;
    threat_actors: number;
    malware: number;
    ttps: number;
  };
  detection: {
    total_rules: number;
    published_rules: number;
  };
  events: {
    recent_7d: number;
    unread: number;
  };
}

export interface TrendingEntity {
  entity_id: string;
  entity_name: string;
  article_count?: number;
  severity?: string;
  technique_id?: string;
  first_seen: string | null;
  last_seen?: string | null;
}

export interface DetectionCoverageResponse {
  total_ttps: number;
  covered_ttps: number;
  coverage_percentage: number;
  tactic_summary: Record<string, { total: number; covered: number }>;
  gaps: Array<{
    technique_id: string;
    technique_name: string;
    tactic: string;
  }>;
}

export interface VelocityDay {
  date: string;
  count: number;
}

export interface VelocityResponse {
  days: number;
  velocity: Record<string, VelocityDay[]>;
}

export interface EntryInsight {
  type: string;
  severity: string;
  message: string;
  entity_id?: string;
  entity_type?: string;
  action?: string;
  related_ids?: string[];
  campaign_id?: string;
  requirement_id?: string;
  overlap_count?: number;
}

// Entity Relationships

export interface EntityRelationship {
  id: string;
  source_type: string;
  source_id: string;
  target_type: string;
  target_id: string;
  relationship_type: string;
  confidence: string;
  source: string;
  description: string | null;
  evidence_entry_ids: string[];
  created_by: string | null;
  created_at: string;
  updated_at: string;
  source_name?: string;
  target_name?: string;
}

export interface EntityRelationshipCreate {
  source_type: string;
  source_id: string;
  target_type: string;
  target_id: string;
  relationship_type: string;
  confidence?: string;
  description?: string;
  evidence_entry_ids?: string[];
}

export interface EntityRelationshipUpdate {
  relationship_type?: string;
  confidence?: string;
  description?: string;
  evidence_entry_ids?: string[];
}

// --- Enrichment ---

export interface EnrichmentSource {
  id: string;
  source_type: string;
  display_name: string;
  is_enabled: boolean;
  trigger_mode: string;
  has_api_key: boolean;
  requires_api_key: boolean;
  shared_key_group: string | null;
  rate_limit_config: Record<string, number>;
  min_confidence_threshold: string;
  daily_budget: number | null;
  daily_budget_used: number;
  supported_entity_types: string[];
  last_synced_at: string | null;
  health_status: string;
  config: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface EnrichmentBudgetSummary {
  source_type: string;
  display_name: string;
  daily_budget: number;
  used_today: number;
  remaining: number;
}

export interface EnrichmentResult {
  id: string;
  entity_type: string;
  entity_id: string;
  source_type: string;
  parsed_data: Record<string, unknown>;
  enriched_at: string;
  expires_at: string;
  status: string;
}

export interface UserEnrichmentOverride {
  id: string;
  source_id: string;
  has_api_key: boolean;
  created_at: string;
}

export interface EnrichmentStatus {
  total_sources: number;
  enabled_sources: number;
  healthy_sources: number;
  enrichments_today: number;
}

// --- Detection Summary Persistence ---

export interface DetectionSummarySaved {
  id: string;
  created_by: string | null;
  title: string;
  entry_ids: string[];
  analysis_focus: string;
  summary_content: DetectionSummaryResponse;
  created_at: string;
  updated_at: string;
}

// --- Rule Provenance ---

export interface RuleProvenance {
  rule: {
    id: string;
    title: string;
    rule_type: string;
    created_at: string;
  };
  entries: Array<{ id: string; title: string; url: string | null; published_at: string | null }>;
  ttps: Array<{ id: string; technique_id: string; technique_name: string; tactic: string | null }>;
  threat_actors: Array<{ id: string; name: string; aliases: string[] }>;
  malware: Array<{ id: string; name: string; malware_type: string | null }>;
}

// --- Rules Needing Review ---

export interface RuleNeedingReview {
  rule_id: string;
  rule_title: string;
  rule_type: string;
  updated_at: string;
  techniques: string[];
  new_article_count: number;
}

// --- Version Diff ---

export interface VersionDiff {
  rule_id: string;
  from_version: number;
  to_version: number | "current";
  diff: string;
  has_changes: boolean;
}

// --- Telemetry Gaps ---

export interface TelemetryGapRule {
  rule_id: string;
  rule_title: string;
  rule_type: string;
  severity: string | null;
  is_draft: boolean;
  required_sources: string[];
  missing_sources: string[];
  coverage_pct: number;
}

export interface TelemetryGapsResponse {
  rules_with_gaps: TelemetryGapRule[];
  total_rules_checked: number;
  rules_with_gaps_count: number;
  most_needed_sources: Array<[string, number]>;
}

// --- Entity Maintenance Log ---

export interface MergePairView {
  target_id: string;
  source_id: string;
  target_name: string | null;
  source_name: string | null;
  reasoning: string | null;
  new_description: string | null;
  extra_aliases: string[] | null;
}

export interface ReclassifyPairView {
  source_type: string;
  source_id: string;
  target_type: string;
  target_id: string | null;
  source_name: string | null;
  target_name: string | null;
  reasoning: string | null;
  new_description: string | null;
}

export interface ClusterMember {
  entity_type: string;
  entity_id: string;
  name: string | null;
}

export interface EntityMaintenanceLogRow {
  id: string;
  created_at: string;
  entity_type: string;
  entity_id: string | null;
  action: string;
  mode: "shadow" | "apply";
  applied: boolean;
  reasoning: string | null;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  ai_result_id: string | null;
  merges_view: MergePairView[] | null;
  reclassifies_view: ReclassifyPairView[] | null;
  cluster_names: string[] | null;
  cluster_members: ClusterMember[] | null;
  subject: string | null;
}

// --- Story threads ---------------------------------------------------------

export interface ThreadEntity {
  entity_type: string;
  entity_id: string;
  label: string;
  count: number;
}

export interface ThreadBeat {
  id: string;
  position: number;
  occurred_at: string | null;
  /** first_disclosure | new_tradecraft | peak | update */
  kind: string;
  headline: string;
  body: string | null;
  lead_entry_id: string | null;
  entry_ids: string[];
  collapsed_count: number;
  /** False when the spine came from day-grouping rather than a model. */
  is_ai: boolean;
}

export interface ThreadMember {
  entry_id: string;
  title: string;
  url: string | null;
  published_at: string | null;
  priority_score: number | null;
  feed_title: string;
  source: string | null;
  /** origin | beat | echo */
  role: string;
  similarity: number;
  duplicate_of_entry_id: string | null;
  is_read: boolean;
}

export interface ThreadYield {
  techniques: number;
  cves: number;
  products: number;
  rules: number;
  echoes_folded: number;
}

export interface NearestThread {
  slug: string;
  title: string;
  status: string;
  entry_count: number;
  similarity: number;
}

export interface StoryThread {
  id: string;
  slug: string;
  title: string;
  summary: string | null;
  status: string;
  entry_count: number;
  source_count: number;
  echo_count: number;
  first_seen: string | null;
  last_seen: string | null;
  peak_at: string | null;
  key_entities: ThreadEntity[];
  unread_count: number;
  new_since_opened: number;
  /** Priority score of the best unread non-echo member — the row's rank. */
  top_score: number | null;
  top_entry_id: string | null;
  entry_ids: string[];
  narrated_at: string | null;
}

/**
 * One row of the Priority Queue: a single entry, or a story thread standing in
 * for the articles it folded. Ordered and scored by the server so the reader,
 * the CLI and an agent all see the same queue.
 */
export interface PriorityQueueRow {
  kind: "entry" | "thread";
  score: number;
  entry: Entry | null;
  thread: StoryThread | null;
  /** Thread rows: members kept out of the queue as standalone entries. */
  absorbed_entry_ids: string[];
}

export interface PriorityQueueResponse {
  items: PriorityQueueRow[];
  next_cursor: string | null;
  has_more: boolean;
  /** Score an entry must clear to enter the queue; null when not surfacing. */
  radar_threshold: number | null;
}

export interface StoryThreadDetail extends StoryThread {
  beats: ThreadBeat[];
  members: ThreadMember[];
  thread_yield: ThreadYield;
  nearest: NearestThread[];
}

export interface ThreadListResponse {
  threads: StoryThread[];
  total: number;
}

export type CampaignSourceKind = "entity" | "story" | "query";

/**
 * Standing intake owned by the campaign: an entity it names, a story it holds
 * part of, or a query typed into it. A `query` source has no `ref_id` — unlike
 * a linked saved search it belongs to the campaign, not to one analyst.
 */
export interface CampaignSource {
  id: string;
  campaign_id: string;
  kind: CampaignSourceKind;
  entity_type: string | null;
  ref_id: string | null;
  /** The query-language string, when kind is "query". */
  query: string | null;
  /** The target's name at link time — stays readable if it is later renamed. */
  label: string;
  auto_sync: boolean;
  last_synced_at: string | null;
  entries_added: number;
  created_at: string;
}

export interface CampaignSourceSuggestion {
  kind: "entity" | "story";
  entity_type: string | null;
  ref_id: string;
  label: string;
  /** Why this is offered — "named as primary", "you hold 3 of 27 articles". */
  why: string;
  /** Articles following it would pull in right now. */
  would_add: number;
  /** The newest few of those, by name — what makes the click informed. */
  preview: Array<{ entry_id: string; title: string; published_at: string | null }>;
}

/** A dry run of a source that does not exist yet. */
export interface CampaignSourcePreview {
  kind: CampaignSourceKind;
  entity_type: string | null;
  ref_id: string | null;
  query: string | null;
  /** What the source would be called once created. */
  label: string;
  would_add: number;
  /** Articles it claims that the campaign already has — overlap, not waste. */
  already_held: number;
  preview: Array<{ entry_id: string; title: string | null; published_at: string | null }>;
  /** Why the query could not be run, when it could not be parsed. */
  error: string | null;
  /**
   * Field names the query language does not have. Not fatal — they become text
   * terms — but a standing source built on a typo'd field answers plausibly
   * forever, so the composer says so before the follow is created.
   */
  unknown_fields: string[];
}

/** What the intake pickers are allowed to offer, straight from the server. */
export interface CampaignSourceOptions {
  kinds: CampaignSourceKind[];
  /** Types that own articles; a source on anything else would never add any. */
  followable_entity_types: string[];
  /** Followable *and* findable by name through /intelligence/search. */
  pickable_entity_types: string[];
}

// --- Intel profiles (named report scopes: regions × verticals) ---

export interface IntelProfile {
  id: string;
  name: string;
  description: string | null;
  country_ids: string[];
  countries: { id: string; name: string }[];
  sectors: string[];
  sector_labels: string[];
  window_days: number;
  curation: {
    kept?: { actors?: string[]; malware?: string[] };
    dropped?: { actors?: string[]; malware?: string[] };
  };
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface IntelProfileCreate {
  name: string;
  description?: string;
  country_ids?: string[];
  sectors?: string[];
  window_days?: number;
}

export interface ThreatSurfaceItem {
  id: string;
  entity_type: "threat_actor" | "malware";
  name: string;
  aliases: string[];
  subtype: string | null;
  matched_regions: string[];
  matched_sectors: string[];
  region_sources: string[];
  sector_sources: string[];
  victim_count: number;
  entry_count: number;
  latest_entry: { id: string; title: string; published_at: string | null } | null;
  region_hit: boolean;
  sector_hit: boolean;
  partial: boolean;
  score: number;
}

export interface ThreatSurface {
  actors: ThreatSurfaceItem[];
  malware: ThreatSurfaceItem[];
  window_days: number;
  cutoff: string;
  profile_id?: string;
  curation?: IntelProfile["curation"];
}

export interface ExposureGenerateRequest {
  profile_id: string;
  title?: string;
  tlp_marking?: string;
  actor_ids: string[];
  malware_ids: string[];
  dropped_actor_ids?: string[];
  dropped_malware_ids?: string[];
  tags?: string[];
}

/** A curated starter feed pack shipped with the build (GET /opml/starter-packs). */
export interface StarterPack {
  id: string;
  title: string;
  description: string;
  feed_count: number;
  recommended: boolean;
  /** Human-readable prerequisite (an API token, say) this pack needs to work. */
  requires: string | null;
}

export interface StarterPackImportResult {
  feeds_added: number;
  feeds_skipped: number;
  categories_created: number;
  errors: string[];
  packs: { id: string; title: string; feeds_added: number }[];
}

/** Instance readiness for the onboarding wizard (GET /onboarding/status). */
export interface OnboardingStatus {
  reference_data: {
    ok: boolean;
    checks: { key: string; label: string; count: number; ok: boolean }[];
    missing: string[];
    /** The exact seeder command to run; server-supplied so the UI can't drift from it. */
    remedy: string;
    consequence: string;
  };
  feeds: { total: number; polled_ok: number; errored: number; never_polled: number };
  entries: { total: number; last_24h: number };
  autolink: { entity_links: number };
  ai: { providers: number; active: string | null; tasks_assigned: number };
  /** Seeded, polling and ingesting — the instance can demonstrate itself. */
  ready: boolean;
}

/** Outcome of POST /ai/providers/{id}/commission. */
export interface AIProviderCommissionResult {
  success: boolean;
  /** Straight from the provider, so a failure can name the real cause. */
  message: string;
  models: string[];
  /** The model the assignments were given, resolved against the live list. */
  model: string | null;
  tasks_assigned: number;
  tasks_reassigned: number;
  /** Agentic tasks left on the CLI because this provider can't run tools. */
  tasks_skipped_agentic: string[];
}
