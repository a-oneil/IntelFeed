import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";

export interface HygieneStats {
  /** Adjudicate stage: mode and the unapplied verdicts it has filed. */
  adjudication_mode: string;
  adjudication_pending: number;
  /** Set while the rolling circuit breaker has paused dispatch (ISO time it lifts). */
  adjudication_breaker_until: string | null;
  pending_advisories: number;
  /** Entities with a pending remove-link proposal, either log. */
  pending_unlink_entities: number;
  name_normalization_proposed: number;
  applied_24h: number;
  applied_7d: number;
  orphan_count: number;
  last_maintenance_run_at: string | null;
  alias_collisions_proposed: number;
  vendor_autolinks_proposed: number;
  ttp_cve_issues_proposed: number;
  /** Every pending proposal across both logs, and the split by what applying it changes. */
  pending_total: number;
  pending_by_domain: Partial<Record<ProposalDomain, number>>;
}

export interface AliasScanResult {
  scanned_entities: number;
  proposed: number;
  by_kind: Record<string, number>;
  by_type: Record<string, number>;
}

export interface VendorAutolinkScanResult {
  products_scanned: number;
  proposed: number;
  by_match_kind: Record<string, number>;
}

export interface IdHygieneScanResult {
  ttps_scanned: number;
  cves_scanned: number;
  ttp_malformed: number;
  cve_malformed: number;
  cve_withdrawn: number;
}

export interface ApplyAliasCollisionResult {
  log_id: string;
  applied: boolean;
  skipped: boolean;
  entity_id: string | null;
  removed_alias: string | null;
}

export interface ApplyVendorAutolinkResult {
  log_id: string;
  applied: boolean;
  skipped: boolean;
  product_id: string | null;
  vendor_id: string | null;
}

export interface ApplyIdHygieneResult {
  log_id: string;
  applied: boolean;
  skipped: boolean;
  action_taken: "renamed" | "deleted" | "skipped" | null;
  entity_id: string | null;
  new_id: string | null;
}

export interface EnrichGapResult {
  entity_type: string;
  field: string;
  enqueued: number;
  total_missing: number;
  supported: boolean;
  async_mode: boolean;
  batch_size: number;
  message: string | null;
}

export interface NameNormalizationRunResult {
  mode: string;
  scanned: number;
  proposed: number;
  by_type: Record<string, number>;
  by_kind: Record<string, number>;
  dispatched_batches: number;
  batch_size: number;
  async_mode: boolean;
}

export interface ApplyNormalizeNameResult {
  log_id: string;
  applied: boolean;
  skipped: boolean;
  kind: string | null;
  entity_id: string | null;
  merge_target_id: string | null;
  new_name: string | null;
}

export interface FeedLink {
  kind: "entity" | "entry" | "external";
  entity_type: string | null;
  entity_id: string | null;
  label: string;
  role: string | null;
}

export interface FeedRow {
  id: string;
  source: "link_validator" | "entity_maintenance";
  action: string;
  when: string;
  mode: "shadow" | "apply" | null;
  applied: boolean | null;
  entity_type: string | null;
  entity_id: string | null;
  entity_name: string | null;
  subject: string | null;
  reason: string | null;
  payload: Record<string, unknown>;
  actions: string[];
  links: FeedLink[];
  /** Who proposed it: the post-analysis adjudicate stage (article in hand; every
   *  link-log row), the catalogue-wide duplicate review (two profiles side by side), or a scan. */
  origin: ProposalOrigin | null;
  /** What applying it changes (the Review tab's Domain facet). */
  domain: ProposalDomain;
  /** The article text around the match (bounded), when the row has an article. */
  context?: string | null;
  /** The verdict's confidence, where the stage gave one. */
  confidence?: Confidence | null;
}

export type ProposalOrigin = "adjudicator" | "merge_review" | "scan";

/** Observables are an entity type, so dropping one is an "entities" proposal. */
export type ProposalDomain = "links" | "entities" | "relationships";
export const PROPOSAL_DOMAINS: ProposalDomain[] = ["links", "entities", "relationships"];

export interface FeedResponse {
  rows: FeedRow[];
  has_more: boolean;
  next_offset: number;
}

export interface FeedFilters {
  action?: string;
  source?: "link_validator" | "entity_maintenance";
  /** Spans both logs; a link-log reclassify advisory counts as "entities". */
  domain?: ProposalDomain;
  mode?: "shadow" | "apply";
  /** Only unapplied proposals (review-queue mode) — skips applied history. */
  pending?: boolean;
  origin?: ProposalOrigin;
  /** Pending scan proposals no entry can carry to the adjudicate stage —
   *  listed for manual disposition; nothing automatic touches them. */
  orphaned?: boolean;
  /** One entity's rows (the Review queue's expand). */
  entity_type?: string;
  entity_id?: string;
  limit?: number;
  offset?: number;
}

export interface PruneOrphansResult {
  mode: string;
  pruned: number;
  skipped: number;
  by_type: Record<string, number>;
  log_ids: string[];
}

export interface CascadePreview {
  entity_type: string;
  entity_id: string;
  entity_name: string;
  entry_links: number;
  campaign_links: number;
  detection_rules: number;
  relationships: number;
  notes: number;
}

const HYGIENE_KEYS = ["hygiene"] as const;

export function useHygieneStats() {
  return useQuery({
    queryKey: [...HYGIENE_KEYS, "stats"],
    queryFn: async () => {
      const { data } = await api.get<HygieneStats>("/admin/hygiene/stats");
      return data;
    },
    staleTime: 30 * 1000,
  });
}

export function useHygieneFeed(filters: FeedFilters, opts: { enabled?: boolean } = {}) {
  return useQuery({
    enabled: opts.enabled ?? true,
    queryKey: [...HYGIENE_KEYS, "feed", filters],
    queryFn: async () => {
      const params: Record<string, string | number> = {
        limit: filters.limit ?? 50,
        offset: filters.offset ?? 0,
      };
      if (filters.action) params.action = filters.action;
      if (filters.source) params.source = filters.source;
      if (filters.domain) params.domain = filters.domain;
      if (filters.mode) params.mode = filters.mode;
      if (filters.pending) params.pending = "true";
      if (filters.origin) params.origin = filters.origin;
      if (filters.orphaned) params.orphaned = "true";
      if (filters.entity_type) params.entity_type = filters.entity_type;
      if (filters.entity_id) params.entity_id = filters.entity_id;
      // one entity's rows: small enough to carry the article snippet
      if (filters.entity_id) params.context = "true";
      const { data } = await api.get<FeedResponse>("/admin/hygiene/feed", { params });
      return data;
    },
    staleTime: 15 * 1000,
  });
}

export function usePruneOrphans() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      targets?: Array<{ entity_type: string; entity_id: string }>;
      entity_type?: string;
      mode?: "shadow" | "apply";
      max_prune?: number;
    }) => {
      const { data } = await api.post<PruneOrphansResult>(
        "/admin/hygiene/orphans/prune",
        body,
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
    },
  });
}

export interface ReclassifyGroupsActionResult {
  entities: number;
  cleared_rows: number;
  failed: number;
  errors: { entity_id: string; error: string }[];
}

type ReclassifyItem = { entity_type: string; entity_id: string; target_type?: string };

/** Convert each entity to its target type and clear every proposal about it. */
export function useApplyReclassifyGroups() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (items: ReclassifyItem[]) => {
      const { data } = await api.post<ReclassifyGroupsActionResult>("/admin/hygiene/reclassify-groups/apply", {
        items,
      });
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
      qc.invalidateQueries({ queryKey: ["extraction"] });
      qc.invalidateQueries({ queryKey: ["entity-links"] });
    },
  });
}

/** One row of the Review queue: every pending proposal about one entity,
 *  from both logs, with what each kind wants done. A row about something
 *  that is not a catalogue entity (an edge, an article's assessment) has
 *  entity_id null and carries its own row_ids. */
export interface ReviewGroup {
  key: string;
  entity_type: string;
  entity_id: string | null;
  name: string;
  linked: number | null;
  proposals: number;
  kinds: { action: string; count: number }[];
  reclassify_to: { type: string; count: number }[];
  merge_into: { target_type: string; target_id: string; name: string | null; count: number }[];
  domains: ProposalDomain[];
  origin: ProposalOrigin | "mixed";
  /** The highest verdict confidence among its proposals, where one was given. */
  confidence: Confidence | null;
  subject: string | null;
  reason: string | null;
  links: FeedLink[];
  latest_at: string;
  sample_entry_id: string | null;
  matched_names: string[];
  row_ids: string[];
}

export type Confidence = "high" | "medium" | "low";

/** The Review tab's filters: which pending proposals a list or an action covers. */
export interface ReviewScope {
  q?: string;
  entity_type?: string;
  action?: string;
  domain?: ProposalDomain;
  origin?: ProposalOrigin;
}

export type ReviewSort = "newest" | "count" | "oldest" | "confidence";

interface ReviewGroupsResponse {
  groups: ReviewGroup[];
  total: number;
  proposals: number;
  /** Proposals per domain under every other filter, and per origin likewise. */
  facets: { domains: Partial<Record<ProposalDomain, number>>; origins: Partial<Record<ProposalOrigin, number>> };
}

export function useReviewGroups(params: ReviewScope & { sort?: ReviewSort; limit?: number; offset?: number }) {
  return useQuery({
    queryKey: [...HYGIENE_KEYS, "review-groups", params],
    queryFn: async () => {
      const { data } = await api.get<ReviewGroupsResponse>("/admin/hygiene/review-groups", { params });
      return data;
    },
    placeholderData: keepPreviousData,
    staleTime: 15 * 1000,
  });
}

type ReviewGroupRef = { entity_type: string; entity_id: string | null; row_ids?: string[] };

/** Everything applying or dismissing a proposal can change on screen. */
export function invalidateAfterReview(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
  qc.invalidateQueries({ queryKey: ["engine"] });
  qc.invalidateQueries({ queryKey: ["entity-links"] });
  qc.invalidateQueries({ queryKey: ["relationships"] });
  qc.invalidateQueries({ queryKey: ["extraction"] });
}

/** Dismiss what the filters show: the named groups, or with no `items`
 *  every proposal the filters select (Dismiss all). Each dismissal sticks:
 *  a type change for the entity, a duplicate pair as two things, an
 *  adjudicator verdict for its article. */
export function useDismissReview() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: ReviewScope & { items?: ReviewGroupRef[] }) => {
      const { data } = await api.post<{ cleared_rows: number }>("/admin/hygiene/review-groups/dismiss", body);
      return data;
    },
    onSuccess: () => invalidateAfterReview(qc),
  });
}

interface ReviewApplyResult {
  applied: number;
  skipped: number;
  failed: number;
  errors: { id: string; error: string }[];
}

interface ReviewApplyBatch extends ReviewApplyResult {
  has_more: boolean;
  unapplied: string[];
}

/** Apply what the filters show for the named groups, in server batches,
 *  until every row has been tried once: rows a batch leaves pending (failed,
 *  or nothing to do) go back as `exclude`, so the next batch moves on. Type
 *  changes are left to the chips; assessments are never applied. */
export function useApplyReview() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: ReviewScope & { items: ReviewGroupRef[] }) => {
      const total: ReviewApplyResult = { applied: 0, skipped: 0, failed: 0, errors: [] };
      const exclude: string[] = [];
      for (;;) {
        const { data } = await api.post<ReviewApplyBatch>("/admin/hygiene/review-groups/apply", { ...body, exclude: [...exclude] });
        total.applied += data.applied;
        total.skipped += data.skipped;
        total.failed += data.failed;
        total.errors.push(...data.errors);
        exclude.push(...data.unapplied);
        if (!data.has_more || exclude.length > 5000) return total;
      }
    },
    onSuccess: () => invalidateAfterReview(qc),
  });
}

/** Run the duplicate review now: likely-duplicate pairs go to the model on
 *  the AI worker and come back as Merge proposals. Only dispatches; a run
 *  already in progress is reported, not doubled. */
export function useScanDuplicates() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const { data } = await api.post<{ dispatched: boolean; already_running: boolean }>("/admin/hygiene/scan-duplicates");
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
    },
  });
}

export function useDismissFeedRow() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ source, id }: { source: string; id: string }) => {
      await api.delete(`/admin/hygiene/feed/${source}/${id}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
    },
  });
}

/** A background "Apply all" over what the filters show (see useStartBulkApply). */
export interface BulkApplyProgress {
  job_id: string;
  scope: Record<string, unknown>;
  status: "queued" | "running" | "done" | "error";
  /** Rows in scope when the job was queued. */
  total: number;
  processed: number;
  applied: number;
  skipped: number;
  errors: Array<Record<string, string>>;
  error_count: number;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  message: string | null;
}

export type BulkApplyRequest = ReviewScope & { limit?: number };

const BULK_APPLY_KEY = ["hygiene", "bulk-apply"] as const;

/**
 * Queue a background Apply all. The whole backlog (thousands of rows on a
 * busy instance) used to go through one request, which the client gave up
 * on at 15 s while the server kept applying. Poll the returned job with
 * useBulkApplyProgress.
 */
export function useStartBulkApply() {
  return useMutation({
    mutationFn: async (body: BulkApplyRequest) => {
      const { data } = await api.post<BulkApplyProgress>("/admin/hygiene/bulk-apply", body);
      return data;
    },
  });
}

/** Progress of a background Apply all; polls every 1.5 s until it finishes. */
export function useBulkApplyProgress(jobId: string | null) {
  return useQuery({
    queryKey: [...BULK_APPLY_KEY, jobId],
    enabled: !!jobId,
    queryFn: async () => {
      const { data } = await api.get<BulkApplyProgress>(`/admin/hygiene/bulk-apply/${jobId}`);
      return data;
    },
    refetchInterval: (q) => {
      const st = q.state.data?.status;
      return st === "done" || st === "error" ? false : 1500;
    },
    staleTime: 0,
  });
}

export function useRunNameNormalization() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      mode?: "shadow" | "apply";
      entity_type?: string;
      max_proposals?: number;
    }) => {
      const { data } = await api.post<NameNormalizationRunResult>(
        "/admin/hygiene/run-name-normalization",
        body,
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
    },
  });
}

export function useEnrichGap() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: { entity_type: string; field: string; limit?: number }) => {
      const { data } = await api.post<EnrichGapResult>(
        "/admin/hygiene/enrichment-gaps/enrich",
        body,
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
    },
  });
}

export function useApplyNormalizeName() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (logId: string) => {
      const { data } = await api.post<ApplyNormalizeNameResult>(
        `/admin/hygiene/normalize-name/${logId}/apply`,
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
    },
  });
}

export function useScanAliasHygiene() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const { data } = await api.post<AliasScanResult>(
        "/admin/hygiene/scan-alias-hygiene",
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
    },
  });
}

export function useScanVendorAutolink() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const { data } = await api.post<VendorAutolinkScanResult>(
        "/admin/hygiene/scan-vendor-autolink",
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
    },
  });
}

export function useScanIdHygiene() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const { data } = await api.post<IdHygieneScanResult>(
        "/admin/hygiene/scan-id-hygiene",
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
    },
  });
}

export function useApplyAliasCollision() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (logId: string) => {
      const { data } = await api.post<ApplyAliasCollisionResult>(
        `/admin/hygiene/alias-collision/${logId}/apply`,
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
    },
  });
}

export function useApplyVendorAutolink() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (logId: string) => {
      const { data } = await api.post<ApplyVendorAutolinkResult>(
        `/admin/hygiene/vendor-autolink/${logId}/apply`,
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
    },
  });
}

export function useApplyIdHygiene() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (logId: string) => {
      const { data } = await api.post<ApplyIdHygieneResult>(
        `/admin/hygiene/id-hygiene/${logId}/apply`,
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
    },
  });
}

export function useCascadePreview(entityType: string | null, entityId: string | null) {
  return useQuery({
    queryKey: [...HYGIENE_KEYS, "cascade-preview", entityType, entityId],
    queryFn: async () => {
      if (!entityType || !entityId) return null;
      const { data } = await api.get<CascadePreview>(
        `/entities/${entityType}/${entityId}/cascade-preview`,
      );
      return data;
    },
    enabled: Boolean(entityType && entityId),
  });
}
