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
  /** Who proposed it: the post-analysis adjudicate stage (article in hand), the
   *  catalogue-wide duplicate review (two profiles side by side), or a scan / an analyst. */
  origin: ProposalOrigin | null;
  /** What applying it changes (the Review tab's Domain facet). */
  domain: ProposalDomain;
  /** The article text around the match (bounded), when the row has an article. */
  context?: string | null;
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

export interface ApplyAdjudicationAllResult {
  applied: number;
  skipped: number;
  errors: Array<{ log_id: string; action: string; error: string }>;
}

export interface OrphanRow {
  entity_type: string;
  entity_id: string;
  name: string;
  article_count: number;
  first_seen_at: string | null;
  last_seen_at: string | null;
}

export interface OrphanListResponse {
  total: number;
  items: OrphanRow[];
  by_type: Record<string, number>;
}

export interface ApplyAdvisoriesResult {
  mode: string;
  advisories_considered: number;
  distinct_sources: number;
  applied: number;
  skipped: number;
  failed: number;
  cleared_advisory_rows: number;
  errors: Array<Record<string, string>>;
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

export function useOrphans(entityType?: string) {
  return useQuery({
    queryKey: [...HYGIENE_KEYS, "orphans", entityType ?? "all"],
    queryFn: async () => {
      const { data } = await api.get<OrphanListResponse>("/admin/hygiene/orphans", {
        params: entityType ? { entity_type: entityType } : undefined,
      });
      return data;
    },
    staleTime: 60 * 1000,
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

export function useApplyAdvisories() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      limit?: number;
      entity_type?: string;
      mode?: "shadow" | "apply";
    }) => {
      const { data } = await api.post<ApplyAdvisoriesResult>(
        "/admin/hygiene/apply-reclassify-advisories",
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

function useReclassifyGroupsAction(action: "apply" | "dismiss") {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (items: ReclassifyItem[]) => {
      const { data } = await api.post<ReclassifyGroupsActionResult>(`/admin/hygiene/reclassify-groups/${action}`, {
        items,
      });
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
      if (action === "apply") {
        qc.invalidateQueries({ queryKey: ["extraction"] });
        qc.invalidateQueries({ queryKey: ["entity-links"] });
      }
    },
  });
}

/** Convert each entity to its target type and clear every proposal about it. */
export const useApplyReclassifyGroups = () => useReclassifyGroupsAction("apply");
/** Clear every proposal about each entity and stop new ones being filed. */
export const useDismissReclassifyGroups = () => useReclassifyGroupsAction("dismiss");

export interface UnlinkActionResult {
  done: number;
  failed: number;
  remaining: number;
  errors: { id: string; error: string }[];
}

type UnlinkTarget = { items?: { entity_type: string; entity_id: string }[]; row_ids?: string[] };

/** Remove the links (apply) or keep them (clear the proposals). Apply runs in
 *  server batches; this repeats until the groups are drained or a batch stalls. */
export function useUnlinkAction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ action, target }: { action: "apply" | "keep"; target: UnlinkTarget }) => {
      const total: UnlinkActionResult = { done: 0, failed: 0, remaining: 0, errors: [] };
      for (;;) {
        const { data } = await api.post<UnlinkActionResult>(`/admin/hygiene/unlink-groups/${action}`, target);
        total.done += data.done;
        total.failed += data.failed;
        total.remaining = data.remaining;
        total.errors.push(...data.errors);
        if (action === "keep" || data.remaining === 0 || data.done === 0) return total;
      }
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
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
  exists: boolean;
  linked: number | null;
  proposals: number;
  kinds: { action: string; count: number }[];
  reclassify_to: { type: string; count: number }[];
  merge_into: { target_type: string; target_id: string; name: string | null; count: number }[];
  domains: ProposalDomain[];
  origin: ProposalOrigin | "mixed";
  subject: string | null;
  reason: string | null;
  links: FeedLink[];
  latest_at: string;
  sample_entry_id: string | null;
  matched_names: string[];
  row_ids: string[];
}

export interface ReviewGroupsFilters {
  q?: string;
  entity_type?: string;
  action?: string;
  domain?: ProposalDomain;
  origin?: ProposalOrigin;
  limit?: number;
  offset?: number;
}

export function useReviewGroups(params: ReviewGroupsFilters) {
  return useQuery({
    queryKey: [...HYGIENE_KEYS, "review-groups", params],
    queryFn: async () => {
      const { data } = await api.get<{ groups: ReviewGroup[]; total: number; proposals: number }>(
        "/admin/hygiene/review-groups",
        { params },
      );
      return data;
    },
    placeholderData: keepPreviousData,
    staleTime: 15 * 1000,
  });
}

export type ReviewGroupRef = { entity_type: string; entity_id: string | null; row_ids?: string[] };

/** Settle rows the "leave it alone" way: keep links and type (and stop
 *  proposing the change), remember a duplicate-review pair as two things,
 *  drop every other pending proposal about the entity. */
export function useDismissReviewGroups() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (items: ReviewGroupRef[]) => {
      const { data } = await api.post<{ entities: number; cleared_rows: number }>("/admin/hygiene/review-groups/dismiss", {
        items,
      });
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
    },
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

/** Bulk-discard pending proposals without applying them. Scope with
 *  action / source / origin, or pass {} to clear the whole pending queue. */
export function useDismissProposals() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      action?: string;
      source?: string;
      origin?: ProposalOrigin;
      domain?: ProposalDomain;
    }) => {
      const { data } = await api.post<{ dismissed: number }>("/admin/hygiene/dismiss-proposals", body);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
    },
  });
}

/** Apply every pending adjudicator proposal (both logs) through the stage's
 *  own apply path. `action` narrows to one `adjudication_*` code or `shadow_remove`. */
export function useApplyAdjudicationAll() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: { action?: string; limit?: number }) => {
      const { data } = await api.post<ApplyAdjudicationAllResult>("/admin/hygiene/adjudication/apply-all", body);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
      qc.invalidateQueries({ queryKey: ["engine"] });
      qc.invalidateQueries({ queryKey: ["entity-links"] });
      qc.invalidateQueries({ queryKey: ["relationships"] });
      qc.invalidateQueries({ queryKey: ["extraction"] });
    },
  });
}

/** A background "Apply all" over one proposals queue (see useStartBulkApply). */
export interface BulkApplyProgress {
  job_id: string;
  kind: "adjudication" | "advisories" | "all";
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

export interface BulkApplyRequest {
  /** "all" is the Review tab's one button: the adjudicator's queue, then the reclassify advisories. */
  kind: "adjudication" | "advisories" | "all";
  /** adjudication_* codes, shadow_remove and/or needs_reclassification, comma-separated; omit for all. */
  action?: string;
  domain?: ProposalDomain;
  /** advisories only. */
  entity_type?: string;
  mode?: "shadow" | "apply";
  limit?: number;
}

export const BULK_APPLY_KEY = ["hygiene", "bulk-apply"] as const;

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

/** Everything a bulk apply can change on screen. */
export function invalidateAfterBulkApply(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
  qc.invalidateQueries({ queryKey: ["engine"] });
  qc.invalidateQueries({ queryKey: ["entity-links"] });
  qc.invalidateQueries({ queryKey: ["relationships"] });
  qc.invalidateQueries({ queryKey: ["extraction"] });
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
