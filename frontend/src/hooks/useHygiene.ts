import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";

export interface HygieneStats {
  link_validator_mode: string;
  entity_maintenance_mode: string;
  pending_advisories: number;
  shadow_proposals: number;
  name_normalization_proposed: number;
  applied_24h: number;
  applied_7d: number;
  orphan_count: number;
  last_validator_run_at: string | null;
  last_maintenance_run_at: string | null;
  link_validator_pending: number;
  link_validator_validated_24h: number;
  alias_collisions_proposed: number;
  vendor_autolinks_proposed: number;
  ttp_cve_issues_proposed: number;
  ai_review_approved: number;
  ai_review_rejected: number;
  ai_review_unsure: number;
  ai_review_unreviewed: number;
  /** Adjudicate stage: mode and the unapplied verdicts it has filed. */
  adjudication_mode?: string;
  adjudication_pending?: number;
}

export type ReviewDecision = "approve" | "reject" | "unsure";

export interface AiReviewKickoffResult {
  pending_unreviewed: number;
  dispatched: boolean;
}

export interface ApplyAiApprovedResult {
  applied: number;
  skipped: number;
  failed: number;
  dismissed_rejected: number;
  errors: Array<Record<string, string>>;
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
  review_decision: ReviewDecision | null;
  review_reason: string | null;
  /** Who proposed it: the post-analysis adjudicate stage, or the legacy jobs/scans. */
  origin: "adjudicator" | "legacy" | null;
}

export interface FeedResponse {
  rows: FeedRow[];
  has_more: boolean;
  next_offset: number;
}

export interface FeedFilters {
  action?: string;
  source?: "link_validator" | "entity_maintenance";
  mode?: "shadow" | "apply";
  review?: ReviewDecision | "unreviewed";
  /** Only unapplied proposals (review-queue mode) — skips applied history. */
  pending?: boolean;
  origin?: "adjudicator" | "legacy";
  limit?: number;
  offset?: number;
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

export interface GapBucket {
  entity_type: string;
  field: string;
  missing: number;
  sample: Array<{ id: string; name: string; article_count: number | null }>;
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

export function useHygieneFeed(filters: FeedFilters) {
  return useQuery({
    queryKey: [...HYGIENE_KEYS, "feed", filters],
    queryFn: async () => {
      const params: Record<string, string | number> = {
        limit: filters.limit ?? 50,
        offset: filters.offset ?? 0,
      };
      if (filters.action) params.action = filters.action;
      if (filters.source) params.source = filters.source;
      if (filters.mode) params.mode = filters.mode;
      if (filters.review) params.review = filters.review;
      if (filters.pending) params.pending = "true";
      if (filters.origin) params.origin = filters.origin;
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

export function useEnrichmentGaps() {
  return useQuery({
    queryKey: [...HYGIENE_KEYS, "enrichment-gaps"],
    queryFn: async () => {
      const { data } = await api.get<{ buckets: GapBucket[] }>(
        "/admin/hygiene/enrichment-gaps",
      );
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
      exclude_rejected?: boolean;
    }) => {
      const { data } = await api.post<ApplyAdvisoriesResult>(
        "/admin/hygiene/apply-reclassify-advisories",
        body,
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
      qc.invalidateQueries({ queryKey: ["entity-maintenance-log"] });
    },
  });
}

export function useKickoffAiReview() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const { data } = await api.post<AiReviewKickoffResult>("/admin/hygiene/ai-review");
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
    },
  });
}

export function useApplyAiApproved() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: { dismiss_rejected?: boolean }) => {
      const { data } = await api.post<ApplyAiApprovedResult>(
        "/admin/hygiene/apply-ai-approved",
        body,
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
      qc.invalidateQueries({ queryKey: ["entity-maintenance-log"] });
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
 *  action / source / review, or pass {} to clear the whole pending queue. */
export function useDismissProposals() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: { action?: string; source?: string; review?: string }) => {
      const { data } = await api.post<{ dismissed: number }>("/admin/hygiene/dismiss-proposals", body);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: HYGIENE_KEYS });
    },
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
      qc.invalidateQueries({ queryKey: ["entity-maintenance-log"] });
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
      qc.invalidateQueries({ queryKey: ["entity-maintenance-log"] });
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
