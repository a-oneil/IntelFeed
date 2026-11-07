import { keepPreviousData, useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import api from "@/api/client";
import { CONSOLE_KEY as ENRICHMENT_CONSOLE_KEY } from "@/hooks/useEnrichment";

export interface SignalStat {
  signal_type: string;
  family: string;
  firing_rate: number | null;
  effective_weight: number;
}

export interface EngineJobRun {
  status: string;
  finished_at: string | null;
}

export interface SignalEngineHealth {
  shadow_enabled: boolean;
  surface_enabled: boolean;
  unscored_recent: number;
  feedback_min_samples: number;
  feedback_counts: Record<string, number>;
  feedback_nudges: Record<string, number>;
  last_rate_recompute: EngineJobRun | null;
  last_rescore: EngineJobRun | null;
}

export interface SignalStats {
  health: SignalEngineHealth;
  signals: SignalStat[];
  family_multipliers: Record<string, number>;
  default_family_multipliers: Record<string, number>;
  threshold: number;
  threshold_is_auto: boolean;
}

export interface WhatsNewSubject {
  type: string;
  name: string;
  id: string | null;
}

export interface WhatsNewItem {
  entry_id: string;
  entry_title: string;
  published_at: string | null;
  signal_type: string;
  explanation: string;
  subject: WhatsNewSubject | null;
}

export function useSignalStats() {
  return useQuery({
    queryKey: ["engine", "signal-stats"],
    queryFn: async () => {
      const res = await api.get<SignalStats>("/engine/signals/stats");
      return res.data;
    },
    staleTime: 60_000,
  });
}

export function useUpdateSignalSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      family_multipliers?: Record<string, number>;
      threshold_override?: number | null;
      clear_threshold_override?: boolean;
    }) => {
      const res = await api.put("/engine/signals/settings", body);
      return res.data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["engine", "signal-stats"] });
      qc.invalidateQueries({ queryKey: ["triage"] });
      qc.invalidateQueries({ queryKey: ["entries"] });
    },
  });
}

export function useEntityWhatsNew(entityType: string, entityId: string, enabled = true, scoped = false) {
  return useQuery({
    queryKey: ["engine", "whats-new", entityType, entityId, scoped],
    queryFn: async () => {
      const res = await api.get<{ items: WhatsNewItem[] }>(
        `/engine/entities/${entityType}/${entityId}/whats-new`,
        { params: scoped ? { scoped: true } : undefined },
      );
      return res.data.items;
    },
    enabled,
    staleTime: 120_000,
  });
}

export interface PipelineStageInfo {
  name: string;
  kind: string;
  description: string;
  default_enabled: boolean;
  config_schema: Record<string, unknown>;
  /** `queued` only on the synthetic analyze row: queue rows waiting on the AI worker.
   *  `new_error` / `new_retry` count only what came in after the check-engine
   *  light was last cleared (the same as `error` / `retry` when it never was). */
  runs_24h: {
    success: number;
    error: number;
    retry: number;
    new_error?: number;
    new_retry?: number;
    queued?: number;
  };
}

export interface PipelineOverview {
  health_cleared_at?: string | null;
  pipeline_engine_enabled: boolean;
  run_logging_enabled: boolean;
  stages: PipelineStageInfo[];
}

export interface PipelinePlanRow {
  id: string;
  name: string;
  scope_type: "global" | "category" | "feed";
  scope_id: string | null;
  stages: Record<string, { enabled?: boolean; config?: Record<string, unknown> }>;
  is_active: boolean;
}

export interface JobRunRow {
  id: string;
  job_key: string | null;
  task_name: string;
  status: string;
  finished_at: string | null;
  duration_ms: number | null;
  error: string | null;
  detail: {
    args?: unknown[];
    kwargs?: Record<string, unknown>;
    result?: unknown;
  } | null;
}

export interface ExtractionStatus {
  enabled: boolean;
  queue: Record<string, number>;
  spent_today_usd: number;
  daily_budget_usd: number;
  last_batch: {
    provider_batch_id: string;
    status: string;
    request_count: number;
    succeeded: number;
    errored: number;
    created_at: string | null;
  } | null;
}

export function usePipelineOverview({ enabled = true, poll }: { enabled?: boolean; poll?: number } = {}) {
  return useQuery({
    queryKey: ["engine", "pipeline"],
    queryFn: async () => (await api.get<PipelineOverview>("/engine/pipeline")).data,
    staleTime: 30_000,
    enabled,
    refetchInterval: poll,
  });
}

export interface RetryErrorsResult {
  dispatched: number;
  skipped: number;
  by_stage: Record<string, number>;
  remaining: number;
}

/** Re-dispatch every stage still stuck on an error (optionally one stage) for
 *  entries ingested in the window. Admin only. */
export function useRetryPipelineErrors() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: { stage?: string; window?: string; limit?: number }) =>
      (await api.post<RetryErrorsResult>("/engine/pipeline/retry-errors", body)).data,
    // The runs land asynchronously; give the workers a moment before refetching.
    onSuccess: () => setTimeout(() => qc.invalidateQueries({ queryKey: ["engine"] }), 3000),
  });
}

export function usePipelinePlans() {
  return useQuery({
    queryKey: ["engine", "plans"],
    queryFn: async () => (await api.get<{ plans: PipelinePlanRow[] }>("/engine/plans")).data.plans,
    staleTime: 30_000,
  });
}

export function useUpsertPlan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: Omit<PipelinePlanRow, "id"> & { id?: string }) => {
      const res = await api.put("/engine/plans", body);
      return res.data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["engine", "plans"] }),
  });
}

export function useDeletePlan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (planId: string) => {
      await api.delete(`/engine/plans/${planId}`);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["engine", "plans"] }),
  });
}

export interface StageRunRow {
  id: string;
  entry_id: string;
  entry_title: string | null;
  status: string;
  duration_ms: number | null;
  error: string | null;
  created_at: string | null;
  retryable: boolean;
}

export interface EntryAdjudicationVerdict {
  item_id: string;
  kind: "link" | "held" | "edge" | "ioc" | "assessment";
  entity_type: string | null;
  entity_id: string | null;
  /** The entity's name when the verdict recorded one (held matches). */
  name?: string | null;
  verdict: string;
  reason: string | null;
  suggested_type?: string | null;
  merge_into?: string | null;
  applied: boolean;
  /** An analyst already put this one back: neither Apply nor Restore applies. */
  restored: boolean;
  log: string;
  action: string;
}

export interface EntryAdjudication {
  status: string | null;
  adjudicated_at: string | null;
  run: {
    status: string;
    created_at: string | null;
    duration_ms: number | null;
    mode: string | null;
    detail: Record<string, unknown> | null;
  } | null;
  verdicts: EntryAdjudicationVerdict[];
}

/** What the adjudicate stage decided for one entry (drawer badges). */
export function useEntryAdjudication(entryId: string, enabled = true) {
  return useQuery({
    queryKey: ["engine", "adjudication", entryId],
    queryFn: async () => (await api.get<EntryAdjudication>(`/engine/entries/${entryId}/adjudication`)).data,
    enabled: enabled && !!entryId,
    staleTime: 15_000,
  });
}

export function useStageRuns(stage: string, status?: string) {
  return useQuery({
    queryKey: ["engine", "stage-runs", stage, status ?? "all"],
    queryFn: async () => {
      const params = status ? { status } : {};
      return (
        await api.get<{ runs: StageRunRow[] }>(`/engine/pipeline/stages/${stage}/runs`, { params })
      ).data.runs;
    },
    enabled: !!stage,
    staleTime: 30_000,
  });
}

export function useExtractionStatus() {
  return useQuery({
    queryKey: ["engine", "extraction-status"],
    queryFn: async () => (await api.get<ExtractionStatus>("/engine/extraction/status")).data,
    staleTime: 30_000,
  });
}

// ---- Engine → Processing (per-entry pipeline matrix) --------------------

export interface ProcessingStageCol {
  name: string;
  label: string;
}

export interface ProcessingStats {
  ingested: number;
  complete: number;
  errored: number;
  processing: number;
  by_stage_errors: Record<string, number>;
  median_latency_ms: number | null;
  p95_latency_ms: number | null;
  ingest_series: number[];
}

export interface ProcessingEntity {
  type: string;
  name: string;
}

export interface ProcessingStageCell {
  /** success / error / retry are real runs. queued and skipped are synthetic
   *  cells for a stage task that never ran (the adjudicate stage waiting on
   *  the AI worker, or gated off before dispatch). Every `analyze` cell is
   *  synthetic: the AI analysis writes no runs, its queue row is the state. */
  status: "success" | "error" | "retry" | "queued" | "skipped";
  duration_ms: number | null;
  error: string | null;
  retryable: boolean;
  created_at: string | null;
  /** Stage-specific run detail: the adjudicate stage's verdict counters and
   *  mode on a run, `{queued_at}` or `{waiting_on}` on a queued cell,
   *  `{skipped}` on a skip, `{reused_from}` on a copied analysis. */
  detail?: Record<string, unknown> | null;
}

/** Output-lens counts: what each stage produced for one entry. */
export interface ProcessingOutputs {
  links_auto: number;
  links_ai: number;
  links_other: number;
  entities_created: number;
  rels_cooc: number;
  rels_other: number;
  signals: number;
  observables?: number;
  observable_candidates?: number;
}

export interface ProcessingEntry {
  id: string;
  title: string;
  feed: string | null;
  category: string | null;
  created_at: string | null;
  radar_score: number | null;
  latency_ms: number | null;
  status: "complete" | "errored" | "in_flight";
  stages: Record<string, ProcessingStageCell>;
  entities: ProcessingEntity[];
  outputs: ProcessingOutputs;
}

export interface ProcessingPage {
  window: string;
  stages: ProcessingStageCol[];
  stats: ProcessingStats;
  entries: ProcessingEntry[];
  next_cursor: string | null;
}

export interface ProcessingFilters {
  window: string; // 1h | 24h | 7d
  status?: string; // error | in_flight | complete
  stage?: string;
  feedId?: string;
  search?: string;
}

export function useEngineProcessing(filters: ProcessingFilters) {
  const { window, status, stage, feedId, search } = filters;
  return useInfiniteQuery({
    queryKey: ["engine", "processing", window, status ?? "all", stage ?? "", feedId ?? "", search ?? ""],
    initialPageParam: null as string | null,
    queryFn: async ({ pageParam }) => {
      const params: Record<string, string> = { window };
      if (status) params.status = status;
      if (stage) params.stage = stage;
      if (feedId) params.feed_id = feedId;
      if (search) params.search = search;
      if (pageParam) params.cursor = pageParam;
      return (await api.get<ProcessingPage>("/engine/processing", { params })).data;
    },
    getNextPageParam: (last) => last.next_cursor,
    staleTime: 15_000,
  });
}

// ---- Autolink name lists --------------------------------------------------
// Two comma-separated settings, same shape: "fp" is the curated vocabulary list
// (bypassed by vendor/product/tool/mitigation, whose real names are common brand
// words), "blocked" is the analyst list that binds for every entity type.

export type AutolinkNameList = "fp" | "blocked";

const NAME_LIST_PATH: Record<AutolinkNameList, string> = {
  fp: "/engine/autolink/fp-names",
  blocked: "/engine/autolink/blocked-names",
};

export function useAutolinkNames(list: AutolinkNameList, params: { q?: string; limit?: number; offset?: number }) {
  return useQuery({
    queryKey: ["engine", "autolink-names", list, params],
    queryFn: async () => {
      const { data } = await api.get<{ items: string[]; total: number; limit: number; offset: number }>(
        NAME_LIST_PATH[list],
        { params },
      );
      return data;
    },
    placeholderData: keepPreviousData,
  });
}

export function useAddAutolinkName(list: AutolinkNameList) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (name: string) => {
      await api.post(NAME_LIST_PATH[list], { name });
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["engine", "autolink-names", list] }),
  });
}

export function useRemoveAutolinkName(list: AutolinkNameList) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (name: string) => {
      await api.delete(NAME_LIST_PATH[list], { params: { name } });
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["engine", "autolink-names", list] }),
  });
}

// --- Personalised Radar (per-analyst learned signal weights) ---------------

export interface MyRadarFamily {
  family: string;
  weight: number;
  learned: boolean;
  up_votes: number;
  down_votes: number;
  sample_count: number;
  votes_seen: number;
  updated_at: string | null;
}

export interface MyRadar {
  /** Instance-wide switch (Settings → System). */
  enabled: boolean;
  /** This analyst's own opt-in. */
  personalized: boolean;
  /** enabled && personalized && at least one fitted family. */
  active: boolean;
  min_samples: number;
  window_days: number;
  total_votes: number;
  families: MyRadarFamily[];
}

export function useMyRadar() {
  return useQuery({
    queryKey: ["engine", "my-radar"],
    queryFn: async () => {
      const res = await api.get<MyRadar>("/engine/my-radar");
      return res.data;
    },
    staleTime: 60_000,
  });
}

export function useSetMyRadarPersonalized() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (personalized: boolean) => {
      const res = await api.put<{ personalized: boolean }>("/engine/my-radar", { personalized });
      return res.data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["engine", "my-radar"] });
      // The Radar ordering is computed server-side per request, so the entry
      // list has to be refetched for the toggle to take visible effect.
      qc.invalidateQueries({ queryKey: ["entries"] });
    },
  });
}

export function useResetMyRadarWeights() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const res = await api.delete<{ cleared: number }>("/engine/my-radar");
      return res.data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["engine", "my-radar"] });
      qc.invalidateQueries({ queryKey: ["entries"] });
    },
  });
}

export interface EngineState {
  stopped: boolean;
  /** Tasks waiting on each queue; null when Redis couldn't be asked. */
  queued: Record<string, number | null>;
  /** When an admin last cleared the check-engine light. */
  health_cleared_at?: string | null;
}

const ENGINE_STATE_KEY = ["engine", "state"];

export function useEngineState(enabled = true, poll = 15_000) {
  return useQuery({
    queryKey: ENGINE_STATE_KEY,
    queryFn: async () => (await api.get<EngineState>("/engine/state")).data,
    refetchInterval: poll,
    enabled,
  });
}

/** Clears the check-engine light until a new error or retry comes in. */
export function useClearEngineHealth() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => (await api.post<EngineState>("/engine/state/clear-health")).data,
    onSuccess: (data) => {
      qc.setQueryData(ENGINE_STATE_KEY, data);
      qc.invalidateQueries({ queryKey: ["engine", "pipeline"] });
    },
  });
}

export function useSetEngineStopped() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (stopped: boolean) => (await api.put<EngineState>("/engine/state", { stopped })).data,
    onSuccess: (data) => {
      qc.setQueryData(ENGINE_STATE_KEY, data);
      // Stopping the engine pauses enrichment too.
      qc.invalidateQueries({ queryKey: ENRICHMENT_CONSOLE_KEY });
    },
  });
}

type EngineHealthLevel = "stopped" | "err" | "warn" | "ok";

export interface EngineHealth {
  level: EngineHealthLevel;
  /** Entries stuck on an errored stage, per stage, since the last clear. */
  failing: { stage: string; count: number }[];
  retrying: number;
  /** When the light was last cleared, and the errors still stuck from before it. */
  clearedAt: string | null;
  clearedErrors: number;
}

/** One status for the whole engine, for the header light. Stopped beats
 *  errors; errors are entries still stuck at a stage (a retry to green drops
 *  them), so a red light always has something to fix behind it. An admin
 *  can clear the light: it then counts only errors and retries newer than
 *  the clear. Fewer than ERROR_LIGHT_THRESHOLD stuck entries in all don't
 *  turn it red: a stray failure is noise, ten is a pattern.
 *  The light sits on every page for every admin, so it polls once a minute;
 *  the Engine console's own observers poll faster while it is open and
 *  TanStack uses the shortest interval. */
/** Stuck entries, across every stage, before the light turns red. */
export const ERROR_LIGHT_THRESHOLD = 10;

export function useEngineHealth(enabled: boolean): EngineHealth | undefined {
  const { data: state } = useEngineState(enabled, 60_000);
  const { data: overview } = usePipelineOverview({ enabled, poll: 60_000 });
  if (!state || !overview) return undefined;
  const newError = (s: PipelineStageInfo) => s.runs_24h.new_error ?? s.runs_24h.error;
  const failing = overview.stages
    .filter((s) => newError(s) > 0)
    .map((s) => ({ stage: s.name, count: newError(s) }));
  const retrying = overview.stages.reduce((n, s) => n + (s.runs_24h.new_retry ?? s.runs_24h.retry), 0);
  const clearedAt = overview.health_cleared_at ?? null;
  const clearedErrors = clearedAt ? overview.stages.reduce((n, s) => n + s.runs_24h.error, 0) : 0;
  const failingTotal = failing.reduce((n, f) => n + f.count, 0);
  const level: EngineHealthLevel = state.stopped
    ? "stopped"
    : failingTotal >= ERROR_LIGHT_THRESHOLD
      ? "err"
      : retrying
        ? "warn"
        : "ok";
  return { level, failing, retrying, clearedAt, clearedErrors };
}

/** The Engine console's time picker: one window for every tab but Review. */
export const ENGINE_WINDOWS = ["1h", "24h", "7d", "30d", "all"] as const;
export type EngineWindow = (typeof ENGINE_WINDOWS)[number];

/** The window in hours, or undefined for "all". */
export function engineWindowHours(w: EngineWindow): number | undefined {
  return { "1h": 1, "24h": 24, "7d": 24 * 7, "30d": 24 * 30, all: undefined }[w];
}
