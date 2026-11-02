import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import api from "@/api/client";
import { useIsVisitor } from "@/stores/authStore";
import { entityContextKey } from "@/hooks/useEntityContext";
import { entityGlanceKey } from "@/hooks/useEntityGlance";
import type { EnrichmentSource } from "@/api/types";

/** Every console query (the table and each source's detail) sits under this. */
export const CONSOLE_KEY = ["enrichment-console"] as const;

// --- Sources ---

export function useEnrichmentSources(enabled = true) {
  // Signed-in only; the route answers 401 to a visitor.
  const isVisitor = useIsVisitor();
  return useQuery({
    queryKey: ["enrichment-sources"],
    queryFn: async () => {
      const { data } = await api.get<EnrichmentSource[]>(
        "/enrichment/sources"
      );
      return data;
    },
    enabled: enabled && !isVisitor,
  });
}

export function useUpdateEnrichmentSource() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      sourceId,
      ...body
    }: {
      sourceId: string;
      is_enabled?: boolean;
      trigger_mode?: string;
      rate_limit_config?: Record<string, number>;
      config?: Record<string, unknown>;
      min_confidence_threshold?: string;
      daily_budget?: number | null;
      clear_daily_budget?: boolean;
    }) => {
      const { data } = await api.put<EnrichmentSource>(
        `/enrichment/sources/${sourceId}`,
        body
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["enrichment-sources"] });
      qc.invalidateQueries({ queryKey: CONSOLE_KEY });
    },
  });
}

// --- Entity Enrichment ---

export function useEnrichEntity() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      entityType,
      entityId,
      sourceTypes,
      refresh,
    }: {
      entityType: string;
      entityId: string;
      sourceTypes?: string[];
      /** Ask the sources again even where a stored answer is still fresh. */
      refresh?: boolean;
    }) => {
      const { data } = await api.post<{
        entity_type: string;
        entity_id: string;
        results: Array<{
          source_type: string;
          status: string;
          parsed_data?: Record<string, unknown>;
          error?: string;
        }>;
        /** The queue lane a refused lookup waits in: always "manual" here. */
        lane?: "manual";
        /** Sources that refused for now; each lookup is queued to retry. */
        queued: string[];
      }>("/enrichment/enrich", {
        entity_type: entityType,
        entity_id: entityId,
        source_types: sourceTypes,
        refresh,
        // A person asked: the manual lane, ahead of new/refresh/backfill work.
        lane: "manual",
      });
      return data;
    },
    onSuccess: (data) => {
      if (data.queued?.length) {
        toast(`Queued to retry when the source allows: ${data.queued.map(sourceLabel).join(", ")}`);
      }
      return Promise.all([
        qc.invalidateQueries({ queryKey: entityContextKey(data.entity_type, data.entity_id) }),
        qc.invalidateQueries({ queryKey: entityGlanceKey(data.entity_type, data.entity_id) }),
        // The console counts today's requests and what's queued.
        qc.invalidateQueries({ queryKey: CONSOLE_KEY }),
      ]);
    },
  });
}

export function useEnrichValue() {
  return useMutation({
    mutationFn: async ({
      value,
      sourceTypes,
      entryId,
    }: {
      value: string;
      sourceTypes?: string[];
      entryId?: string;
    }) => {
      const { data } = await api.post<{
        entity_type: string;
        entity_id: string;
        value: string;
        results: Array<{ source_type: string; status: string; parsed_data?: Record<string, unknown>; error?: string }>;
      }>("/enrichment/enrich-value", {
        value,
        source_types: sourceTypes,
        entry_id: entryId,
      });
      return data;
    },
  });
}

// --- Console (Settings → Engine → Enrichment) ---

/** key_rejected: the source turned the key down (401/403) — fix the key,
 *  waiting won't help. */
type EnrichmentSourceStatus = "ok" | "failing" | "off" | "needs_key" | "key_rejected";

/** What a lookup sends out: nothing (the source is downloaded), public ids,
 *  or the analyst's indicators. */
export type EnrichmentEgress = "none" | "low" | "shares_ioc";

export type EnrichmentKeyStatus = "set" | "missing" | "optional" | "rejected";

/** The one action that fixes an attention item. */
export type EnrichmentAction =
  | { kind: "key"; key: string; label: string }
  | { kind: "source"; source: string; tab: "overview" | "limits" | "fields" | "jobs"; label: string }
  | { kind: "retry"; source: string; label: string };

interface EnrichmentAttention {
  source_type: string | null;
  label: string;
  /** Other sources the same problem covers (one key, several sources). */
  sources?: string[];
  text: string;
  severity: "bad" | "warn";
  action: EnrichmentAction | null;
}

export interface EnrichmentConsoleSummary {
  sources_on: number;
  sources_total: number;
  paused: boolean;
  redis_ok: boolean;
  activity_24h: {
    requests: number;
    /** 24 hourly totals, oldest first. */
    trend: number[];
    waiting: number;
    waiting_backfill: number;
    deferred: number;
    /** Distinct indicators sent to outside sources; null when Redis can't say. */
    iocs_sent: number | null;
    ioc_sources: string[];
  };
}

export interface EnrichmentConsoleEntityType {
  entity_type: string;
  label: string;
  source_count: number;
}

export interface EnrichmentConsoleSource {
  /** The enrichment_sources row id, for PUT /enrichment/sources/{id}. */
  id: string;
  source_type: string;
  label: string;
  about: string;
  kind: "lookup" | "catalog";
  status: EnrichmentSourceStatus;
  enabled: boolean;
  /** Added recently (in the last two weeks, after the instance's first sources). */
  new?: boolean;
  /** What a needs_key source lacks: "key", or "setting <name>". */
  needs?: string | null;
  /** Plain-words summary of what the source writes. */
  fills: string;
  applies_to: string[];
  /** Why the source needs a look; null when it's fine. */
  attention: string | null;
  egress: EnrichmentEgress;
  license: string;
  commercial_ok: boolean;
  /** The credential (Keys view row) it uses; null when it takes no key. */
  key: string | null;
  key_status: EnrichmentKeyStatus | null;
  /** Lookup sources only: "auto" looks up new entities on its own. */
  trigger_mode: "auto" | "manual" | null;
  used_today: number;
  daily_budget: number | null;
  jobs: number;
  /** Settings that tune its jobs. */
  settings_keys: string[];
  /** Settings that configure the source itself (Limits tab). */
  source_settings: string[];
}

export interface EnrichmentConsole {
  summary: EnrichmentConsoleSummary;
  attention: EnrichmentAttention[];
  entity_types: EnrichmentConsoleEntityType[];
  sources: EnrichmentConsoleSource[];
}

/** source_type → label, from the last console read: toasts name sources the
 *  way the console does. */
const LABELS = new Map<string, string>();
export function sourceLabel(sourceType: string): string {
  return LABELS.get(sourceType) ?? sourceType;
}

export type EnrichmentLane = "manual" | "new" | "refresh" | "backfill";

export type EnrichmentQueueReason =
  | "rate_limited"
  | "breaker_open"
  | "budget_exhausted"
  | "backfill_share"
  | "paused"
  | "auth_failed"
  | "source_disabled";

export interface EnrichmentSourceDetail {
  limits: {
    /** The row's stored rate — what the limits form edits. */
    rate: {
      requests_per_period: number;
      period_seconds: number;
    };
    /** What the gateway enforces: a keyed quota's rate when a key is set. */
    effective_rate: {
      requests_per_period: number;
      period_seconds: number;
    };
    /** "with key" when the effective rate is the keyed one, else null. */
    rate_note: string | null;
    ceiling_per_period: number | null;
    daily_budget: number | null;
    used_today: number;
    backfill_share: number | null;
    /** How often a stored answer is looked up again, in days. */
    refresh_days: number | null;
    /** Requests in flight at once under one credential, when capped. */
    concurrency?: number | null;
    triggers: string[];
    scope: string | null;
  };
  /** 24 hourly request counts, oldest first. */
  trend_24h: number[];
  queue: {
    waiting: number;
    by_lane: Partial<Record<EnrichmentLane, number>>;
    retrying: number;
    /** Queued lookups by why they wait again (rate_limited = after a 429). */
    by_reason?: Partial<Record<EnrichmentQueueReason, number>>;
    failed: number;
  };
  /** What the limits form edits. */
  settings?: {
    trigger_mode: string;
    rate_limit_config: Record<string, number>;
  };
  outputs: Array<{
    field: string;
    target: string;
    kind: "column" | "context" | "relationship";
    policy?: string | null;
    rank?: number | null;
    filled_pct: number | null;
    /** Relationship outputs: claims linked to an entity, and claims held for review. */
    linked?: number;
    held?: number;
  }>;
  /** Null when the source has no column output. */
  gap: {
    entity_type: string;
    field: string;
    missing: number;
    in_scope: number;
    eta_days: number | null;
  } | null;
  jobs: Array<{
    key: string;
    description: string;
    settings_keys: string[];
    schedule: string;
    runs_30d: number;
    ok_30d: number;
    last_status: string | null;
    last_error: string | null;
    last_detail: Record<string, unknown> | null;
  }>;
}

export function useEnrichmentConsole(entityType?: string) {
  return useQuery({
    queryKey: [...CONSOLE_KEY, entityType ?? "all"],
    queryFn: async () => {
      const { data } = await api.get<EnrichmentConsole>("/enrichment/console", {
        params: entityType ? { entity_type: entityType } : undefined,
      });
      for (const src of data.sources) LABELS.set(src.source_type, src.label);
      return data;
    },
    // Switching filters keeps the last list up instead of flashing a spinner.
    placeholderData: (prev) => prev,
    refetchInterval: 60_000,
  });
}

export function useEnrichmentSourceDetail(sourceType: string | null) {
  return useQuery({
    queryKey: [...CONSOLE_KEY, "detail", sourceType],
    queryFn: async () => {
      const { data } = await api.get<EnrichmentSourceDetail>(
        `/enrichment/sources/${sourceType}/detail`
      );
      return data;
    },
    enabled: !!sourceType,
  });
}

export function usePauseEnrichment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (paused: boolean) => {
      const { data } = await api.post<{ paused: boolean }>("/enrichment/pause", { paused });
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: CONSOLE_KEY }),
  });
}

export function useQueueBackfill() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      sourceType,
      entityType,
      limit,
    }: {
      sourceType: string;
      entityType: string;
      limit: number;
    }) => {
      const { data } = await api.post<{ queued: number }>(
        `/enrichment/sources/${sourceType}/backfill`,
        { entity_type: entityType, limit }
      );
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: CONSOLE_KEY }),
  });
}

/** Queue again the lookups that gave up (at one source, or all). */
export function useRetryFailedLookups() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (sourceType?: string) => {
      const { data } = await api.post<{ queued: number }>("/enrichment/retry", null, {
        params: sourceType ? { source_type: sourceType } : undefined,
      });
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: CONSOLE_KEY }),
  });
}

// --- Keys ---

export interface EnrichmentKey {
  id: string;
  label: string;
  /** What the key does, in one sentence. */
  note: string;
  required: boolean;
  sources: Array<{ source_type: string; label: string }>;
  /** A user of the key outside enrichment (GitHub feeds). */
  also_used_by: string | null;
  status: EnrichmentKeyStatus;
  /** Why the source rejected it, when it did. */
  message: string | null;
  /** The caller has an own key, used for the lookups they start. */
  mine: boolean;
  personal_allowed: boolean;
  signup_url: string | null;
}

export function useEnrichmentKeys() {
  return useQuery({
    queryKey: [...CONSOLE_KEY, "keys"],
    queryFn: async () => {
      const { data } = await api.get<EnrichmentKey[]>("/enrichment/keys");
      return data;
    },
  });
}

export function useSetEnrichmentKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ keyId, apiKey, mine }: { keyId: string; apiKey: string | null; mine?: boolean }) => {
      await api.put(`/enrichment/keys/${keyId}${mine ? "/mine" : ""}`, { api_key: apiKey });
    },
    // A key changes the sources' status, so the whole console reloads.
    onSuccess: () => qc.invalidateQueries({ queryKey: CONSOLE_KEY }),
  });
}

export function useTestEnrichmentKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (keyId: string) => {
      const { data } = await api.post<{
        status: "ok" | "rejected" | "unreachable" | "missing" | "untestable";
        message: string | null;
      }>(`/enrichment/keys/${keyId}/test`);
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: CONSOLE_KEY }),
  });
}

// --- Coverage and activity ---

export interface EnrichmentCoverageField {
  entity_type: string;
  entity_label: string;
  field: string;
  label: string;
  filled: number;
  total: number;
  filled_pct: number | null;
  sources: Array<{ source_type: string; label: string; enabled: boolean }>;
  /** The one thing to do about the rest; null when jobs fill it on a schedule. */
  action: { kind: "backfill"; source: string; count: number } | { kind: "ai"; field: string } | null;
  cadence: string | null;
}

export function useEnrichmentCoverage(enabled = true) {
  return useQuery({
    queryKey: [...CONSOLE_KEY, "coverage"],
    queryFn: async () => {
      const { data } = await api.get<{ fields: EnrichmentCoverageField[] }>("/enrichment/coverage");
      return data.fields;
    },
    enabled,
    staleTime: 5 * 60_000,
  });
}

interface EnrichmentActivity {
  lanes: Array<{ lane: EnrichmentLane; waiting: number; deferred: number }>;
  backfill_share: number;
  failed: Array<{ source_type: string; label: string; count: number; last_error: string | null }>;
  /** Null when Redis can't say. */
  requests: Array<{ source_type: string; label: string; requests: number }> | null;
}

export function useEnrichmentActivity(enabled = true) {
  return useQuery({
    queryKey: [...CONSOLE_KEY, "activity"],
    queryFn: async () => {
      const { data } = await api.get<EnrichmentActivity>("/enrichment/activity");
      return data;
    },
    enabled,
    refetchInterval: 60_000,
  });
}
