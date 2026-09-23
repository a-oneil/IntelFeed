import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type {
  DataSourceTaxonomy,
  DetectionRule,
  DetectionRuleVersion,
  DetectionSummarySaved,
  FeasibilityResult,
  RuleProvenance,
  RuleTelemetryVocabulary,
  RuleValidationResult,
  TechniqueCoverageResponse,
  TelemetryGapsResponse,
  VersionDiff,
} from "@/api/types";

export function useCreateDetectionRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      title: string;
      rule_type: string;
      rule_content: string;
      description?: string;
      is_draft?: boolean;
      tags?: string[];
      source_ttps?: string[];
      source_entries?: string[];
      source_actors?: string[];
    }) => {
      const { data } = await api.post<DetectionRule>("/detection-rules", body);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["detection-rules"] });
    },
  });
}

export function useDetectionRuleVersions(ruleId: string | undefined) {
  return useQuery({
    queryKey: ["detection-rule-versions", ruleId],
    queryFn: async () => {
      const { data } = await api.get<DetectionRuleVersion[]>(
        `/detection-rules/${ruleId}/versions`
      );
      return data;
    },
    enabled: !!ruleId,
  });
}

export function useRollbackVersion() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      ruleId,
      versionId,
    }: {
      ruleId: string;
      versionId: string;
    }) => {
      const { data } = await api.post<DetectionRule>(
        `/detection-rules/${ruleId}/versions/${versionId}/rollback`
      );
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["detection-rule", vars.ruleId] });
      qc.invalidateQueries({
        queryKey: ["detection-rule-versions", vars.ruleId],
      });
      qc.invalidateQueries({ queryKey: ["detection-rules"] });
    },
  });
}

export function useToggleRuleStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      ruleId,
      is_draft,
    }: {
      ruleId: string;
      is_draft: boolean;
    }) => {
      const { data } = await api.patch<DetectionRule>(
        `/detection-rules/${ruleId}/status`,
        { is_draft }
      );
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["detection-rule", vars.ruleId] });
      qc.invalidateQueries({ queryKey: ["detection-rules"] });
    },
  });
}

export function useValidateRule() {
  return useMutation({
    mutationFn: async ({
      rule_type,
      rule_content,
    }: {
      rule_type: string;
      rule_content: string;
    }) => {
      const { data } = await api.post<RuleValidationResult>(
        "/detection-rules/validate",
        { rule_type, rule_content }
      );
      return data;
    },
  });
}

export function useExtractRuleMetadata() {
  return useMutation({
    mutationFn: async ({
      rule_type,
      rule_content,
    }: {
      rule_type: string;
      rule_content: string;
    }) => {
      const { data } = await api.post<{
        metadata: Record<string, unknown>;
        mapped_fields: Record<string, unknown>;
      }>("/detection-rules/extract-metadata", { rule_type, rule_content });
      return data;
    },
  });
}

/**
 * Which of the rule library's Telemetry values the enabled inventory answers.
 *
 * Server-side because the match is tiered and fuzzy — a ticked product name, a
 * canonical behaviour id, or a category with a ticked source — so comparing the
 * two lists in the client would under-count badly.
 *
 * Changes only when someone edits Telemetry Sources, so it is cached for the
 * session rather than refetched per keystroke in the library.
 */
export function useRuleTelemetryVocabulary() {
  return useQuery({
    queryKey: ["rule-telemetry-vocabulary"],
    queryFn: async () => {
      const { data } = await api.get<RuleTelemetryVocabulary>("/detection-rules/telemetry-vocabulary");
      return data;
    },
    staleTime: 5 * 60 * 1000,
  });
}

export function useBulkUpdateRules() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      rule_ids: string[];
      is_draft?: boolean;
      tags_add?: string[];
      tags_remove?: string[];
    }) => {
      const { data } = await api.post<{ updated: number }>(
        "/detection-rules/bulk-update",
        body
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["detection-rules"] });
    },
  });
}

export function useBulkDeleteRules() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (rule_ids: string[]) => {
      const { data } = await api.post<{ deleted: number }>(
        "/detection-rules/bulk-delete",
        { rule_ids }
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["detection-rules"] });
    },
  });
}

export function useImportRules() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (file: File) => {
      const formData = new FormData();
      formData.append("file", file);
      const { data } = await api.post<{
        imported: number;
        skipped: number;
        errors: Array<{ file: string; error: string }>;
      }>("/detection-rules/import", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["detection-rules"] });
    },
  });
}

export function useExportRules() {
  return useMutation({
    mutationFn: async ({
      rule_ids,
      format = "zip",
    }: {
      rule_ids?: string[];
      format?: "yaml" | "zip";
    }) => {
      const params: Record<string, string> = { format };
      if (rule_ids?.length) {
        params.rule_ids = rule_ids.join(",");
      }
      const { data } = await api.get("/detection-rules/export", {
        params,
        responseType: "blob",
      });
      // Trigger browser download
      const blob = new Blob([data as BlobPart]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download =
        format === "zip" ? "detection-rules.zip" : "detection-rules.yml";
      a.click();
      URL.revokeObjectURL(url);
    },
  });
}

export function useCheckFeasibility() {
  return useMutation({
    mutationFn: async (data_sources: string[]) => {
      const { data } = await api.post<FeasibilityResult>(
        "/telemetry-sources/check-feasibility",
        { data_sources }
      );
      return data;
    },
  });
}

export function useDataSourceTaxonomy() {
  return useQuery({
    queryKey: ["data-source-taxonomy"],
    queryFn: async () => {
      const { data } =
        await api.get<DataSourceTaxonomy>("/telemetry-sources/taxonomy");
      return data;
    },
    staleTime: Infinity,
  });
}

export function useRuleProvenance(ruleId: string | undefined) {
  return useQuery({
    queryKey: ["rule-provenance", ruleId],
    queryFn: async () => {
      const { data } = await api.get<RuleProvenance>(
        `/detection-rules/${ruleId}/provenance`
      );
      return data;
    },
    enabled: !!ruleId,
  });
}

export interface CommitRecord {
  sha: string;
  short_sha: string;
  author: string;
  message: string;
  date: string | null;
  change_type: string;
  url: string | null;
  file_url: string | null;
}

export interface CommitTimeline {
  rule_id: string;
  owner: string;
  repo: string;
  file_path: string;
  commits: CommitRecord[];
}

export function useRuleCommitTimeline(ruleId: string | undefined) {
  return useQuery({
    queryKey: ["rule-commits", ruleId],
    queryFn: async () => {
      const { data } = await api.get<CommitTimeline>(
        `/detection-rules/${ruleId}/commits`
      );
      return data;
    },
    enabled: !!ruleId,
  });
}

export interface RelatedRuleSummary {
  id: string;
  title: string;
  rule_type: string;
  severity: string | null;
  source_repo: string | null;
  similarity?: number;
}

export interface RelatedRules {
  near_duplicate: RelatedRuleSummary[];
  other_format: RelatedRuleSummary[];
  same_cve: RelatedRuleSummary[];
  same_technique: RelatedRuleSummary[];
}

export function useRelatedRules(ruleId: string | undefined) {
  return useQuery({
    queryKey: ["rule-related", ruleId],
    queryFn: async () => {
      const { data } = await api.get<RelatedRules>(`/detection-rules/${ruleId}/related`);
      return data;
    },
    enabled: !!ruleId,
  });
}

export interface FreshIntelEntry {
  id: string;
  title: string;
  url: string | null;
  published_at: string | null;
  matched_on: string;
}

export interface RuleFreshIntel {
  items: FreshIntelEntry[];
  total: number;
  since: string;
}

export function useRuleFreshIntel(ruleId: string | undefined) {
  return useQuery({
    queryKey: ["rule-fresh-intel", ruleId],
    queryFn: async () => {
      const { data } = await api.get<RuleFreshIntel>(`/detection-rules/${ruleId}/fresh-intel`);
      return data;
    },
    enabled: !!ruleId,
  });
}


export function useVersionDiff() {
  return useMutation({
    mutationFn: async ({
      ruleId,
      v1,
      v2,
    }: {
      ruleId: string;
      v1: number;
      v2?: number;
    }) => {
      const params: Record<string, number> = { v1 };
      if (v2 !== undefined) params.v2 = v2;
      const { data } = await api.get<VersionDiff>(
        `/detection-rules/${ruleId}/diff`,
        { params }
      );
      return data;
    },
  });
}

export function useTelemetryGaps() {
  return useQuery({
    queryKey: ["telemetry-gaps"],
    queryFn: async () => {
      const { data } =
        await api.get<TelemetryGapsResponse>("/telemetry-sources/telemetry-gaps");
      return data;
    },
  });
}

/** The endpoint rejects more than 500 technique IDs per request. */
const COVERAGE_BATCH = 500;

/** Telemetry-aware 3-way coverage (covered / library_only / no_rule) for a set of techniques. */
export function useTechniqueCoverage(techniqueIds: string[]) {
  const ids = [...new Set(techniqueIds.filter(Boolean))].sort();
  return useQuery({
    queryKey: ["technique-coverage", ids],
    queryFn: async () => {
      // The workbench TTP table feeds this the whole infinite-scrolled page set,
      // which runs past the server's 500-ID cap — split and recombine.
      const chunks: string[][] = [];
      for (let i = 0; i < ids.length; i += COVERAGE_BATCH) {
        chunks.push(ids.slice(i, i + COVERAGE_BATCH));
      }
      const pages = await Promise.all(
        chunks.map((chunk) =>
          api
            .post<TechniqueCoverageResponse>("/intelligence/detection-coverage", chunk)
            .then((r) => r.data)
        )
      );
      if (pages.length === 1) return pages[0];
      const merged: TechniqueCoverageResponse = {
        summary: { total: 0, covered: 0, library_only: 0, no_rule: 0, coverage_percentage: 0 },
        techniques: {},
      };
      for (const page of pages) {
        Object.assign(merged.techniques, page.techniques);
        merged.summary.total += page.summary.total;
        merged.summary.covered += page.summary.covered;
        merged.summary.library_only += page.summary.library_only;
        merged.summary.no_rule += page.summary.no_rule;
      }
      merged.summary.coverage_percentage = merged.summary.total
        ? Math.round((merged.summary.covered / merged.summary.total) * 1000) / 10
        : 0;
      return merged;
    },
    enabled: ids.length > 0,
    staleTime: 60_000,
  });
}

export function useSavedDetectionSummaries() {
  return useQuery({
    queryKey: ["detection-summaries"],
    queryFn: async () => {
      const { data } = await api.get<DetectionSummarySaved[]>(
        "/intelligence/detection-summaries"
      );
      return data;
    },
  });
}

export function useSavedDetectionSummary(id: string | undefined) {
  return useQuery({
    queryKey: ["detection-summary", id],
    queryFn: async () => {
      const { data } = await api.get<DetectionSummarySaved>(
        `/intelligence/detection-summaries/${id}`
      );
      return data;
    },
    enabled: !!id,
  });
}

export function useSaveDetectionSummary() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: {
      entry_ids: string[];
      title: string;
      include_existing_intelligence?: boolean;
      rule_formats?: string[];
      focus?: string;
    }) => {
      const { data } = await api.post<DetectionSummarySaved>(
        "/intelligence/detection-summaries",
        body
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["detection-summaries"] });
    },
  });
}

export function useDeleteDetectionSummary() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/intelligence/detection-summaries/${id}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["detection-summaries"] });
    },
  });
}

// --- AI Rule Conversion ---

export interface ConvertResult {
  converted_content: string;
  source_type: string;
  target_type: string;
  model: string;
  tokens_input: number;
  tokens_output: number;
  tokens_used: number;
  cost: number;
}

export function useConvertRule() {
  return useMutation({
    mutationFn: async ({
      ruleId,
      target_type,
    }: {
      ruleId: string;
      target_type: string;
    }) => {
      const { data } = await api.post<ConvertResult>(
        `/detection-rules/${ruleId}/convert`,
        { target_type },
        // AI conversion routinely takes 30-90s; the client default of 15s
        // aborted every call before the model could answer.
        { timeout: 180000 }
      );
      return data;
    },
  });
}

// --- AI Rule Chat (Streaming) ---

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export interface RuleChatOptions {
  ruleContent: string;
  ruleType: string;
  title: string;
  severity?: string;
  mitreTactics?: string[];
  dataSources?: string[];
  history: ChatMessage[];
  message: string;
  onChunk: (text: string) => void;
  onDone: () => void;
  onError: (error: string) => void;
}

export async function streamRuleChat(
  options: RuleChatOptions,
  signal?: AbortSignal,
): Promise<void> {
  const { useAuthStore } = await import("@/stores/authStore");
  const token = useAuthStore.getState().accessToken;

  const body = {
    message: options.message,
    rule_content: options.ruleContent,
    rule_type: options.ruleType,
    title: options.title,
    severity: options.severity || "",
    mitre_tactics: options.mitreTactics || [],
    data_sources: options.dataSources || [],
    history: options.history,
  };

  const resp = await fetch("/api/detection-rules/chat", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
    signal,
  });

  if (!resp.ok) {
    const errText = await resp.text();
    let msg = "AI chat request failed";
    try {
      const errJson = JSON.parse(errText);
      msg = errJson.detail?.message || errJson.detail || msg;
    } catch {
      // use default
    }
    options.onError(msg);
    return;
  }

  const reader = resp.body?.getReader();
  if (!reader) {
    options.onError("No response stream");
    return;
  }

  const decoder = new TextDecoder();
  let buffer = "";

  // eslint-disable-next-line no-constant-condition -- stream read loop, exits on `done`
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() || "";

    for (const line of lines) {
      if (line.startsWith("data: ")) {
        const dataStr = line.slice(6).trim();
        if (!dataStr) continue;
        try {
          const data = JSON.parse(dataStr);
          if (data.text) {
            options.onChunk(data.text);
          }
          if (data.error) {
            options.onError(data.error);
            return;
          }
        } catch {
          // skip malformed SSE data
        }
      }
    }
  }

  options.onDone();
}
