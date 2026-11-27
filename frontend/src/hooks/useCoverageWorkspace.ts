/**
 * Coverage Workspace — the authoring lane on a threat's Detection tab.
 *
 * Every read here is served from stored rows (articles, extracted behaviors, `rule_coverage` candidates), never from an AI call: the summary generator returns 503 under load and `GET /detection-rules/{id}` takes about 5s, so opening the workspace has to be a plain read.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";

/** Strongest tier the enabled telemetry reaches for a required source. */
export type TelemetryTier = "source" | "log_type" | "category" | null;

/** What is being done with a rule right now, not a lifecycle state. A skip is saved with its reason, so it explains the gap to the next person. */
export type SetOp = "adopt" | "extend" | "new" | "skip";

export interface WorkspaceQuote {
  telemetry?: string | null;
  entry_id: string;
  entry_title: string;
  /** entry_ttps.source_text — the sentence the technique was read from. */
  text: string;
  paragraph_indices: number[];
  /** domain_pattern | path | cmdline | registry | client_id | header | hash | other */
  observable_type: string | null;
  /** The concrete artifact, verbatim — what a rule draft compiles into a clause. */
  observable_value: string | null;
}

export interface WorkspaceArticle {
  entry_id: string;
  title: string;
  url: string | null;
  source: string;
  published_at: string | null;
  word_count: number | null;
  technique_count: number;
  new_technique_count: number;
  /** False for a recap that added no techniques — a different kind of input. */
  contributed: boolean;
}

export interface WorkspaceChannel {
  source: string;
  tier: TelemetryTier;
}

export interface WorkspaceBehavior {
  technique_id: string;
  technique_name: string;
  tactic: string | null;
  entry_count: number;
  first_seen: string | null;
  is_new: boolean;
  quotes: WorkspaceQuote[];
  channels: WorkspaceChannel[];
  tier: TelemetryTier;
  missing_channels: string[];
  missing_categories: string[];
  /** No required channel matches the inventory: a sourcing item, not a gap. */
  below_line: boolean;
  prior_rules: number;
  prior_rules_strong: number;
}

export interface CoverageWorkspace {
  entity_type: string;
  entity_key: string;
  label: string;
  window: string;
  articles: WorkspaceArticle[];
  behaviours: WorkspaceBehavior[];
  /** Every article in the window. `articles` above is a capped page of it, so the provenance section cites this rather than the page length. */
  article_total: number;
  /** Of those, the ones that carried at least one technique. */
  article_contributed_total: number;
  missing_categories: string[];
  below_line_count: number;
  /** Rules resolving to the threat itself — candidates for every behavior. */
  threat_prior_rules: number;
  threat_prior_rules_strong: number;
  /** Exploitation context, present only on the CVE face. */
  cve: CveContext | null;
}

export interface CveContext {
  severity: string | null;
  cvss_score: number | null;
  epss_score: number | null;
  epss_percentile: number | null;
  is_kev: boolean;
  kev_date_added: string | null;
  kev_due_date: string | null;
  exploit_status: string | null;
  exploit_availability: string | null;
  github_poc_count: number;
  metasploit_module: boolean;
  affected: string[];
}

export interface PriorRuleItem {
  rule_id: string;
  title: string;
  rule_type: string;
  repo: string;
  license: string | null;
  is_draft: boolean;
  /** "technique" = tagged with this behavior; "threat" = names the threat. */
  scope: "technique" | "threat";
  via: "tag" | "meta" | "text";
  confidence: "high" | "medium" | "low";
  matched_on: string | null;
  tier: TelemetryTier;
  required: string[];
  missing: string[];
  /** Upstream commit date where the importer recorded one, else the local row's date. Ranks a maintained rule above one abandoned in 2022; it is the only signal that reliably varies when every candidate is tagged, strong and satisfiable. */
  maintained_at: string | null;
}

export interface PriorRulesResponse {
  technique_id: string;
  items: PriorRuleItem[];
  total: number;
  total_candidates: number;
  strong: number;
  weak: number;
  technique_scope: number;
  threat_scope: number;
}

export interface SetItem {
  op: SetOp;
  rule_id: string | null;
  technique_id: string | null;
  title: string;
  rule_type: string | null;
  repo?: string | null;
  license?: string | null;
  note?: string | null;
  /** skip only: cannot fire here | duplicate | low quality — a known gap in exports. */
  reason?: string | null;
}

export interface SavedSet {
  id: string;
  title: string;
  created_at: string;
  updated_at: string;
  entry_ids: string[];
  item_count: number;
  /** Adopted/extended rules whose upstream commit is newer than the save: the upstream rule changed after it was adopted, so it is worth re-reading. */
  upstream_moved: string[];
  content: { items: SetItem[]; label?: string; window?: string };
}

/** Types with an "articles that contributed techniques" question to answer. */
/** Entity types that get a Detection tab: threats get the board + workspace; a CVE gets the workspace with exploitation context; a technique gets an unranked coverage bench for itself. Every other type hides the tab. */
// Campaigns are included: the workspace reads behaviors from an entity's articles, and a campaign's articles are chosen by hand rather than matched, so the Detection tab gives it the same Build bench as an actor instead of a plain list.
export const WORKSPACE_TYPES = new Set(["threat_actor", "malware", "cve", "ttp", "campaign"]);

export function useCoverageWorkspace(entityType: string, entityKey: string, window: string, enabled: boolean) {
  return useQuery({
    queryKey: ["coverage-workspace", entityType, entityKey, window],
    queryFn: async () => {
      const { data } = await api.get<CoverageWorkspace>(
        `/coverage-workspace/${entityType}/${entityKey}`,
        { params: { window } }
      );
      return data;
    },
    enabled: enabled && WORKSPACE_TYPES.has(entityType),
    staleTime: 60_000,
  });
}

export function useBehaviorRules(entityType: string, entityKey: string, techniqueId: string | null) {
  return useQuery({
    queryKey: ["coverage-workspace-rules", entityType, entityKey, techniqueId],
    queryFn: async () => {
      const { data } = await api.get<PriorRulesResponse>(
        `/coverage-workspace/${entityType}/${entityKey}/behaviours/${techniqueId}/rules`,
        { params: { limit: 25 } }
      );
      return data;
    },
    enabled: Boolean(techniqueId) && WORKSPACE_TYPES.has(entityType),
    staleTime: 60_000,
  });
}

export function useSavedSets(entityType: string, entityKey: string, enabled: boolean) {
  return useQuery({
    queryKey: ["coverage-workspace-sets", entityType, entityKey],
    queryFn: async () => {
      const { data } = await api.get<{ items: SavedSet[]; total: number }>(
        `/coverage-workspace/${entityType}/${entityKey}/sets`
      );
      return data;
    },
    enabled: enabled && WORKSPACE_TYPES.has(entityType),
    staleTime: 60_000,
  });
}

export function useSaveCoverageSet(entityType: string, entityKey: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (vars: {
      title: string;
      window: string;
      items: {
        op: SetOp;
        rule_id: string | null;
        technique_id: string | null;
        title: string;
        rule_type: string | null;
        note?: string | null;
        reason?: string | null;
      }[];
      entryIds?: string[];
      summaryId?: string | null;
    }) => {
      const { data } = await api.post<SavedSet>(`/coverage-workspace/${entityType}/${entityKey}/sets`, {
        title: vars.title,
        window: vars.window,
        items: vars.items,
        entry_ids: vars.entryIds ?? [],
        summary_id: vars.summaryId ?? null,
      });
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["coverage-workspace-sets", entityType, entityKey] });
    },
  });
}

/**
 * The export writer is deliberately a stub: it returns the assembled set with its provenance so an existing exporter can render it. A second serializer here would give one set two formats that drift apart.
 */
export function useExportCoverageSet() {
  return useMutation({
    mutationFn: async (vars: { summaryId: string; format: string }) => {
      const { data } = await api.post<{ format: string; item_count: number; payload: Record<string, unknown> }>(
        `/coverage-workspace/sets/${vars.summaryId}/export`,
        null,
        { params: { format: vars.format } }
      );
      return data;
    },
  });
}

export function useDeleteCoverageSet(entityType: string, entityKey: string) {
  const qc = useQueryClient();
  return useMutation({
    // The set is a detection_summaries row, so it is deleted through the endpoint that already owns that table.
    mutationFn: async (summaryId: string) => {
      await api.delete(`/intelligence/detection-summaries/${summaryId}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["coverage-workspace-sets", entityType, entityKey] });
    },
  });
}
