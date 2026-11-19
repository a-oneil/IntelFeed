import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type { QueryLanguage } from "@/utils/queryLanguage";

export type ThreatAction = "write" | "extend" | "diff" | "audit" | "adopt" | "collect" | "merge" | "review";
export type ThreatState = "open" | "handled" | "muted" | "tracked";

export interface ThreatHeadline {
  entry_id: string;
  title: string | null;
  url: string | null;
  source: string | null;
  published_at: string | null;
  /** The thread marks this article as the one that broke the story. */
  is_origin?: boolean;
  /** Outlets on that thread inside the window. */
  outlets?: number;
}

export interface ThreatBoardItem {
  entity_type: string;
  entity_key: string;
  label: string;
  /** ["threat_actor", "malware"] when one threat exists as both entities. */
  facets: string[];
  /** Distinct source domains in the window. */
  attention: number;
  /** Distinct stories behind those domains: one per story thread, plus one per
      domain no thread claimed. Equals `attention` where nothing is threaded. */
  stories: number;
  /** Window articles those stories folded as re-reports. */
  echoes_folded: number;
  /** Waves of coverage on this row's thread — its spine length. */
  beats: number;
  /** Techniques first seen for this threat inside the window. */
  new_techniques: number;
  /** Distinct techniques ever extracted for this threat. */
  on_record: number;
  /** Library rules resolving to this threat — an inventory, not a verdict. */
  prior_rules: number;
  /** Of those, resolved at high or medium confidence (title, tag or metadata). */
  prior_rules_strong: number;
  prior_rule_repos: Record<string, number>;
  last_seen: string | null;
  state: ThreatState;
  is_generic: boolean;
  score: number;
  action: ThreatAction;
  /** Distinct window entries behind the attention count. */
  articles: number;
  /** The window's lead article — a title that names the threat wins over a
      technique-dense roundup that merely mentions it. */
  headline: ThreatHeadline | null;
  /** Distinct source hosts behind the attention count (top 6), for "why". */
  sources: string[];
  /** In-window technique links carrying a real observable sentence. */
  writable_observables: number;
  /** The story thread holding this row's window coverage, when one does. */
  thread_slug: string | null;
  thread_title: string | null;
  /** True for a row backed only by a thread — no actor, malware or CVE
      resolved, so `entity_key` is the thread slug. */
  is_story: boolean;
  /** Rows folded into this one: threat rows a single thread holds together,
      and on the All view the CVEs this row's articles claim (`entity_type`
      "cve", with the exploitation chips the row needs to name them). */
  merged_from: {
    entity_type: string;
    entity_key: string;
    label: string;
    is_kev?: boolean;
    product?: string | null;
    in_stack?: boolean;
  }[];
  /** Nightly AI story line built only from the window's entries. Null until
      generated — render the headline as fallback, never a template sentence. */
  brief: string | null;
  /** Entry ids the brief was built from — its audit trail. */
  brief_sources: string[];
  /** Vulnerability-row extras — null/false on actor and malware rows. */
  product: string | null;
  in_stack: boolean;
  is_kev: boolean;
  cvss_score: number | null;
  epss_score: number | null;
  exploit_status: string | null;
  /** blind (rule blocked by telemetry) | no_rule | defended */
  posture: string | null;
  /** Entity uuid for profile navigation on CVE rows. */
  profile_id: string | null;
  /** False for CVE rows affecting nothing you run with no fireable rule.
      Informational: it never changes the row's rank or visibility. */
  on_surface: boolean;
}

export interface ThreatBoardResponse {
  window: string;
  items: ThreatBoardItem[];
  total: number;
}

export type BoardFacet = "threats" | "vulns" | "all";

export function useThreatBoard(window: string, includeHandled: boolean, facet: BoardFacet = "threats") {
  return useQuery({
    queryKey: ["threat-board", window, includeHandled, facet],
    queryFn: async () => {
      const { data } = await api.get<ThreatBoardResponse>("/threat-board", {
        params: { window, include_handled: includeHandled, limit: 40, facet },
      });
      return data;
    },
    // The board is rebuilt on a schedule, not per request — a short stale window
    // avoids refetching the same materialised ranking on every tab switch.
    staleTime: 60_000,
  });
}

export interface PrecedentStory {
  slug: string;
  title: string;
  status: string;
  entry_count: number;
  similarity: number;
}

/** Stories this row's story resembles — the "have we seen this before" line.
    Answered from thread centroids, so it reaches back past the window. */
export function usePrecedent(threadSlug: string | null | undefined, enabled: boolean) {
  return useQuery({
    queryKey: ["threat-board-precedent", threadSlug],
    queryFn: async () => {
      const { data } = await api.get<{ thread: string; items: PrecedentStory[] }>(
        "/threat-board/precedent",
        { params: { thread: threadSlug } }
      );
      return data.items;
    },
    enabled: enabled && !!threadSlug,
    // Centroids move only when the sweeper reshapes a thread.
    staleTime: 300_000,
  });
}

export function useSetThreatState() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (vars: {
      entityType: string;
      entityKey: string;
      state: ThreatState;
      /** The board view's window — a row visible only at 30d must be
          handleable from the 30d view. */
      window: string;
      note?: string;
    }) => {
      const { data } = await api.put<ThreatBoardItem>(
        `/threat-board/${vars.entityType}/${encodeURIComponent(vars.entityKey)}/state`,
        { state: vars.state, note: vars.note ?? null },
        { params: { window: vars.window } }
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["threat-board"] });
    },
  });
}

export interface BoardRule {
  rule_id: string;
  title: string;
  rule_type: string;
  is_draft: boolean;
  license: string | null;
  severity: string | null;
  repo: string;
  via: string;
  confidence: string;
  matched_on: string | null;
}

export interface BoardRulesResponse {
  items: BoardRule[];
  total: number;
  strong: number;
  weak: number;
}

/** Every library rule that resolves to one board row — the list behind the
    caption's "N rules name it", fetched when the drawer opens. */
export function useBoardRules(entityType: string, entityKey: string, enabled: boolean) {
  return useQuery({
    queryKey: ["threat-board-rules", entityType, entityKey],
    queryFn: async () => {
      const { data } = await api.get<BoardRulesResponse>(
        `/threat-board/${entityType}/${encodeURIComponent(entityKey)}/rules`
      );
      return data;
    },
    enabled,
    staleTime: 60_000,
  });
}


/* ── Hunt packs ──────────────────────────────────────────────────────────────
   A starting point for a hunt, not a record of one: hypotheses and queries
   the analyst copies into their SIEM or exports as an ATHF hunt file. */

export interface HuntTelemetry {
  source: string;
  have: boolean;
}

export interface HuntHypothesis {
  id: string;
  title: string;
  /** ATHF form: "Adversaries use [behavior] to [goal] on [target]". */
  hypothesis: string;
  tactic: string | null;
  techniques: string[];
  platform: string | null;
  data_sources: string[];
  /** data_sources checked against the enabled telemetry inventory. */
  telemetry: HuntTelemetry[];
  runnable: boolean;
  query: string;
  query_notes: string | null;
  false_positives: string | null;
}

export interface HuntPack {
  entity_type: string;
  entity_key: string;
  label: string;
  window: string;
  language: QueryLanguage;
  language_name: string;
  generated_at: string | null;
  model: string | null;
  entry_ids: string[];
  hypotheses: HuntHypothesis[];
}

export interface HuntPackResponse {
  status: "ready" | "none";
  language: QueryLanguage;
  language_name: string;
  pack: HuntPack | null;
}

const huntPackKey = (entityType: string, entityKey: string, window: string) => [
  "threat-board-hunt-pack",
  entityType,
  entityKey,
  window,
];

/** The cached hunt pack for a row — `status: "none"` until someone drafts it.
    The language is the user's preferred query language, applied server-side. */
export function useHuntPack(entityType: string, entityKey: string, window: string, enabled: boolean) {
  return useQuery({
    queryKey: huntPackKey(entityType, entityKey, window),
    queryFn: async () => {
      const { data } = await api.get<HuntPackResponse>(
        `/threat-board/${entityType}/${encodeURIComponent(entityKey)}/hunt-pack`,
        { params: { window } }
      );
      return data;
    },
    enabled,
    staleTime: 60_000,
  });
}

/** Draft (or redraft) a row's hunt pack. Synchronous on the server: the AI
    call runs while the mutation is pending, then the GET above is refreshed. */
export function useDraftHuntPack() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (vars: { entityType: string; entityKey: string; window: string }) => {
      const { data } = await api.post<HuntPackResponse>(
        `/threat-board/${vars.entityType}/${encodeURIComponent(vars.entityKey)}/hunt-pack`,
        null,
        { params: { window: vars.window }, timeout: 330_000 }
      );
      return data;
    },
    onSuccess: (data, vars) => {
      qc.setQueryData(huntPackKey(vars.entityType, vars.entityKey, vars.window), data);
    },
  });
}

/** Download the row's pack as an ATHF hunt file (H-XXXX-<slug>.md). */
export async function downloadHuntFile(entityType: string, entityKey: string, window: string): Promise<void> {
  const res = await api.get<Blob>(`/threat-board/${entityType}/${encodeURIComponent(entityKey)}/hunt-pack.md`, {
    params: { window },
    responseType: "blob",
  });
  const disposition = String(res.headers?.["content-disposition"] ?? "");
  const name = /filename="([^"]+)"/.exec(disposition)?.[1] ?? "H-XXXX.md";
  const url = URL.createObjectURL(res.data);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
