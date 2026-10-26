import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";

interface DateRangeParams {
  date_from?: string;
  date_to?: string;
}

function dateQuery(params?: DateRangeParams): Record<string, unknown> {
  const query: Record<string, unknown> = {};
  if (params?.date_from) query.date_from = params.date_from;
  if (params?.date_to) query.date_to = params.date_to;
  return query;
}

/* ── Overview ── */

export interface OverviewMetric {
  count: number;
  trend?: number;
}

export interface OverviewEntityCount {
  type: string;
  count: number;
  trend: number;
}

export interface OverviewSeriesPoint {
  date: string;
  count: number;
}

export interface BoardOverviewData {
  headline: {
    entries: OverviewMetric;
    radar: OverviewMetric;
    /** Absent for a visitor (public read-only mode). */
    unread?: OverviewMetric;
    /** Absent for a visitor (public read-only mode). */
    detections?: OverviewMetric;
  };
  entities: OverviewEntityCount[];
  series: {
    entries: OverviewSeriesPoint[];
    detections?: OverviewSeriesPoint[];
  };
}

export function useBoardOverview(params?: DateRangeParams) {
  const query = dateQuery(params);
  return useQuery({
    queryKey: ["widgets", "board-overview", query],
    queryFn: async () => {
      const res = await api.get<BoardOverviewData>("/widgets/overview", { params: query });
      return res.data;
    },
  });
}

/* ── Watchlist pulse ── */

export interface WatchlistPulseRow {
  entity_type: string;
  entity_id: string;
  name: string;
  points: OverviewSeriesPoint[];
  total: number;
  delta: number;
}

export interface WatchlistPulseData {
  items: WatchlistPulseRow[];
  window_days: number;
}

export function useWatchlistPulse(days?: number) {
  const query = days ? { days } : {};
  return useQuery({
    queryKey: ["widgets", "watchlist-pulse", query],
    queryFn: async () => {
      const res = await api.get<WatchlistPulseData>("/widgets/watchlist-pulse", { params: query });
      return res.data;
    },
  });
}

/* ── Ransomware pulse ── */

export interface RansomwarePulseWeek {
  week_start: string;
  label: string;
  total: number;
  groups: Record<string, number>;
}

export interface RansomwarePulseData {
  weeks: RansomwarePulseWeek[];
  groups: string[];
  totals: { victims: number; trend: number; groups_active: number };
}

export function useRansomwarePulse(params?: DateRangeParams) {
  const query = dateQuery(params);
  return useQuery({
    queryKey: ["widgets", "ransomware-pulse", query],
    queryFn: async () => {
      const res = await api.get<RansomwarePulseData>("/widgets/ransomware-pulse", { params: query });
      return res.data;
    },
  });
}

/* ── Rules needing attention ── */

export interface RuleAttentionRow {
  rule_id: string;
  title: string;
  rule_type: string;
  severity: string | null;
  updated_at: string | null;
  new_intel_count: number;
}

export interface RulesAttentionData {
  items: RuleAttentionRow[];
  total_rules: number;
  stale_count: number;
  window_days: number;
}

export function useRulesAttention(limit?: number) {
  const query = limit ? { limit } : {};
  return useQuery({
    queryKey: ["widgets", "rules-attention", query],
    queryFn: async () => {
      const res = await api.get<RulesAttentionData>("/widgets/rules-attention", { params: query });
      return res.data;
    },
  });
}

/* ── Targeting grid ── */

export interface TargetingGridRow {
  sector: string;
  label: string;
  cells: number[];
  total: number;
}

export interface TargetingGridData {
  regions: string[];
  rows: TargetingGridRow[];
  max_cell: number;
}

export function useTargetingGrid(params?: DateRangeParams) {
  const query = dateQuery(params);
  return useQuery({
    queryKey: ["widgets", "targeting-grid", query],
    queryFn: async () => {
      const res = await api.get<TargetingGridData>("/widgets/targeting-grid", { params: query });
      return res.data;
    },
  });
}

/* ── KEV deadlines ── */

export interface KEVDeadlineRow {
  id: string;
  cve_id: string;
  kev_due_date: string;
  kev_date_added: string | null;
  days_left: number;
  cvss_score: number | null;
  vendor: string | null;
  product: string | null;
  name: string | null;
}

export interface KEVDeadlinesData {
  items: KEVDeadlineRow[];
  due_7d: number;
}

export function useKEVDeadlines(limit?: number) {
  const query = limit ? { limit } : {};
  return useQuery({
    queryKey: ["widgets", "kev-deadlines", query],
    queryFn: async () => {
      const res = await api.get<KEVDeadlinesData>("/widgets/kev-deadlines", { params: query });
      return res.data;
    },
  });
}

/* ── Triage flow ── */

export interface TriageFlowDay {
  date: string;
  arrived: number;
  read: number;
}

export interface TriageFlowData {
  days: TriageFlowDay[];
  backlog: number;
}

export function useTriageFlow(days?: number) {
  const query = days ? { days } : {};
  return useQuery({
    queryKey: ["widgets", "triage-flow", query],
    queryFn: async () => {
      const res = await api.get<TriageFlowData>("/widgets/triage-flow", { params: query });
      return res.data;
    },
  });
}

/* ── Campaign momentum ── */

export interface CampaignMomentumWeek {
  week_start: string;
  count: number;
}

export interface CampaignMomentumRow {
  id: string;
  name: string;
  status: string;
  tlp_marking: string | null;
  weeks: CampaignMomentumWeek[];
  recent_count: number;
  total_entries: number;
}

export function useCampaignMomentum(limit?: number) {
  const query = limit ? { limit } : {};
  return useQuery({
    queryKey: ["widgets", "campaign-momentum", query],
    queryFn: async () => {
      const res = await api.get<{ items: CampaignMomentumRow[] }>("/widgets/campaign-momentum", {
        params: query,
      });
      return res.data;
    },
  });
}

/* ── Under the radar ── */

export interface UnderReportedRow {
  entry_id: string;
  title: string;
  published_at: string | null;
  explanation: string;
  feeds_covering: number | null;
  cve_ids: string[];
  priority_score: number | null;
}

export function useUnderReported(params?: DateRangeParams & { limit?: number }) {
  const query = dateQuery(params);
  if (params?.limit) query.limit = params.limit;
  return useQuery({
    queryKey: ["widgets", "under-reported", query],
    queryFn: async () => {
      const res = await api.get<{ items: UnderReportedRow[] }>("/widgets/under-reported", { params: query });
      return res.data;
    },
  });
}

/* ── Morning briefing ── */

export interface MorningBriefingData {
  summary: string | null;
  generated_at: string | null;
  day_key: string | null;
}

export function useMorningBriefing() {
  return useQuery({
    queryKey: ["widgets", "morning-briefing"],
    queryFn: async () => {
      const res = await api.get<MorningBriefingData>("/widgets/morning-briefing");
      return res.data;
    },
  });
}

/* ── Relationship inbox ── */

export interface RelationshipInboxRow {
  id: string;
  source_type: string;
  source_id: string;
  source_name: string;
  relationship_type: string;
  target_type: string;
  target_id: string;
  target_name: string;
  evidence_count: number;
  created_at: string | null;
}

export interface RelationshipInboxData {
  ladder: { claimed: number; adjudicated: number; confirmed: number };
  items: RelationshipInboxRow[];
}

export function useRelationshipInbox(params?: DateRangeParams & { limit?: number }) {
  const query = dateQuery(params);
  if (params?.limit) query.limit = params.limit;
  return useQuery({
    queryKey: ["widgets", "relationship-inbox", query],
    queryFn: async () => {
      const res = await api.get<RelationshipInboxData>("/widgets/relationship-inbox", { params: query });
      return res.data;
    },
  });
}

/* ── Playbook drift ── */

export interface PlaybookDriftAddition {
  ttp_id: string;
  technique_id: string | null;
  technique_name: string | null;
  report_count: number;
}

export interface PlaybookDriftRow {
  actor_id: string;
  actor_name: string;
  known_count: number;
  additions: PlaybookDriftAddition[];
}

export interface PlaybookDriftData {
  items: PlaybookDriftRow[];
  total_new: number;
}

export function usePlaybookDrift(params?: DateRangeParams) {
  const query = dateQuery(params);
  return useQuery({
    queryKey: ["widgets", "playbook-drift", query],
    queryFn: async () => {
      const res = await api.get<PlaybookDriftData>("/widgets/playbook-drift", { params: query });
      return res.data;
    },
  });
}

/* ── Telemetry gaps (existing endpoint, first widget consumer) ── */

export interface TelemetryGapRule {
  rule_id: string;
  rule_title: string;
  rule_type: string;
  severity: string | null;
  is_draft: boolean;
  required_sources: string[];
  missing_sources: string[];
  /** Ratio 0–1 (note: /widgets/detection-coverage returns 0–100 instead). */
  coverage_pct: number;
}

export interface TelemetryGapsData {
  rules_with_gaps: TelemetryGapRule[];
  total_rules_checked: number;
  rules_with_gaps_count: number;
  /** [source_name, rule_count] pairs, most-needed first. */
  most_needed_sources: Array<[string, number]>;
}

export function useTelemetryGaps() {
  return useQuery({
    queryKey: ["widgets", "telemetry-gaps"],
    queryFn: async () => {
      const res = await api.get<TelemetryGapsData>("/telemetry-sources/telemetry-gaps");
      return res.data;
    },
  });
}
