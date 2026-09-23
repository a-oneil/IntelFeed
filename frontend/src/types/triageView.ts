import type { TimeRange } from "@/components/TimeRangeSelector";

/**
 * Property-order-insensitive deep equality for plain JSON-shaped values
 * (objects, arrays, primitives, null). Avoids the JSON.stringify pitfall
 * where `{a:1,b:2}` and `{b:2,a:1}` serialize differently.
 */
function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a === null || b === null) return a === b;
  if (typeof a !== typeof b) return false;
  if (typeof a !== "object") return false;
  if (Array.isArray(a)) {
    if (!Array.isArray(b) || a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!deepEqual(a[i], b[i])) return false;
    }
    return true;
  }
  if (Array.isArray(b)) return false;
  const aObj = a as Record<string, unknown>;
  const bObj = b as Record<string, unknown>;
  const aKeys = Object.keys(aObj);
  const bKeys = Object.keys(bObj);
  if (aKeys.length !== bKeys.length) return false;
  for (const k of aKeys) {
    if (!Object.prototype.hasOwnProperty.call(bObj, k)) return false;
    if (!deepEqual(aObj[k], bObj[k])) return false;
  }
  return true;
}

export type TriageWidgetName = "correlations" | "convergence";

export type CorrelationFilter = "smart" | "unread" | "all";
export type CorrelationSeverity = "" | "high" | "medium" | "low";

export interface CorrelationsWidgetConfig {
  collapsed: boolean;
  filter: CorrelationFilter;
  severity: CorrelationSeverity;
  event_types: string[];
  entity_type: string;
}

export interface ConvergenceWidgetConfig {
  collapsed: boolean;
  window_hours: number;
  min_shared: number;
}

export interface TriageWidgetsConfig {
  correlations: CorrelationsWidgetConfig;
  convergence: ConvergenceWidgetConfig;
}

export interface TriageView {
  global_range: TimeRange;
  global_custom_start?: string | null;
  global_custom_end?: string | null;
  widgets: TriageWidgetsConfig;
}

export interface BuildDefaultViewOptions {
  convergenceWindowHours?: number;
  convergenceMinShared?: number;
}

export function buildDefaultView(opts: BuildDefaultViewOptions = {}): TriageView {
  return {
    global_range: "7d",
    widgets: {
      correlations: {
        collapsed: true,
        filter: "smart",
        severity: "",
        event_types: [],
        entity_type: "",
      },
      convergence: {
        collapsed: false,
        window_hours: opts.convergenceWindowHours ?? 24,
        min_shared: opts.convergenceMinShared ?? 2,
      },
    },
  };
}

function mergeWithDefault(raw: unknown, defaults: TriageView): TriageView {
  if (!raw || typeof raw !== "object") return defaults;
  const r = raw as Partial<TriageView> & { widgets?: Partial<TriageWidgetsConfig> };
  const widgets: Partial<TriageWidgetsConfig> = r.widgets ?? {};
  const correlations: Partial<CorrelationsWidgetConfig> = widgets.correlations ?? {};
  return {
    global_range: r.global_range ?? defaults.global_range,
    global_custom_start: r.global_custom_start ?? null,
    global_custom_end: r.global_custom_end ?? null,
    widgets: {
      correlations: {
        ...defaults.widgets.correlations,
        ...correlations,
        event_types: Array.isArray(correlations.event_types)
          ? correlations.event_types
          : defaults.widgets.correlations.event_types,
      },
      convergence: { ...defaults.widgets.convergence, ...(widgets.convergence ?? {}) },
    },
  };
}

export function getSavedTriageView(
  userSettings: Record<string, unknown> | undefined,
  opts: BuildDefaultViewOptions = {},
): TriageView {
  const defaults = buildDefaultView(opts);
  return mergeWithDefault(userSettings?.triage_view, defaults);
}

/**
 * Normalize a raw (possibly stale) triage view to the current canonical shape —
 * drops removed widget keys (e.g. legacy `atlas`/`priority`) and fills any
 * missing defaults. Used when rehydrating the persisted store so it matches the
 * server-normalized view and doesn't trigger a spurious auto-save on mount.
 */
export function normalizeTriageView(raw: unknown, opts: BuildDefaultViewOptions = {}): TriageView {
  return mergeWithDefault(raw, buildDefaultView(opts));
}

/**
 * Days mapping used by Priority Queue / Convergence which want a number, not a TimeRange.
 * Custom ranges fall back to a sensible default since those endpoints don't support
 * arbitrary windows yet.
 */
export function rangeToDays(range: TimeRange): number {
  switch (range) {
    case "24h":
      return 1;
    case "7d":
      return 7;
    case "30d":
      return 30;
    case "90d":
      return 90;
    case "1y":
      return 365;
    case "all":
      return 36500;
    case "custom":
      return 7;
  }
}

export function viewsEqual(a: TriageView, b: TriageView): boolean {
  if (a.global_range !== b.global_range) return false;
  if ((a.global_custom_start ?? null) !== (b.global_custom_start ?? null)) return false;
  if ((a.global_custom_end ?? null) !== (b.global_custom_end ?? null)) return false;
  return deepEqual(a.widgets, b.widgets);
}

/* ── Saved triage / convergence tuning (user settings) ── */

export interface TriageSettings {
  pir_weight: number;
  correlation_weight: number;
  automation_weight: number;
  min_priority_score: number;
}

export interface ClusterSettings {
  days: number;
  window_hours: number;
  min_shared_entities: number;
}

export const DEFAULT_TRIAGE_SETTINGS: TriageSettings = {
  pir_weight: 10,
  correlation_weight: 3,
  automation_weight: 1,
  min_priority_score: 3,
};

export const DEFAULT_CLUSTER_SETTINGS: ClusterSettings = {
  days: 7,
  window_hours: 24,
  min_shared_entities: 2,
};

export function getSavedTriageSettings(userSettings: Record<string, unknown> | undefined): TriageSettings {
  const saved = userSettings?.triage_settings;
  if (saved && typeof saved === "object") {
    return { ...DEFAULT_TRIAGE_SETTINGS, ...(saved as Partial<TriageSettings>) };
  }
  return { ...DEFAULT_TRIAGE_SETTINGS };
}

export function getSavedClusterSettings(userSettings: Record<string, unknown> | undefined): ClusterSettings {
  const saved = userSettings?.cluster_settings;
  if (saved && typeof saved === "object") {
    return { ...DEFAULT_CLUSTER_SETTINGS, ...(saved as Partial<ClusterSettings>) };
  }
  return { ...DEFAULT_CLUSTER_SETTINGS };
}
