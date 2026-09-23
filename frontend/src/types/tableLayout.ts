import type { TableLayout } from "@/stores/uiStore";

/**
 * The slice of a DataTable's state that follows the user across devices,
 * stored server-side under `user.settings.table_layouts`.
 *
 * Deliberately layout-only: which columns are shown, how wide, in what order.
 * Active filters and the client sort stay device-local — those are transient
 * "what am I looking at right now" state, and pushing one device's search box
 * onto another is surprising rather than helpful.
 */
export interface SharedTableLayout {
  columnVisibility: Record<string, boolean>;
  columnWidths: Record<string, number>;
  columnOrder: string[];
  /** Epoch ms of the last layout edit — the tiebreaker when two devices differ. */
  updatedAt: number;
}

/** Keyed by DataTable id ("entries", "entity:threat_actor", ...). */
export type TableLayoutMap = Record<string, SharedTableLayout>;

export const TABLE_LAYOUTS_SETTINGS_KEY = "table_layouts";

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/** Keep only the entries of a record whose values pass `ok`. */
function filterRecord<T>(raw: unknown, ok: (v: unknown) => v is T): Record<string, T> {
  if (!isPlainObject(raw)) return {};
  const out: Record<string, T> = {};
  for (const [k, v] of Object.entries(raw)) if (ok(v)) out[k] = v;
  return out;
}

const isBool = (v: unknown): v is boolean => typeof v === "boolean";
const isFiniteNumber = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);

/**
 * Sanitize one layout coming back from the server. The settings blob is
 * free-form JSON that any client can write, so nothing here is trusted —
 * bad shapes degrade to the default rather than crashing the table.
 */
function parseLayout(raw: unknown): SharedTableLayout | null {
  if (!isPlainObject(raw)) return null;
  const order = Array.isArray(raw.columnOrder)
    ? raw.columnOrder.filter((k): k is string => typeof k === "string")
    : [];
  return {
    columnVisibility: filterRecord(raw.columnVisibility, isBool),
    columnWidths: filterRecord(raw.columnWidths, isFiniteNumber),
    columnOrder: order,
    updatedAt: isFiniteNumber(raw.updatedAt) ? raw.updatedAt : 0,
  };
}

/** Read + sanitize the layout map out of a user's settings blob. */
export function parseTableLayouts(userSettings: Record<string, unknown> | undefined): TableLayoutMap {
  const raw = userSettings?.[TABLE_LAYOUTS_SETTINGS_KEY];
  if (!isPlainObject(raw)) return {};
  const out: TableLayoutMap = {};
  for (const [tableId, value] of Object.entries(raw)) {
    const parsed = parseLayout(value);
    if (parsed) out[tableId] = parsed;
  }
  return out;
}

const isDefaultLayout = (l: SharedTableLayout) =>
  Object.keys(l.columnVisibility).length === 0 &&
  Object.keys(l.columnWidths).length === 0 &&
  l.columnOrder.length === 0;

/**
 * Project the store's per-table state down to the shareable layout map.
 * Untouched tables (all defaults, never stamped) are dropped so the settings
 * blob only carries layouts the user actually arranged — but a stamped empty
 * layout is kept, since that's how a "reset columns" propagates to other devices.
 */
export function toTableLayoutMap(tables: Record<string, TableLayout>): TableLayoutMap {
  const out: TableLayoutMap = {};
  for (const [tableId, t] of Object.entries(tables)) {
    const layout: SharedTableLayout = {
      columnVisibility: t.columnVisibility,
      columnWidths: t.columnWidths,
      columnOrder: t.columnOrder,
      updatedAt: t.layoutUpdatedAt ?? 0,
    };
    if (layout.updatedAt === 0 && isDefaultLayout(layout)) continue;
    out[tableId] = layout;
  }
  return out;
}

function recordsEqual(a: Record<string, unknown>, b: Record<string, unknown>): boolean {
  const aKeys = Object.keys(a);
  if (aKeys.length !== Object.keys(b).length) return false;
  return aKeys.every((k) => Object.prototype.hasOwnProperty.call(b, k) && a[k] === b[k]);
}

export function layoutsEqual(a: SharedTableLayout, b: SharedTableLayout): boolean {
  return (
    a.updatedAt === b.updatedAt &&
    a.columnOrder.length === b.columnOrder.length &&
    a.columnOrder.every((k, i) => k === b.columnOrder[i]) &&
    recordsEqual(a.columnVisibility, b.columnVisibility) &&
    recordsEqual(a.columnWidths, b.columnWidths)
  );
}

/** True when two maps carry the same layouts — used to skip no-op saves. */
export function layoutMapsEqual(a: TableLayoutMap, b: TableLayoutMap): boolean {
  const aKeys = Object.keys(a);
  if (aKeys.length !== Object.keys(b).length) return false;
  return aKeys.every((k) => b[k] !== undefined && layoutsEqual(a[k], b[k]));
}
