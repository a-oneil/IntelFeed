import type { Entry } from "@/api/types";
import type { DisplayItem } from "./groupEntries";

export interface DayDividerItem {
  type: "divider";
  dayKey: string;
  label: string;
  dayCount: number;
  cumulativeIndex: number;
}

export type DisplayItemWithDividers = DisplayItem | DayDividerItem;

function dayKeyOf(date: Date): string {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const d = String(date.getDate()).padStart(2, "0");
  return `${y}-${m}-${d}`;
}

function labelOf(date: Date, todayKey: string, yesterdayKey: string, nowYear: number): string {
  const k = dayKeyOf(date);
  if (k === todayKey) return "Today";
  if (k === yesterdayKey) return "Yesterday";
  const sameYear = date.getFullYear() === nowYear;
  return date.toLocaleDateString("en-US", {
    weekday: "short",
    month: "short",
    day: "numeric",
    ...(sameYear ? {} : { year: "numeric" }),
  });
}

function entryDate(entry: Entry): Date | null {
  const raw = entry.published_at;
  if (!raw) return null;
  const d = new Date(raw);
  if (isNaN(d.getTime())) return null;
  return d;
}

function representativeEntry(item: DisplayItem): Entry | null {
  if (item.type === "single") return item.entry;
  return item.entries[0] ?? null;
}

function entryCountOf(item: DisplayItem): number {
  return item.type === "single" ? 1 : item.entries.length;
}

export function injectDayDividers(
  items: DisplayItem[],
  enabled: boolean,
): DisplayItemWithDividers[] {
  if (!enabled || items.length === 0) return items;

  const now = new Date();
  const todayKey = dayKeyOf(now);
  const yesterday = new Date(now);
  yesterday.setDate(yesterday.getDate() - 1);
  const yesterdayKey = dayKeyOf(yesterday);
  const nowYear = now.getFullYear();

  const dayKeys: (string | null)[] = items.map((it) => {
    const e = representativeEntry(it);
    const d = e ? entryDate(e) : null;
    return d ? dayKeyOf(d) : null;
  });

  const counts: Record<string, number> = {};
  for (let i = 0; i < items.length; i++) {
    const k = dayKeys[i];
    if (!k) continue;
    counts[k] = (counts[k] ?? 0) + entryCountOf(items[i]);
  }

  const result: DisplayItemWithDividers[] = [];
  let lastKey: string | null = null;
  let entryIndex = 0;
  for (let i = 0; i < items.length; i++) {
    const key = dayKeys[i];
    if (key && key !== lastKey) {
      const e = representativeEntry(items[i]);
      const d = e ? entryDate(e) : null;
      if (d) {
        result.push({
          type: "divider",
          dayKey: key,
          label: labelOf(d, todayKey, yesterdayKey, nowYear),
          dayCount: counts[key] ?? 0,
          cumulativeIndex: entryIndex,
        });
      }
      lastKey = key;
    }
    result.push(items[i]);
    entryIndex += entryCountOf(items[i]);
  }
  return result;
}

/** Hide entries that fall under a collapsed day; dividers stay visible. */
export function filterCollapsedDays<T extends DisplayItemWithDividers>(
  items: T[],
  collapsedDays: Set<string>,
): T[] {
  if (collapsedDays.size === 0) return items;
  const out: T[] = [];
  let currentDayKey: string | null = null;
  for (const item of items) {
    if (item.type === "divider") {
      currentDayKey = item.dayKey;
      out.push(item);
    } else if (!currentDayKey || !collapsedDays.has(currentDayKey)) {
      out.push(item);
    }
  }
  return out;
}
