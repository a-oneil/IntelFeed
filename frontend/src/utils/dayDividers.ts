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

/**
 * A story-thread row, as far as day bucketing is concerned.
 *
 * Structural on purpose: `ThreadItem` lives in utils/threads, which already
 * imports this module, and a thread only owes the dividers a date.
 */
export interface DatedThreadItem {
  type: "thread";
  thread: { last_seen: string | null };
}

/** Anything a divider run can be injected into. */
export type DividerSource = DisplayItem | DatedThreadItem;

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

/**
 * The date a row sits under.
 *
 * A thread is dated by its most recent coverage, not its first: the story is
 * filed on the day it last said something, which is the day a reader scanning
 * dividers expects to find it under.
 */
function itemDate(item: DividerSource): Date | null {
  if (item.type === "thread") {
    if (!item.thread.last_seen) return null;
    const d = new Date(item.thread.last_seen);
    return isNaN(d.getTime()) ? null : d;
  }
  const e = item.type === "single" ? item.entry : (item.entries[0] ?? null);
  return e ? entryDate(e) : null;
}

/**
 * How many entries a row is worth in the day's count.
 *
 * A thread counts as one, not as the articles it swallowed: those articles are
 * spread across the whole run of the story, and crediting all of them to the
 * day of its last beat would inflate that day past what is on screen.
 */
function entryCountOf(item: DividerSource): number {
  if (item.type === "thread") return 1;
  return item.type === "single" ? 1 : item.entries.length;
}

export function injectDayDividers<T extends DividerSource>(
  items: T[],
  enabled: boolean,
): (T | DayDividerItem)[] {
  if (!enabled || items.length === 0) return items;

  const now = new Date();
  const todayKey = dayKeyOf(now);
  const yesterday = new Date(now);
  yesterday.setDate(yesterday.getDate() - 1);
  const yesterdayKey = dayKeyOf(yesterday);
  const nowYear = now.getFullYear();

  const dayKeys: (string | null)[] = items.map((it) => {
    const d = itemDate(it);
    return d ? dayKeyOf(d) : null;
  });

  const counts: Record<string, number> = {};
  for (let i = 0; i < items.length; i++) {
    const k = dayKeys[i];
    if (!k) continue;
    counts[k] = (counts[k] ?? 0) + entryCountOf(items[i]);
  }

  const result: (T | DayDividerItem)[] = [];
  let lastKey: string | null = null;
  let entryIndex = 0;
  for (let i = 0; i < items.length; i++) {
    const key = dayKeys[i];
    if (key && key !== lastKey) {
      const d = itemDate(items[i]);
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

/** Hide rows that fall under a collapsed day; dividers stay visible. */
export function filterCollapsedDays<T extends DividerSource | DayDividerItem>(
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
