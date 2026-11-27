import { currentReadingPrefs } from "@/hooks/useReadingPrefs";

type DateInput = string | Date | null | undefined;

function getDateFormat(): "relative" | "absolute" | "both" {
  return currentReadingPrefs().date_format;
}

function toAbsolute(date: Date): string {
  return date.toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

/** "2h ago" regardless of the date_format preference, for labels that must stay short. */
export function formatRelative(input: DateInput, fallback = ""): string {
  if (!input) return fallback;
  const date = input instanceof Date ? input : new Date(input);
  return isNaN(date.getTime()) ? fallback : toRelative(date);
}

function toRelative(date: Date): string {
  const now = new Date();
  const diff = now.getTime() - date.getTime();
  if (diff < 0) return "Just now";
  if (diff < 60000) return "Just now";
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  if (diff < 2592000000) return `${Math.floor(diff / 86400000)}d ago`;
  return toAbsolute(date);
}

/** "Oct 13, 2026 (2d ago)" — past 30 days the relative form is the date itself, so drop it. */
function withRelative(absolute: string, date: Date): string {
  const relative = toRelative(date);
  return relative === toAbsolute(date) ? absolute : `${absolute} (${relative})`;
}

/** Format a date according to the user's date_format setting. Returns `fallback` (default "") for null/undefined, and an unparseable string as-is. */
export function formatDate(input: DateInput, fallback = ""): string {
  if (!input) return fallback;
  const date = input instanceof Date ? input : new Date(input);
  if (isNaN(date.getTime())) return typeof input === "string" ? input : fallback;

  const fmt = getDateFormat();
  switch (fmt) {
    case "absolute":
      return toAbsolute(date);
    case "both":
      return withRelative(toAbsolute(date), date);
    case "relative":
    default:
      return toRelative(date);
  }
}

/** Format a date with time (for timestamps that need more precision). */
export function formatDateTime(input: DateInput, fallback = ""): string {
  if (!input) return fallback;
  const date = input instanceof Date ? input : new Date(input);
  if (isNaN(date.getTime())) return typeof input === "string" ? input : fallback;

  const fmt = getDateFormat();
  const absolute = date.toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });

  switch (fmt) {
    case "absolute":
      return absolute;
    case "both":
      return withRelative(absolute, date);
    case "relative":
    default:
      return toRelative(date);
  }
}

/** A compact timestamp for dense tables ("Nov 21, 1:26 PM"): the date and time without the year or the relative part. Put the full formatDateTime() on the cell's title. */
export function formatShortDateTime(input: DateInput, fallback = ""): string {
  if (!input) return fallback;
  const date = input instanceof Date ? input : new Date(input);
  if (isNaN(date.getTime())) return typeof input === "string" ? input : fallback;
  return date.toLocaleString("en-US", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}
