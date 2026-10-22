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

/**
 * Format a date according to the user's date_format setting.
 * Returns empty string for null/undefined/invalid input.
 */
export function formatDate(input: DateInput, fallback = ""): string {
  if (!input) return fallback;
  const date = input instanceof Date ? input : new Date(input);
  if (isNaN(date.getTime())) return typeof input === "string" ? input : fallback;

  const fmt = getDateFormat();
  switch (fmt) {
    case "absolute":
      return toAbsolute(date);
    case "both":
      return `${toAbsolute(date)} (${toRelative(date)})`;
    case "relative":
    default:
      return toRelative(date);
  }
}

/**
 * Format a date with time (for timestamps that need more precision).
 */
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
      return `${absolute} (${toRelative(date)})`;
    case "relative":
    default:
      return toRelative(date);
  }
}
