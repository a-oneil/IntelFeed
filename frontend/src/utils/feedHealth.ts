import type { FeedHealthWarning, FeedPauseReason } from "@/api/types";

function shortUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.host}${u.pathname === "/" ? "" : u.pathname}`;
  } catch {
    return url;
  }
}

/**
 * "Paused automatically after HTTP 403 for 30 days (412 failed fetches)".
 * A feed paused by a person has no pause_reason and just reads "Paused".
 */
export function describePauseReason(reason: FeedPauseReason): string {
  const what = reason.last_error || "repeated errors";
  const span = reason.days != null ? ` for ${reason.days} day${reason.days === 1 ? "" : "s"}` : "";
  const count =
    reason.failures != null
      ? ` (${reason.failures} failed fetch${reason.failures === 1 ? "" : "es"})`
      : "";
  return `Paused automatically after ${what}${span}${count}`;
}

/** "Redirects to example.com/services and has no articles" / "No articles in the feed for 5 days". */
export function describeHealthWarning(warning: FeedHealthWarning): string {
  if (warning.kind === "redirected_no_items" && warning.redirected_to) {
    return `Reachable but empty: redirects to ${shortUrl(warning.redirected_to)}, which has no articles`;
  }
  return `Reachable but empty: no articles in the feed for ${warning.days} day${warning.days === 1 ? "" : "s"}`;
}
