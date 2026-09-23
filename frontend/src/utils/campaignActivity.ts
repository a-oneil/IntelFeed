/**
 * A campaign nobody has added to in this long has stopped being tracked, whether
 * or not its status says so. Two months is roughly when a story that is still
 * running would have produced something.
 */
export const QUIET_AFTER_DAYS = 60;

/** Days since the campaign's newest article, or null when it holds none. */
export function daysQuiet(lastActivityAt: string | null | undefined, now: number = Date.now()): number | null {
  if (!lastActivityAt) return null;
  const last = new Date(lastActivityAt).getTime();
  if (Number.isNaN(last)) return null;
  return Math.floor((now - last) / 86_400_000);
}

/** True when an open campaign has gone quiet long enough to be worth closing. */
export function isCampaignQuiet(status: string, lastActivityAt: string | null | undefined, now?: number): boolean {
  const quiet = daysQuiet(lastActivityAt, now);
  return quiet !== null && quiet >= QUIET_AFTER_DAYS && ["active", "monitoring"].includes(status);
}
