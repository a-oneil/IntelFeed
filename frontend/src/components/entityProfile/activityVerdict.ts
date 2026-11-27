/** activityVerdict: a short phrase describing the trend of the last 90 days of reporting, computed from the daily mentions series. The header's Active / Dormant chip only looks at the last sighting, so a group with a burst of reporting in September and none in November still shows "Active" there; this compares the last 21 days against the days before them instead. */
import type { MentionsTimeseriesPoint } from "@/hooks/useEntityProfile";

/** The recent stretch compared against everything before it. */
const RECENT_DAYS = 21;

export type ActivityTone = "rising" | "steady" | "cooling" | "quiet" | "new";

export interface ActivityVerdict {
  tone: ActivityTone;
  label: string;
  detail: string;
}

const MONTH = new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", timeZone: "UTC" });

export function activityVerdict(points: MentionsTimeseriesPoint[] | undefined): ActivityVerdict | null {
  if (!points || points.length < RECENT_DAYS * 2) return null;
  const counts = points.map((p) => p.count);
  const recent = counts.slice(-RECENT_DAYS);
  const before = counts.slice(0, -RECENT_DAYS);
  const recentTotal = recent.reduce((a, b) => a + b, 0);
  const beforeTotal = before.reduce((a, b) => a + b, 0);

  const n = (k: number) => `${k} article${k === 1 ? "" : "s"}`;
  if (recentTotal === 0 && beforeTotal === 0) {
    return { tone: "quiet", label: "No recent reporting", detail: "No articles in the last 90 days" };
  }
  if (beforeTotal === 0) {
    return { tone: "new", label: "Newly reported", detail: `First reported in the last 3 weeks: ${n(recentTotal)}` };
  }

  // Per-day rates, so a 21-day stretch compares fairly with the 69 before it.
  const recentRate = recentTotal / recent.length;
  const beforeRate = beforeTotal / before.length;
  const ratio = recentRate / beforeRate;

  let peakAt = 0;
  counts.forEach((c, i) => {
    if (c > counts[peakAt]) peakAt = i;
  });
  const peakDate = points[peakAt]?.date ? MONTH.format(new Date(points[peakAt].date)) : null;
  const peak = peakDate ? `The busiest day was ${peakDate}, with ${n(counts[peakAt])}.` : "";

  if (recentTotal === 0) {
    return { tone: "quiet", label: "No recent reporting", detail: `No articles in the last 3 weeks. ${peak}`.trim() };
  }
  if (ratio <= 0.4) {
    return {
      tone: "cooling",
      label: "Less reporting than before",
      detail: `${n(recentTotal)} in the last 3 weeks, fewer than in the weeks before. ${peak}`.trim(),
    };
  }
  if (ratio >= 1.6) {
    return {
      tone: "rising",
      label: "More reporting than before",
      detail: `${n(recentTotal)} in the last 3 weeks, about ${Math.round(ratio)} times the daily rate of the weeks before`,
    };
  }
  return { tone: "steady", label: "Steady reporting", detail: `${n(recentTotal)} in the last 3 weeks, about the same rate as before` };
}
