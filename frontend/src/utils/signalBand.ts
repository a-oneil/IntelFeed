// Single source of truth for how a signal-engine priority score maps to a
// color band. Used by SignalChip (entry list / reader) and the Priority Queue
// badge so the same score always reads as the same band + color everywhere.

export type SignalBand = "high" | "medium" | "low";

// A score at or above each threshold lands in that band. Scores run 0–10,
// ranked against the last 30 days: 8.5 is roughly the top 8% of entries with
// signals, 9.5 the top 3%.
export const SIGNAL_BAND_THRESHOLDS = { high: 9.5, medium: 8.5 } as const;

export const SIGNAL_BAND_LABEL: Record<SignalBand, string> = {
  high: "High",
  medium: "Medium",
  low: "Low",
};

export function signalBand(score: number): SignalBand {
  if (score >= SIGNAL_BAND_THRESHOLDS.high) return "high";
  if (score >= SIGNAL_BAND_THRESHOLDS.medium) return "medium";
  return "low";
}
