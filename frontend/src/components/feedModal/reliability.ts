/**
 * What a feed's reliability rating does to the tags its articles get.
 *
 * Mirrors the backend exactly: `_reliability_to_weight` in
 * workers/intel_feed_tasks.py (A 1.0, B .85, C .7, D .5, E .3, F .15, unrated
 * .5) multiplies a catalog match's confidence (a canonical name 0.9, an alias
 * 0.5), and `_weighted_confidence` in intelligence/autolinker.py buckets the
 * product at ≥0.7 high, ≥0.4 medium, else low. So a canonical-name match
 * reaches "high" only from an A or B feed, stays "medium" from C, D or an
 * unrated feed, and drops to "low" from E or F; an alias match is one step
 * lower. The rating does not touch the AI's own tags.
 */
const WEIGHTS: Record<string, number> = { A: 1.0, B: 0.85, C: 0.7, D: 0.5, E: 0.3, F: 0.15 };
const UNRATED_WEIGHT = 0.5;
const CANONICAL_CONFIDENCE = 0.9;

export type TagCeiling = "high" | "medium" | "low";

export function tagCeiling(rating: string | null | undefined): TagCeiling {
  const weight = (rating && WEIGHTS[rating]) || UNRATED_WEIGHT;
  const score = CANONICAL_CONFIDENCE * weight;
  if (score >= 0.7) return "high";
  if (score >= 0.4) return "medium";
  return "low";
}

/** One sentence for the Pipeline pane. */
export function reliabilityNote(rating: string | null | undefined): string {
  const ceiling = tagCeiling(rating);
  const who = rating ? `Rated ${rating}` : "Unrated";
  if (ceiling === "high") {
    return `${who}: catalog-matched tags from this feed can be high confidence.`;
  }
  const hint = rating
    ? ""
    : " An unrated feed counts the same as a D. Rate it A or B under Assessment to allow high.";
  return `${who}: catalog-matched tags from this feed top out at ${ceiling}.${hint}`;
}
