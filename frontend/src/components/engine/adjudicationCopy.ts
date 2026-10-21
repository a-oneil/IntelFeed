/** Why the adjudicate stage didn't run (or ran and found nothing to do), in
 *  plain words. Gate codes come from `enqueue_adjudication`; the rest from the
 *  task's own `detail.skipped`. */
export const SKIP_REASONS: Record<string, string> = {
  off: "adjudication is off",
  plan: "plan turns the stage off for this feed",
  echo: "analysis reused from a near-duplicate",
  nothing_new: "nothing new in this run (created trigger)",
  score: "below the score floor",
  budget: "waiting: hourly budget",
  paused: "waiting: provider paused",
  locked: "another review held the lock",
  already_reviewed: "already reviewed — duplicate dispatch, nothing re-run",
  nothing_to_review: "nothing to review",
  provider_paused: "waiting: provider paused",
  ai_parse_error: "model returned unusable JSON",
  ai_provider_error: "provider error",
  ai_bad_shape: "duplicate item ids; all kept",
  no_analysis: "no analysis to review",
};

export function skipReason(code: string): string {
  return SKIP_REASONS[code] ?? code.replace(/_/g, " ");
}
