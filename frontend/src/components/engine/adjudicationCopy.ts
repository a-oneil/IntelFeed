/** Why the AI analysis or the adjudicate stage didn't run (or ran and found
 *  nothing to do), in plain words. Gate codes come from `enqueue_entry_analysis`
 *  and `enqueue_adjudication`; the rest from the review task's `detail.skipped`. */
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
  junk: "looks like non-security chatter (junk gate)",
  feed_ai: "the feed's AI analysis toggle is off",
  feed_none: "the feed's extraction mode is none",
  analysis_disabled: "AI analysis is switched off",
};

export function skipReason(code: string): string {
  return SKIP_REASONS[code] ?? code.replace(/_/g, " ");
}

/** What a queued stage cell is waiting for, in plain words. */
export function waitingOn(cell: { detail?: { waiting_on?: string } | null }): string {
  switch (cell.detail?.waiting_on) {
    case "analysis":
      return "waiting on the AI analysis it reviews";
    case "submit":
      return "waiting to be sent to the AI worker";
    default:
      return "waiting on the AI worker";
  }
}
