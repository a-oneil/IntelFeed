// Client-side, approximate cost + latency hints for AI task buttons.
//
// These estimates are intentionally rough — they exist to give the analyst a
// sense of "how expensive / how slow" a one-shot task is before running it, not
// to bill anyone. Everything here is a heuristic.

import type { AITaskAssignment, AIProvider } from "@/api/types";
import { formatUsd } from "@/utils/format";

// Cost per 1M tokens (input, output) in USD.
// Mirrors the backend COST_TABLE in `backend/app/ai/engine.py`. Keep in sync if
// backend rates change. Matched by model-family substring (opus/sonnet/haiku)
// so date-suffixed model ids (e.g. "claude-haiku-4-5-20251001") still resolve.
const MODEL_COST: Record<"opus" | "sonnet" | "haiku", { in: number; out: number }> = {
  opus: { in: 15.0, out: 75.0 },
  sonnet: { in: 3.0, out: 15.0 },
  haiku: { in: 0.8, out: 4.0 },
};

// Rough latency band per model family (seconds) for a single one-shot task.
const MODEL_LATENCY: Record<"opus" | "sonnet" | "haiku", number> = {
  opus: 25,
  sonnet: 15,
  haiku: 6,
};

type ModelFamily = "opus" | "sonnet" | "haiku";

function modelFamily(modelName: string | undefined | null): ModelFamily | null {
  if (!modelName) return null;
  const m = modelName.toLowerCase();
  if (m.includes("opus")) return "opus";
  if (m.includes("sonnet")) return "sonnet";
  if (m.includes("haiku")) return "haiku";
  return null;
}

// Nominal token estimate per task category. Input tokens are dominated by the
// article/entity content we feed in; output by the response length. These are
// deliberate round numbers — a typical article summary vs. a full detection
// generation differ by roughly an order of magnitude in output.
function nominalTokens(category: string | null, taskName: string): { in: number; out: number } {
  // Generation tasks (detection rules, report sections) produce long output.
  if (category === "generation" || taskName === "detection_rules") {
    return { in: 6000, out: 2500 };
  }
  // Larger analysis tasks that reason over more context.
  if (taskName === "threat_assessment" || taskName === "detection_engineering_summary") {
    return { in: 6000, out: 1200 };
  }
  // Default analysis (summaries, briefings).
  return { in: 4000, out: 600 };
}

export interface TaskEstimate {
  /** Formatted hint like "~$0.01 · ~15s", or null when unassigned. */
  label: string | null;
  /** True when no assignment/model could be resolved (caller shows "not configured"). */
  unassigned: boolean;
}

function formatCost(usd: number): string {
  if (usd < 0.01) return "<$0.01";
  return `~${formatUsd(usd)}`;
}

/**
 * Estimate cost + latency for a task given its assignment. Everything is
 * client-side and approximate. Returns `unassigned: true` when there's no
 * assignment or the model family isn't recognized (so we don't invent a cost).
 *
 * @param assignment  the task's AITaskAssignment (from useAllTaskAssignments), a personal
 *                    route's {provider_id, model_name} when the click runs on the user's own
 *                    key, or undefined
 * @param providers   AI providers list (from useAIProviders), used to detect the claude_code CLI
 */
export function estimateTask(
  category: string | null,
  taskName: string,
  assignment: Pick<AITaskAssignment, "provider_id" | "model_name"> | undefined,
  providers: AIProvider[] | undefined,
): TaskEstimate {
  if (!assignment) return { label: null, unassigned: true };

  const provider = providers?.find((p) => p.id === assignment.provider_id);
  const isClaudeCode = provider?.provider_type === "claude_code";

  const family = modelFamily(assignment.model_name);

  // Claude Code CLI: no per-token billing surfaced here (subscription/quota),
  // and latency is dominated by CLI spin-up. Show a time-only hint.
  if (isClaudeCode) {
    return { label: "~30–60s", unassigned: false };
  }

  if (!family) {
    // Assigned but unknown model — still not "configured cost", show a plain
    // time band and skip the dollar figure rather than guessing rates.
    return { label: "≈", unassigned: false };
  }

  const tokens = nominalTokens(category, taskName);
  const rates = MODEL_COST[family];
  const usd = (tokens.in / 1_000_000) * rates.in + (tokens.out / 1_000_000) * rates.out;
  const secs = MODEL_LATENCY[family];

  return { label: `${formatCost(usd)} · ~${secs}s`, unassigned: false };
}
