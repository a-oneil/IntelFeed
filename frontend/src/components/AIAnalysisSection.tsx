import { useState } from "react";
import { Link } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import {
  useAITasks,
  useRunAIOnEntry,
  useRunAIOnEntity,
  useAllTaskAssignments,
  useAIProviders,
  useMyAI,
  useMyAIPolicy,
} from "@/hooks/useAI";
import { useAuthStore } from "@/stores/authStore";
import type { AITask, UserAIOverview, UserAIPolicyStatus, UserAIPromptRow } from "@/api/types";
import { estimateTask } from "@/utils/aiTaskEstimate";
import { apiErrorInfo, apiErrorReason } from "@/api/errors";
import { blockedReasonShort, fallbackFixLabel, isCapReason } from "@/utils/aiProvenance";
import styles from "./AIAnalysisSection.module.css";

// Tasks that need a special UI instead of one-click run (Ask Agent chat lives
// in the AI panel action bar, not as a task row).
const CHAT_TASKS = new Set(["entry_qa"]);

// Steerable one-shots: tasks that accept an optional "focus" to shape output.
const FOCUSABLE_TASKS = new Set([
  "article_summary",
  "intelligence_briefing",
  "threat_assessment",
  "daily_summary",
  "video_transcript_summary",
]);

// Categories that never make sense as per-article action buttons.
export const NON_ENTRY_CATEGORIES = new Set(["extraction", "maintenance", "validation"]);

const GROUPS: Array<{ key: string; label: string; match: (category: string | null) => boolean }> = [
  { key: "analysis", label: "Analyze", match: (c) => c === "analysis" },
  { key: "generation", label: "Generate", match: (c) => c === "generation" },
  { key: "custom", label: "Custom", match: (c) => c !== "analysis" && c !== "generation" && !NON_ENTRY_CATEGORIES.has(c ?? "") },
];

export interface RunTaskResult {
  task_name: string;
  entry_id: string;
  result: Record<string, unknown>;
  model_name: string | null;
  cost_estimate: string | null;
  /** Share pages only: what the link may still run today after this call. */
  remaining_today?: number | null;
}

/** What a click on a task row does, said before the click. */
export interface RowRun {
  /** "user": the person's key; "site": the instance's provider; "refused": the policy stops it. */
  on: "user" | "site" | "refused";
  /** Why the person's key can't answer, when it can't (null when it can, or when there is none to speak of). */
  reason: string | null;
  /** The personal route that would answer, for the estimate. */
  route: { provider_id: string; model_name: string | null } | null;
  /** Whether the row says anything about keys at all (false = plain instance estimate, no dot). */
  aware: boolean;
}

/**
 * Where a click runs, from the overview row when there is one. Without an
 * overview (the policy says this person has no routes, so it is never
 * fetched) the policy alone answers: a required key that is missing refuses
 * every eligible task; otherwise the instance's provider answers quietly.
 */
export function rowRun(
  task: AITask,
  policy: UserAIPolicyStatus | undefined,
  overview: UserAIOverview | undefined,
): RowRun {
  const none: RowRun = { on: "site", reason: null, route: null, aware: false };
  if (!policy?.allow_user_ai_providers) return none;
  const row: UserAIPromptRow | undefined = overview?.policy.allow_user_ai_providers
    ? overview.tasks.find((t) => t.task_name === task.name)
    : undefined;
  if (row) {
    const myRoute = row.route ?? overview?.default_route ?? null;
    const routed = !!myRoute && myRoute.provider_id !== null;
    // Older servers send no verdict; then a routed key is what answers.
    const on = row.will_run_on ?? (routed ? "user" : "site");
    const reason = row.blocked_reason ?? null;
    return {
      on,
      reason,
      route: on === "user" && routed ? { provider_id: myRoute.provider_id as string, model_name: myRoute.model_name } : null,
      aware: true,
    };
  }
  if (!policy.has_routes && task.allows_user_provider) {
    return policy.require_user_ai_provider
      ? { on: "refused", reason: "no_key", route: null, aware: true }
      : { on: "site", reason: null, route: null, aware: false };
  }
  return none;
}

interface AIAnalysisSectionProps {
  /** Entry target (reader AI panel). Omit when targeting an entity. */
  entryId?: string;
  /** Entity target (entity profile AI tab) — backend target_type, e.g. "threat_actor". */
  entityType?: string;
  entityId?: string;
  /** Pre-loaded tasks list (skips useAITasks hook when provided) */
  tasks?: AITask[];
  /** Custom run function (skips useRunAIOnEntry hook when provided) */
  runTaskFn?: (taskName: string, focus?: string) => Promise<RunTaskResult>;
  /** Tasks that already have results — shown as completed & disabled */
  completedTasks?: Set<string>;
  /** Called after a task completes so the parent can refresh results display */
  onTaskComplete?: (data: RunTaskResult) => void;
}

/** Pick a glyph for the task's icon tile (by name keyword, then category). */
function taskGlyph(task: AITask): string {
  const n = task.name.toLowerCase();
  if (n.includes("summary")) return "\u2261"; // ≡
  if (n.includes("briefing") || n.includes("brief")) return "\u2630"; // ☰
  if (n.includes("assessment") || n.includes("threat")) return "\u25EC"; // ◬
  if (n.includes("rule") || n.includes("detection")) return "\u2317"; // ⌗
  if (task.category === "generation") return "\u270E"; // ✎
  return "\u2261";
}

/** Sort within a group: explicit order first (ascending), then by display name. */
function taskSort(a: AITask, b: AITask): number {
  const ao = a.entry_action_order;
  const bo = b.entry_action_order;
  if (ao != null && bo != null && ao !== bo) return ao - bo;
  if (ao != null && bo == null) return -1;
  if (ao == null && bo != null) return 1;
  return a.display_name.localeCompare(b.display_name);
}

export function AIAnalysisSection({ entryId, entityType, entityId, tasks: tasksProp, runTaskFn, completedTasks, onTaskComplete }: AIAnalysisSectionProps) {
  const isEntity = !!entityType && !!entityId;
  const { data: hookTasks } = useAITasks();
  const hookRunTask = useRunAIOnEntry();
  const hookRunEntity = useRunAIOnEntity();
  const { data: assignments } = useAllTaskAssignments();
  // Unfiltered on purpose: the estimate looks up the site assignment's
  // provider or the person's own key, whichever will answer.
  const { data: providers } = useAIProviders();
  // Which tasks a click would run on the person's own key, so the row says so
  // before they click. The policy read is cheap and answers for most people:
  // personal keys off, or no routes, and the overview is never fetched.
  const signedIn = useAuthStore((s) => !!s.accessToken);
  const { data: myPolicy } = useMyAIPolicy(signedIn && !runTaskFn);
  const { data: myAI } = useMyAI(!!myPolicy?.allow_user_ai_providers && myPolicy.has_routes);
  const qc = useQueryClient();
  // The customize link targets the admin-only Settings > AI section.
  const isAdmin = useAuthStore((s) => s.user?.role === "admin");
  const [localCompleted, setLocalCompleted] = useState<Set<string>>(new Set());
  const [errors, setErrors] = useState<Record<string, { message: string; code: string | null; reason: string | null }>>({});
  const [runningTask, setRunningTask] = useState<string | null>(null);
  // Which task's focus field is open, and its current text.
  const [focusOpen, setFocusOpen] = useState<string | null>(null);
  const [focusText, setFocusText] = useState<Record<string, string>>({});

  const allTasks = tasksProp ?? hookTasks;

  // Action tasks: visibility is a per-task, per-surface setting (Settings > AI) —
  // articles and entity profiles toggle independently. Extraction and chat
  // tasks never render as rows.
  const isVisible = (t: AITask) =>
    isEntity ? (t.show_in_entity_actions ?? true) : (t.show_in_entry_actions ?? true);
  const actionTasks = (allTasks ?? []).filter(
    (t) =>
      !NON_ENTRY_CATEGORIES.has(t.category ?? "") &&
      !CHAT_TASKS.has(t.name) &&
      isVisible(t)
  );
  const hiddenCount = (allTasks ?? []).filter(
    (t) => !NON_ENTRY_CATEGORIES.has(t.category ?? "") && !CHAT_TASKS.has(t.name) && !isVisible(t)
  ).length;

  const handleRun = async (taskName: string) => {
    setRunningTask(taskName);
    setErrors((prev) => { const next = { ...prev }; delete next[taskName]; return next; });
    const focus = focusText[taskName]?.trim() || undefined;
    try {
      let data: RunTaskResult;
      if (runTaskFn) {
        data = await runTaskFn(taskName, focus);
      } else if (isEntity) {
        const res = await hookRunEntity.mutateAsync({
          targetType: entityType!,
          targetId: entityId!,
          taskName,
          ...(focus ? { focus } : {}),
        });
        data = { task_name: res.task_name, entry_id: "", result: res.result, model_name: null, cost_estimate: null };
      } else {
        data = await hookRunTask.mutateAsync({ entryId: entryId!, taskName, ...(focus ? { focus } : {}) });
      }
      // Mark as completed locally
      setLocalCompleted((prev) => new Set(prev).add(taskName));
      // Refresh detection rules list when rules are generated
      if (taskName === "detection_rules") {
        qc.invalidateQueries({ queryKey: ["detection-rules"] });
      }
      // Refresh persisted AI results so AIResultsDisplay picks up the new result
      qc.invalidateQueries({ queryKey: ["ai-results"] });
      // Notify parent
      onTaskComplete?.(data);
    } catch (err) {
      const info = apiErrorInfo(err);
      const msg = err instanceof Error ? err.message : "Prompt failed";
      let errorText = info.code ? info.message : msg;
      if (!info.code) {
        try {
          const parsed = JSON.parse(msg);
          errorText = parsed.message || parsed.detail || msg;
        } catch {
          if (msg.includes("422")) {
            errorText = "Not configured — assign a provider + model in Settings > AI";
          }
        }
      }
      setErrors((prev) => ({ ...prev, [taskName]: { message: errorText, code: info.code, reason: apiErrorReason(err) } }));
    } finally {
      setRunningTask(null);
    }
  };

  if (!actionTasks.length) return null;

  return (
    <div className={styles.container}>
      {GROUPS.map((group) => {
        const groupTasks = actionTasks.filter((t) => group.match(t.category)).sort(taskSort);
        if (!groupTasks.length) return null;
        return (
          <div key={group.key}>
            <div className={styles.groupLabel}>{group.label}</div>
            {groupTasks.map((task) => {
              const isCompleted = completedTasks?.has(task.name) || localCompleted.has(task.name);
              // Personal keys on: the row says what a click does before the
              // click, by the server's own verdict for this task.
              const run = rowRun(task, myPolicy, myAI);
              const onMyKey = run.on === "user";
              const refused = run.on === "refused";
              // Estimate from whatever will actually answer: the personal key's
              // provider + model when the click runs there, else the site assignment.
              const est = estimateTask(
                task.category,
                task.name,
                onMyKey
                  ? run.route && run.route.model_name
                    ? { provider_id: run.route.provider_id, model_name: run.route.model_name }
                    : undefined
                  : assignments?.[task.id],
                providers,
              );
              const blocked = run.on === "site" ? blockedReasonShort(run.reason) : null;
              const refusedLabel = refused ? (isCapReason(run.reason) ? "over cap" : "needs a key") : null;
              const canFocus = FOCUSABLE_TASKS.has(task.name);
              const isFocusOpen = focusOpen === task.name;
              const titleParts = [task.description || task.display_name];
              if (refused) {
                titleParts.push(
                  isCapReason(run.reason)
                    ? "Your key is over its cap and this instance requires your own key"
                    : "This instance requires your own key for this prompt",
                );
              } else if (est.unassigned && !onMyKey) {
                titleParts.push("Not configured — assign a provider + model in Settings > AI");
              } else if (est.label) {
                titleParts.push(`Estimated ${est.label}`);
              }
              if (run.aware && !refused && (onMyKey || !est.unassigned)) {
                titleParts.push(
                  onMyKey
                    ? "Runs on your own key"
                    : blocked
                      ? `Runs on the instance's provider — your ${blocked}`
                      : "Runs on the instance's provider",
                );
              }
              return (
                <div key={task.id}>
                  <div className={`${styles.taskRow} ${isCompleted ? styles.taskRowDone : ""}`}>
                    <button
                      className={styles.taskRowBtn}
                      onClick={() => handleRun(task.name)}
                      disabled={runningTask === task.name || isCompleted}
                      title={titleParts.join(" — ")}
                    >
                      <span className={styles.taskIcon}>
                        {runningTask === task.name ? <span className={styles.spinner} /> : taskGlyph(task)}
                      </span>
                      <span className={styles.taskName}>
                        {task.display_name}
                        {isCompleted && <span className={styles.check}> &#10003;</span>}
                      </span>
                      {refused ? (
                        <span className={`${styles.hint} ${styles.hintWarn}`}>{refusedLabel}</span>
                      ) : est.unassigned && !onMyKey ? (
                        <span className={styles.hintMuted}>not set</span>
                      ) : run.aware ? (
                        <span className={styles.hint}>
                          <span
                            className={`${styles.keyDot} ${onMyKey ? styles.keyDotMine : ""}`}
                            aria-label={onMyKey ? "your key" : "instance"}
                          />
                          {onMyKey ? "your key" : "instance"}
                          {blocked ? ` · ${blocked}` : est.label && !est.unassigned ? ` · ${est.label}` : ""}
                        </span>
                      ) : est.label ? (
                        <span className={styles.hint}>{est.label}</span>
                      ) : null}
                    </button>
                    {canFocus && (
                      <button
                        type="button"
                        className={`${styles.focusToggle} ${isFocusOpen || focusText[task.name] ? styles.focusToggleActive : ""}`}
                        onClick={() => setFocusOpen(isFocusOpen ? null : task.name)}
                        title="Add an optional focus to steer the output"
                        aria-label="Focus"
                      >
                        &#9672;{(isFocusOpen || focusText[task.name]) ? " focus" : ""}
                      </button>
                    )}
                  </div>
                  {canFocus && isFocusOpen && (
                    <input
                      type="text"
                      className={styles.focusInput}
                      placeholder="Focus (optional) — e.g. detection"
                      value={focusText[task.name] || ""}
                      onChange={(e) =>
                        setFocusText((prev) => ({ ...prev, [task.name]: e.target.value }))
                      }
                      onKeyDown={(e) => {
                        if (e.key === "Enter") { setFocusOpen(null); handleRun(task.name); }
                        if (e.key === "Escape") setFocusOpen(null);
                      }}
                      autoFocus
                    />
                  )}
                  {errors[task.name] && (
                    <div className={styles.error}>
                      {errors[task.name].message}
                      {errors[task.name].code === "user_ai_key_required" && (
                        <>
                          {" "}
                          <Link to="/settings?section=myai" className={styles.hiddenLink}>
                            {fallbackFixLabel(errors[task.name].reason)}
                          </Link>
                        </>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        );
      })}
      {hiddenCount > 0 && !tasksProp && isAdmin && (
        <div className={styles.hiddenNote}>
          {hiddenCount} hidden · <Link to="/settings?section=ai" className={styles.hiddenLink}>Customize buttons…</Link>
        </div>
      )}
    </div>
  );
}
