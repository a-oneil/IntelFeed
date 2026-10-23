import AssignmentSelect from "@/components/AssignmentSelect";
import SystemSettings from "@/components/SystemSettings";
import {
  useAIProviders,
  useAITasks,
  useAllTaskAssignments,
  useUpsertTaskAssignment,
} from "@/hooks/useAI";
import { useExtractionStatus } from "@/hooks/useEngine";

import { DenylistPanel } from "./DenylistPanel";

import styles from "./AnalyzeStageConfig.module.css";
import { USER_AI_SETTING_KEYS } from "./engineSettingsIndex";

/** Analyze stage panel: one-pass AI analysis status + model + budget/gate
 *  settings, plus the entity-creation guardrails its output passes through.
 *  (The extract stage is pattern matching; the AI read lives here.) */
export function AnalyzeStageConfig() {
  const { data: status } = useExtractionStatus();
  const { data: tasks } = useAITasks();
  const { data: providers } = useAIProviders();
  const { data: assignments } = useAllTaskAssignments();
  const upsertAssignment = useUpsertTaskAssignment();

  const entryTask = tasks?.find((t) => t.name === "entry_analysis");
  const assignment = entryTask ? assignments?.[entryTask.id] : undefined;
  const currentValue = assignment ? `${assignment.provider_id}|${assignment.model_name}` : "";
  const assignedProvider = providers?.find((p) => p.id === assignment?.provider_id);

  const handleAssign = (providerId: string, model: string) => {
    if (!entryTask) return;
    upsertAssignment.mutate({
      taskId: entryTask.id,
      provider_id: providerId,
      model_name: model,
      is_enabled: true,
    });
  };

  const handleMaxTokens = (raw: string) => {
    if (!entryTask || !assignment) return;
    const cfg = { ...assignment.config };
    const parsed = raw.trim() === "" ? undefined : Number(raw);
    const next = parsed !== undefined && Number.isFinite(parsed) && parsed > 0 ? Math.round(parsed) : undefined;
    if (next === (cfg.max_tokens as number | undefined)) return;
    if (next === undefined) delete cfg.max_tokens;
    else cfg.max_tokens = next;
    upsertAssignment.mutate({
      taskId: entryTask.id,
      provider_id: assignment.provider_id,
      model_name: assignment.model_name,
      is_enabled: assignment.is_enabled,
      config: cfg,
    });
  };

  return (
    <div className={styles.wrap}>
      <h4 className={styles.heading}>One-pass AI analysis</h4>
      {status && (
        <div className={styles.statusGrid}>
          <div className={styles.stat}>
            <span className={styles.statLabel}>Status</span>
            <span className={status.enabled ? styles.on : styles.off}>{status.enabled ? "enabled" : "off"}</span>
          </div>
          <div className={styles.stat}>
            <span className={styles.statLabel}>Spend today</span>
            <span>
              ${status.spent_today_usd.toFixed(2)} / ${status.daily_budget_usd.toFixed(2)}
            </span>
          </div>
          {Object.entries(status.queue).map(([state, count]) => (
            <div key={state} className={styles.stat}>
              <span className={styles.statLabel}>{state.replace(/_/g, " ")}</span>
              <span>{count}</span>
            </div>
          ))}
          {status.last_batch && (
            <div className={styles.stat}>
              <span className={styles.statLabel}>Last batch</span>
              <span>
                {status.last_batch.status} · {status.last_batch.succeeded}/{status.last_batch.request_count} ok
              </span>
            </div>
          )}
        </div>
      )}
      {entryTask && (
        <div className={styles.modelRow}>
          <span className={styles.modelLabel}>Analysis model</span>
          <AssignmentSelect
            providers={providers}
            value={currentValue}
            onChange={handleAssign}
            placeholder="Not assigned"
          />
          <span className={styles.modelHint}>
            Model lists come from each provider&apos;s cached Test result (Settings → AI
            Configuration → Providers).
          </span>
        </div>
      )}
      {entryTask && assignment && (
        <div className={styles.modelRow}>
          <span className={styles.modelLabel}>Max output tokens</span>
          <input
            type="number"
            className={styles.tokenInput}
            min={256}
            step={256}
            placeholder="4096"
            defaultValue={assignment.config?.max_tokens as number | undefined}
            key={String(assignment.config?.max_tokens ?? "")}
            aria-label="Max output tokens"
            onBlur={(e) => handleMaxTokens(e.target.value)}
          />
          <span className={styles.modelHint}>
            Response budget per analysis call. Too low truncates the payload mid-JSON — the
            schema front-loads summary, observables and relationships, so the trailing
            timeline/patch keys are lost first.
          </span>
        </div>
      )}
      {/* The two pattern-matching knobs in the extraction group (ICS keywords,
          EPSS tier) stay on the extract stage panel. The personal-key policy,
          the per-person allowance and the share-link limit are the User keys
          tab's (AI Configuration): they govern people, not this stage. */}
      <SystemSettings
        filterGroups={["ai", "extraction"]}
        flat
        excludeKeys={[
          "attack_ics_context_keywords",
          "cve_epss_high_risk_threshold",
          ...USER_AI_SETTING_KEYS,
        ]}
        renderAfterKey={{
          ai_use_batches: () =>
            assignedProvider && assignedProvider.provider_type !== "claude" ? (
              <div className={styles.batchesNote}>
                The Batches API only applies to Anthropic-API (claude) providers — the current
                analysis provider ({assignedProvider.name}) runs sequential per-entry calls
                regardless of this toggle.
              </div>
            ) : null,
        }}
      />
      <DenylistPanel />
    </div>
  );
}
