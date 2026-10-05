import { useMemo, useState } from "react";
import { toast } from "sonner";

import { useFeeds } from "@/hooks/useFeeds";
import {
  useDeletePlan,
  usePipelineOverview,
  usePipelinePlans,
  useUpsertPlan,
  type PipelinePlanRow,
} from "@/hooks/useEngine";

import styles from "./PipelinePlans.module.css";

const TOGGLEABLE_STAGES = ["autolink", "telegram_links", "extract", "cooccurrence", "correlation", "requirements", "score"];

/** Pipeline plan editor: per-scope stage toggles layered over the feed booleans.
 *  Only takes effect when the pipeline_engine_enabled flag is on. */
export function PipelinePlans() {
  const { data: overview } = usePipelineOverview();
  const { data: plans } = usePipelinePlans();
  const { data: feedsData } = useFeeds();
  const upsert = useUpsertPlan();
  const deletePlan = useDeletePlan();
  const [newFeedId, setNewFeedId] = useState("");

  const feedNames = useMemo(() => {
    const map: Record<string, string> = {};
    for (const f of feedsData?.items ?? []) map[f.id] = f.title;
    return map;
  }, [feedsData]);

  const sortedPlans = useMemo(() => {
    const rank: Record<string, number> = { global: 0, category: 1, feed: 2 };
    return [...(plans ?? [])].sort(
      (a, b) => (rank[a.scope_type] ?? 3) - (rank[b.scope_type] ?? 3) || a.name.localeCompare(b.name),
    );
  }, [plans]);

  // Cycle: inherit -> forced off -> forced on -> inherit (drop the enabled key
  // so the stage falls through to the layer below again).
  const toggleStage = (plan: PipelinePlanRow, stage: string) => {
    const current = plan.stages[stage]?.enabled;
    const next = { ...plan.stages };
    if (current === true) {
      const rest = { ...(next[stage] ?? {}) };
      delete rest.enabled;
      if (Object.keys(rest.config ?? {}).length > 0) next[stage] = rest;
      else delete next[stage];
    } else {
      next[stage] = { ...(next[stage] ?? {}), enabled: current === false };
    }
    upsert.mutate(
      { name: plan.name, scope_type: plan.scope_type, scope_id: plan.scope_id, stages: next, is_active: plan.is_active },
      {
        onSuccess: () => toast.success("Plan updated"),
        onError: () => toast.error("Failed to update plan"),
      },
    );
  };

  const createFeedPlan = () => {
    if (!newFeedId) return;
    upsert.mutate(
      { name: feedNames[newFeedId] ?? "Feed plan", scope_type: "feed", scope_id: newFeedId, stages: {}, is_active: true },
      {
        onSuccess: () => {
          toast.success("Feed plan created");
          setNewFeedId("");
        },
        onError: () => toast.error("Failed to create plan"),
      },
    );
  };

  return (
    <div className={styles.wrap}>
      {!overview?.pipeline_engine_enabled && (
        <p className={styles.banner}>
          Pipeline plans are configured but inactive — enable "Pipeline Plans" under Settings → Engine
          (Plans) to apply them. Until then the legacy per-feed extraction toggles drive behavior.
        </p>
      )}
      <p className={styles.hint}>
        Plans layer over each feed's legacy settings: global → category → feed. A stage left untouched falls
        through to the layer below.
      </p>

      {sortedPlans.map((plan) => (
        <div key={plan.id} className={styles.planCard}>
          <div className={styles.planHeader}>
            <span className={styles.planName}>
              {plan.scope_type === "global"
                ? "Global default"
                : plan.scope_type === "feed"
                  ? `Feed: ${feedNames[plan.scope_id ?? ""] ?? plan.name}`
                  : `Category: ${plan.name}`}
            </span>
            {plan.scope_type !== "global" && (
              <button
                className={styles.deleteBtn}
                onClick={() =>
                  deletePlan.mutate(plan.id, {
                    onSuccess: () => toast.success("Plan deleted"),
                    onError: () => toast.error("Delete failed"),
                  })
                }
              >
                delete
              </button>
            )}
          </div>
          <div className={styles.stageToggles}>
            {TOGGLEABLE_STAGES.map((stage) => {
              const spec = plan.stages[stage];
              const state = spec?.enabled === undefined ? "inherit" : spec.enabled ? "on" : "off";
              return (
                <button
                  key={stage}
                  className={`${styles.toggle} ${styles[`toggle_${state}`]}`}
                  onClick={() => toggleStage(plan, stage)}
                  title={
                    state === "inherit"
                      ? "Inherited — click to force off"
                      : state === "off"
                        ? "Forced off — click to force on"
                        : "Forced on — click to revert to inherit"
                  }
                >
                  {stage.replace(/_/g, " ")}
                  <span className={styles.toggleState}>{state}</span>
                </button>
              );
            })}
          </div>
        </div>
      ))}

      <div className={styles.newPlanRow}>
        <select value={newFeedId} onChange={(e) => setNewFeedId(e.target.value)} className={styles.feedSelect}>
          <option value="">Add a per-feed plan…</option>
          {(feedsData?.items ?? [])
            .filter((f) => !plans?.some((p) => p.scope_type === "feed" && p.scope_id === f.id))
            .map((f) => (
              <option key={f.id} value={f.id}>
                {f.title}
              </option>
            ))}
        </select>
        <button className={styles.addBtn} onClick={createFeedPlan} disabled={!newFeedId || upsert.isPending}>
          Add
        </button>
      </div>
    </div>
  );
}
