/**
 * AIAnalysisModule — the AI tab folded into the Overview's Workspace section.
 * Run and read are split: persisted results render as cards (AIResultsDisplay
 * hides itself when there are none), and the task-runner list stays behind a
 * "Run a task" toggle so an unused module costs one slim header row. The old
 * standalone AI tab is gone; this is its home.
 */
import { useState } from "react";
import { AIAnalysisSection } from "@/components/AIAnalysisSection";
import { AIResultsDisplay } from "@/components/AIResultsDisplay";
import { useAIResults } from "@/hooks/useAI";
import type { EntityType } from "@/stores/intelStore";
import styles from "./entityProfile.module.css";

export function AIAnalysisModule({ entityType, entityId }: { entityType: EntityType; entityId: string }) {
  const [runnerOpen, setRunnerOpen] = useState(false);
  const { data: results } = useAIResults(entityType, entityId);
  const resultCount = results?.length ?? 0;

  return (
    <div className={styles.aiModule}>
      <div className={styles.aiModuleHead}>
        <span className={styles.sectionLabel}>
          AI analysis
          {resultCount > 0 && <span className={styles.sectionLabelSub}> · {resultCount} on record</span>}
        </span>
        <button className={styles.aiModuleToggle} onClick={() => setRunnerOpen((o) => !o)}>
          {runnerOpen ? "Hide tasks " : "Run a task "}
          <span className="caret-glyph">{runnerOpen ? "▴" : "▾"}</span>
        </button>
      </div>
      {runnerOpen && (
        <div className={styles.aiModuleRunner}>
          <AIAnalysisSection entityType={entityType} entityId={entityId} />
        </div>
      )}
      <AIResultsDisplay targetType={entityType} targetId={entityId} />
    </div>
  );
}
