import type { DetectionRuleVersion, VersionDiff } from "@/api/types";
import { formatDateTime } from "@/utils/formatDate";
import { DiffView, parseUnifiedDiff } from "./DiffView";
import bench from "./bench.module.css";
import styles from "./RuleHistoryPanel.module.css";

interface RuleHistoryPanelProps {
  versions?: DetectionRuleVersion[];
  viewingVersion: string | null;
  diffVersion: number | null;
  diff?: VersionDiff;
  diffPending: boolean;
  onView: (versionId: string) => void;
  onDiff: (versionNumber: number) => void;
  onRollback: (versionId: string) => void;
}

export function RuleHistoryPanel({
  versions,
  viewingVersion,
  diffVersion,
  diff,
  diffPending,
  onView,
  onDiff,
  onRollback,
}: RuleHistoryPanelProps) {
  if (!versions?.length) return <div className={bench.empty}>No previous versions yet.</div>;

  return (
    <>
      {versions.map((v) => (
        <div key={v.id} className={`${styles.version} ${viewingVersion === v.id ? styles.active : ""}`}>
          <div className={styles.head}>
            <span className={styles.num}>v{v.version_number}</span>
            <span className={styles.date}>{formatDateTime(v.created_at)}</span>
          </div>
          {v.change_description && <div className={styles.desc}>{v.change_description}</div>}
          <div className={styles.actions}>
            <button type="button" className={bench.btn} onClick={() => onView(v.id)}>View</button>
            <button type="button" className={bench.btn} onClick={() => onDiff(v.version_number)}>Diff</button>
            <button type="button" className={bench.btn} onClick={() => onRollback(v.id)}>Rollback</button>
          </div>
          {diffVersion === v.version_number && (
            diffPending ? (
              <div className={bench.empty}>Loading diff…</div>
            ) : diff ? (
              diff.has_changes ? (
                <DiffView lines={parseUnifiedDiff(diff.diff)} />
              ) : (
                <div className={bench.empty}>No changes between versions</div>
              )
            ) : null
          )}
        </div>
      ))}
    </>
  );
}
