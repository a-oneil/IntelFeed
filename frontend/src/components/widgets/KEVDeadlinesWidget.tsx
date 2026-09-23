import { useNavigate } from "react-router-dom";
import { useKEVDeadlines } from "@/hooks/useWidgetBoardData";
import { useIntelStore } from "@/stores/intelStore";
import { WidgetListSkeleton } from "@/components/Skeleton";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

/** Urgency color: overdue/imminent → danger, within a fortnight → warning. */
function urgencyColor(daysLeft: number): string {
  if (daysLeft <= 7) return "var(--danger)";
  if (daysLeft <= 14) return "var(--warning)";
  return "var(--success)";
}

function dueLabel(daysLeft: number): string {
  if (daysLeft < 0) return `${Math.abs(daysLeft)}d overdue`;
  if (daysLeft === 0) return "due today";
  return `${daysLeft}d left`;
}

export default function KEVDeadlinesWidget({ config }: Props) {
  const limit = (config.limit as number) || 10;
  const { data, isLoading } = useKEVDeadlines(limit);
  const navigate = useNavigate();
  const selectEntity = useIntelStore((s) => s.selectEntity);

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.items.length === 0) {
    return <div className={styles.noData}>No KEV entries with upcoming due dates</div>;
  }

  return (
    <div className={styles.list}>
      {data.items.map((cve) => {
        const color = urgencyColor(cve.days_left);
        // Fill shows elapsed share of a nominal 21-day remediation window.
        const elapsed = Math.min(100, Math.max(0, ((21 - cve.days_left) / 21) * 100));
        return (
          <button
            key={cve.id}
            className={styles.boardRow}
            onClick={() => {
              selectEntity("cve", cve.id, cve.cve_id);
              navigate("/workbench/explore");
            }}
          >
            <span className={styles.boardGrow}>
              <span className={styles.boardPrimary} style={{ fontFamily: "var(--font-display)", fontSize: 12.5 }}>
                {cve.cve_id}
              </span>
              <span className={styles.boardMeta}>
                {[cve.vendor, cve.product].filter(Boolean).join(" ") || cve.name || "—"}
              </span>
            </span>
            <span className={styles.meterTrack} style={{ maxWidth: 56, flex: "none", width: 56 }}>
              <span className={styles.meterFill} style={{ width: `${elapsed}%`, background: color }} />
            </span>
            <span
              className={styles.boardNum}
              style={{ color, width: 92, textAlign: "right", whiteSpace: "nowrap" }}
            >
              {dueLabel(cve.days_left)}
            </span>
          </button>
        );
      })}
      {data.due_7d > 0 && (
        <div className={styles.boardFootNote}>
          {data.due_7d} due within 7 days
        </div>
      )}
    </div>
  );
}
