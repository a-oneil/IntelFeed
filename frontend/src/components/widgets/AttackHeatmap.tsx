import { useNavigate } from "react-router-dom";
import { useAttackHeatmap } from "@/hooks/useWidgetData";
import { WidgetChartSkeleton } from "@/components/Skeleton";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

const TACTICS = [
  "reconnaissance",
  "resource-development",
  "initial-access",
  "execution",
  "persistence",
  "privilege-escalation",
  "defense-evasion",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "command-and-control",
  "exfiltration",
  "impact",
];

export default function AttackHeatmap({ config }: Props) {
  const navigate = useNavigate();
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const params = date_from ? { date_from, ...(date_to ? { date_to } : {}) } : undefined;
  const { data, isLoading } = useAttackHeatmap(params);

  if (isLoading) return <WidgetChartSkeleton />;
  if (!data || data.length === 0) return <div className={styles.noData}>No ATT&CK data</div>;

  const max = Math.max(...data.map((d) => d.count), 1);

  // Group by tactic
  const byTactic: Record<string, typeof data> = {};
  for (const item of data) {
    const tactic = item.tactic || "unknown";
    if (!byTactic[tactic]) byTactic[tactic] = [];
    byTactic[tactic].push(item);
  }

  return (
    <div className={styles.heatmap}>
      {TACTICS.map((tactic) => {
        const techniques = byTactic[tactic];
        if (!techniques || techniques.length === 0) return null;
        return (
          <div key={tactic} className={styles.heatmapRow}>
            <div className={styles.heatmapTactic}>{tactic.replace(/-/g, " ")}</div>
            <div className={styles.heatmapCells}>
              {techniques.map((t) => {
                const intensity = t.count / max;
                const r = Math.round(255);
                const g = Math.round(255 - intensity * 155);
                const b = Math.round(255 - intensity * 155);
                return (
                  <div
                    key={t.technique_id}
                    className={styles.heatmapCell}
                    style={{ backgroundColor: `rgb(${r},${g},${b})`, cursor: "pointer" }}
                    title={`${t.technique_id} ${t.name}: ${t.count} articles — click to view`}
                    onClick={() => navigate(`/workbench/ttp/${t.technique_id}`)}
                  >
                    <span className={styles.heatmapCellId}>{t.technique_id}</span>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}
