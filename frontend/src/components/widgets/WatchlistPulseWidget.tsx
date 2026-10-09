import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useWatchlistPulse } from "@/hooks/useWidgetBoardData";
import { useIntelStore, type EntityType } from "@/stores/intelStore";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { Sparkline, clampDays, entityColorVar } from "./boardShared";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

export default function WatchlistPulseWidget({ config }: Props) {
  const { data, isLoading } = useWatchlistPulse(clampDays(config.days, 1, 365));
  const [showQuiet, setShowQuiet] = useState(false);
  const navigate = useNavigate();
  const selectEntity = useIntelStore((s) => s.selectEntity);
  const setActiveSection = useIntelStore((s) => s.setActiveSection);

  // Watchable types are a superset of profile-able ones: ransomware victims
  // have no entity profile, so they open the tracker instead.
  const PROFILED: EntityType[] = [
    "threat_actor",
    "malware",
    "cve",
    "ttp",
    "country",
    "sector",
    "mitigation",
    "cwe",
    "tool",
    "vendor",
    "product",
  ];

  function openWatch(entityType: string, entityId: string, name: string) {
    if ((PROFILED as string[]).includes(entityType)) {
      selectEntity(entityType as EntityType, entityId, name);
    } else {
      setActiveSection("ransomware");
    }
    navigate("/workbench/explore");
  }

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.items.length === 0) {
    return <div className={styles.noData}>No watched entities — add watches from any entity profile</div>;
  }

  const moving = data.items.filter((i) => i.total > 0);
  const quiet = data.items.filter((i) => i.total === 0);
  const shown = showQuiet ? [...moving, ...quiet] : moving;

  if (shown.length === 0) {
    return (
      <div className={styles.noData}>
        No mentions for your {quiet.length} watched {quiet.length === 1 ? "entity" : "entities"} in the last{" "}
        {data.window_days} days
      </div>
    );
  }

  return (
    <div className={styles.list}>
      {shown.map((row) => (
        <button
          key={`${row.entity_type}:${row.entity_id}`}
          className={styles.boardRow}
          onClick={() => openWatch(row.entity_type, row.entity_id, row.name)}
        >
          <span className={styles.entityDot} style={{ background: entityColorVar(row.entity_type) }} />
          <span className={`${styles.boardGrow} ${styles.boardPrimary}`}>{row.name}</span>
          <Sparkline points={row.points.map((p) => p.count)} />
          <span
            className={`${styles.boardNum} ${
              row.delta > 0 ? styles.deltaUp : row.delta < 0 ? styles.deltaDown : styles.deltaFlat
            }`}
            style={{ width: 40, textAlign: "right" }}
            title={`${row.total} mentions in ${data.window_days}d`}
          >
            {row.delta > 0 ? "▲" : row.delta < 0 ? "▼" : "—"} {Math.abs(row.delta)}
          </span>
        </button>
      ))}
      {quiet.length > 0 && (
        <button className={styles.boardFootNote} onClick={() => setShowQuiet((v) => !v)} style={{ cursor: "pointer", background: "none", border: "none", borderTop: "1px solid var(--border)", textAlign: "left", width: "100%" }}>
          {showQuiet ? "Hide" : "Show"} {quiet.length} quiet {quiet.length === 1 ? "watch" : "watches"}
        </button>
      )}
    </div>
  );
}
