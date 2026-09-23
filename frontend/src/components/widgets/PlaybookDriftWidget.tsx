import { useNavigate } from "react-router-dom";
import { usePlaybookDrift } from "@/hooks/useWidgetBoardData";
import { useIntelStore } from "@/stores/intelStore";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

export default function PlaybookDriftWidget({ config }: Props) {
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const { data, isLoading } = usePlaybookDrift({ date_from, date_to });
  const navigate = useNavigate();
  const selectEntity = useIntelStore((s) => s.selectEntity);

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.items.length === 0) {
    return (
      <div className={styles.noData}>
        No new techniques attributed to watched actors in this window
      </div>
    );
  }

  return (
    <div className={styles.list}>
      {data.items.map((actor) => (
        <div key={actor.actor_id} className={`${styles.boardRow} ${styles.boardRowStatic}`}>
          <span className={styles.entityDot} style={{ background: "var(--entity-actor)" }} />
          <div className={styles.boardGrow}>
            <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
              <button
                className={styles.boardPrimary}
                style={{ background: "none", border: "none", padding: 0, cursor: "pointer", fontWeight: 600 }}
                onClick={() => {
                  selectEntity("threat_actor", actor.actor_id, actor.actor_name);
                  navigate("/workbench/explore");
                }}
              >
                {actor.actor_name}
              </button>
              <span className={styles.boardMeta}>{actor.known_count} known techniques</span>
            </div>
            <div style={{ display: "flex", gap: 5, marginTop: 4, flexWrap: "wrap", alignItems: "center" }}>
              {actor.additions.map((add) => (
                <Chip
                  key={add.ttp_id}
                  className={styles.boardChip}
                  tone="toned"
                  tint="var(--accent)"
                  title={`${add.report_count} report${add.report_count === 1 ? "" : "s"} in this window`}
                  onClick={() => navigate(`/workbench/ttp/${add.ttp_id}`)}
                >
                  + {add.technique_id ?? "?"}
                  {add.technique_name ? ` · ${add.technique_name}` : ""}
                </Chip>
              ))}
            </div>
          </div>
        </div>
      ))}
      <div className={styles.boardFootNote}>
        {data.total_new} new technique{data.total_new === 1 ? "" : "s"} across watched actors
      </div>
    </div>
  );
}
