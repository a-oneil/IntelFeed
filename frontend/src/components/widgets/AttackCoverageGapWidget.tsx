import { useNavigate } from "react-router-dom";
import { useAttackCoverageGap } from "@/hooks/useWidgetDetectionData";
import { useIntelStore } from "@/stores/intelStore";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

export default function AttackCoverageGapWidget({ config }: Props) {
  const navigate = useNavigate();
  const selectEntity = useIntelStore((s) => s.selectEntity);
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const limit = (config.limit as number) || 15;
  const params = {
    limit,
    ...(date_from ? { date_from } : {}),
    ...(date_to ? { date_to } : {}),
  };
  const { data, isLoading } = useAttackCoverageGap(params);

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.length === 0)
    return <div className={styles.noData}>No uncovered techniques in window</div>;

  return (
    <div className={styles.list}>
      {data.map((t) => (
        <button
          key={t.ttp_id}
          className={styles.listItemClickable}
          onClick={() => {
            selectEntity("ttp", t.ttp_id, t.technique_id);
            navigate("/workbench/explore");
          }}
        >
          <div className={styles.listItemMain}>
            <span className={styles.cveId}>{t.technique_id}</span>
            <span className={styles.actorName} title={t.technique_name}>
              {t.technique_name}
            </span>
            {t.tactic && <Chip truncate className={styles.tagSmall}>{t.tactic}</Chip>}
          </div>
          <div className={styles.listItemMeta}>
            {t.mention_count} mention{t.mention_count !== 1 ? "s" : ""}
          </div>
        </button>
      ))}
    </div>
  );
}
