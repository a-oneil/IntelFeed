import { useNavigate } from "react-router-dom";
import { useTrendingEntities } from "@/hooks/useAnalytics";
import { useEntityMentionsTimeseries } from "@/hooks/useEntityProfile";
import { formatDate } from "@/utils/formatDate";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { Sparkline } from "@/components/Sparkline";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";
import { severityChipColors } from "@/utils/severity";

interface Props {
  config: Record<string, unknown>;
}

/** Filled severity pill colours — was the .critical/.high/.medium/.low class set. */
const NAV_PATHS: Record<string, string> = {
  threat_actor: "/workbench/threat_actor",
  malware: "/workbench/malware",
  cve: "/workbench/cve",
  ttp: "/workbench/ttp",
};

function TrendSparkline({ entityType, entityId }: { entityType: string; entityId: string }) {
  const { data } = useEntityMentionsTimeseries(entityType, entityId, "90d");
  if (!data || data.points.length < 2) return null;
  return <Sparkline values={data.points.map((p) => p.count)} width={48} height={16} />;
}

export default function TrendingEntitiesWidget({ config }: Props) {
  const entityType = (config.entity_type as string) || "threat_actor";
  const days = (config.days as number) || 30;
  const limit = (config.limit as number) || 10;
  const navigate = useNavigate();
  const { data, isLoading } = useTrendingEntities(entityType, { days, limit });

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.length === 0) return <div className={styles.noData}>No trending data</div>;

  const basePath = NAV_PATHS[entityType] || "/intelligence";

  return (
    <div className={styles.list}>
      {data.map((entity) => (
        <button
          key={entity.entity_id}
          className={styles.listItemClickable}
          onClick={() => navigate(`${basePath}/${entity.entity_id}`)}
        >
          <div className={styles.listItemMain}>
            <span className={styles.actorName}>{entity.entity_name}</span>
            {entity.article_count !== undefined && (
              <Chip className={styles.tagSmall}>{entity.article_count} articles</Chip>
            )}
            {entity.severity && (
              <Chip
                tone="solid"
                {...severityChipColors(entity.severity)}
                className={styles.countChip}
              >
                {entity.severity}
              </Chip>
            )}
            <TrendSparkline entityType={entityType} entityId={entity.entity_id} />
          </div>
          {entity.first_seen && (
            <div className={styles.listItemMeta}>
              First seen: {formatDate(entity.first_seen)}
            </div>
          )}
        </button>
      ))}
    </div>
  );
}
