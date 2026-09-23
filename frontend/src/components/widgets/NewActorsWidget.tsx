import { useNavigate } from "react-router-dom";
import { useNewActors } from "@/hooks/useWidgetData";
import { useIntelStore } from "@/stores/intelStore";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

export default function NewActorsWidget({ config }: Props) {
  const days = (config.days as number) || 7;
  const { data, isLoading } = useNewActors(days);
  const navigate = useNavigate();
  const selectEntity = useIntelStore((s) => s.selectEntity);

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.length === 0) return <div className={styles.noData}>No new actors in the last {days} days</div>;

  return (
    <div className={styles.list}>
      {data.map((actor) => (
        <button
          key={actor.id}
          className={styles.listItemClickable}
          onClick={() => { selectEntity("threat_actor", actor.id, actor.name); navigate("/workbench/explore"); }}
        >
          <div className={styles.listItemMain}>
            <span className={styles.actorName}>{actor.name}</span>
            {actor.country && <Chip truncate className={styles.tagSmall}>{actor.country}</Chip>}
          </div>
          <div className={styles.listItemMeta}>
            {actor.article_count} article{actor.article_count !== 1 ? "s" : ""}
          </div>
        </button>
      ))}
    </div>
  );
}
