import { useNavigate } from "react-router-dom";
import { useActorActivity, type ActorActivityRow } from "@/hooks/useWidgetStrategicData";
import { useIntelStore } from "@/stores/intelStore";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

function Sparkline({ points }: { points: { count: number }[] }) {
  if (points.length === 0) return null;
  const max = Math.max(1, ...points.map((p) => p.count));
  const w = 100;
  const h = 20;
  const stepX = points.length > 1 ? w / (points.length - 1) : 0;
  const coords = points.map((p, i) => {
    const x = points.length > 1 ? i * stepX : w / 2;
    const y = h - (p.count / max) * (h - 2) - 1;
    return `${x.toFixed(2)},${y.toFixed(2)}`;
  });
  const polyline = coords.join(" ");
  const areaPath = `M ${coords[0]} L ${coords.slice(1).join(" L ")} L ${w},${h} L 0,${h} Z`;
  return (
    <svg
      className={styles.sparkSvg}
      viewBox={`0 0 ${w} ${h}`}
      preserveAspectRatio="none"
      role="img"
      aria-label="activity sparkline"
    >
      <path d={areaPath} fill="var(--entity-actor)" opacity="0.18" />
      <polyline
        points={polyline}
        fill="none"
        stroke="var(--entity-actor)"
        strokeWidth="1.5"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}

export default function ActorActivityTimelineWidget({ config }: Props) {
  const navigate = useNavigate();
  const selectEntity = useIntelStore((s) => s.selectEntity);

  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const limit = (config.limit as number | undefined) ?? 5;
  const configuredIds = config.actor_ids as string[] | undefined;

  const params: Parameters<typeof useActorActivity>[0] = { limit };
  if (date_from) params.date_from = date_from;
  if (date_to) params.date_to = date_to;
  if (configuredIds && configuredIds.length > 0) params.actor_ids = configuredIds;

  const { data, isLoading } = useActorActivity(params);

  if (isLoading) return <WidgetListSkeleton />;
  const actors = data?.actors ?? [];
  if (actors.length === 0) return <div className={styles.noData}>No actor activity</div>;

  const handleClick = (a: ActorActivityRow) => {
    selectEntity("threat_actor", a.id, a.name);
    navigate("/workbench/explore");
  };

  return (
    <div className={styles.list}>
      {actors.map((a) => (
        <button
          key={a.id}
          type="button"
          className={styles.sparkRow}
          onClick={() => handleClick(a)}
        >
          <div className={styles.sparkLeft}>
            <span className={styles.sparkActorName}>{a.name}</span>
            {a.country && <Chip truncate className={styles.tagSmall}>{a.country}</Chip>}
          </div>
          <span className={styles.sparkTotal}>{a.total}</span>
          <Sparkline points={a.points} />
        </button>
      ))}
    </div>
  );
}
