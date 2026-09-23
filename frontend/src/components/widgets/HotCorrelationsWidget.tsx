import { useNavigate } from "react-router-dom";
import { useHotCorrelations, type HotCorrelationItem } from "@/hooks/useWidgetStrategicData";
import { useIntelStore } from "@/stores/intelStore";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

export default function HotCorrelationsWidget({ config }: Props) {
  const navigate = useNavigate();
  const selectEntity = useIntelStore((s) => s.selectEntity);

  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const limit = (config.limit as number | undefined) ?? 15;

  const params: Record<string, unknown> = { limit };
  if (date_from) params.date_from = date_from;
  if (date_to) params.date_to = date_to;

  const { data, isLoading } = useHotCorrelations(params);

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.length === 0) return <div className={styles.noData}>No correlations</div>;

  const handleSelect = (
    e: React.MouseEvent,
    type: "threat_actor" | "malware" | "cve",
    id: string,
    label: string,
  ) => {
    e.stopPropagation();
    selectEntity(type, id, label);
    navigate("/workbench/explore");
  };

  const renderRow = (item: HotCorrelationItem, idx: number) => {
    const actor = (
      <button
        key="a"
        type="button"
        className={styles.hotCorrEntity}
        style={{ color: "var(--entity-actor)" }}
        onClick={(e) => handleSelect(e, "threat_actor", item.actor_id, item.actor_name)}
      >
        {item.actor_name}
      </button>
    );
    const sep = <span key="s" className={styles.hotCorrSep}>↔</span>;
    const right =
      item.pair_type === "actor_malware" ? (
        <button
          key="m"
          type="button"
          className={styles.hotCorrEntity}
          style={{ color: "var(--entity-malware)" }}
          onClick={(e) => handleSelect(e, "malware", item.malware_id, item.malware_name)}
        >
          {item.malware_name}
        </button>
      ) : (
        <button
          key="c"
          type="button"
          className={styles.hotCorrEntity}
          style={{ color: "var(--entity-cve)", fontFamily: "monospace" }}
          onClick={(e) => handleSelect(e, "cve", item.cve_uuid, item.cve_id)}
        >
          {item.cve_id}
        </button>
      );

    return (
      <div key={`${item.pair_type}-${idx}`} className={styles.hotCorrRow}>
        <div className={styles.hotCorrPair}>
          {actor}
          {sep}
          {right}
        </div>
        <Chip pill className={styles.numBadge}>
          {item.co_occurrences}
        </Chip>
      </div>
    );
  };

  return <div className={styles.list}>{data.map((item, idx) => renderRow(item, idx))}</div>;
}
