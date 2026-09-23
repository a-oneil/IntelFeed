import { useCascadePreview } from "@/hooks/useHygiene";
import styles from "./CascadePreview.module.css";
import { AsyncStateLoading } from "@/components/AsyncState";

interface CascadePreviewProps {
  entity_type: string;
  entity_id: string;
}

interface Row {
  label: string;
  count: number;
}

function buildSummary(rows: Row[]): string {
  const nonZero = rows.filter((r) => r.count > 0);
  if (nonZero.length === 0) {
    return "This entity has no live references. Safe to delete.";
  }
  const parts = nonZero.map((r) => `${r.count} ${r.label.toLowerCase()}`);
  if (parts.length === 1) return `Deleting this entity will unlink it from ${parts[0]}.`;
  if (parts.length === 2)
    return `Deleting this entity will unlink it from ${parts[0]} and ${parts[1]}.`;
  const last = parts.pop();
  return `Deleting this entity will unlink it from ${parts.join(", ")}, and ${last}.`;
}

export function CascadePreview({ entity_type, entity_id }: CascadePreviewProps) {
  const { data, isLoading, isError } = useCascadePreview(entity_type, entity_id);

  if (isLoading) {
    return <AsyncStateLoading label="Loading impact preview…" compact />;
  }

  if (isError) {
    return <div className={`${styles.state} ${styles.error}`}>Could not load impact preview.</div>;
  }

  if (!data) {
    return null;
  }

  const rows: Row[] = [
    { label: "Articles", count: data.entry_links },
    { label: "Campaigns", count: data.campaign_links },
    { label: "Detection rules", count: data.detection_rules },
    { label: "Relationships", count: data.relationships },
    { label: "Notes", count: data.notes },
  ];

  const hasImpact = rows.some((r) => r.count > 0);

  return (
    <div className={styles.container}>
      <div className={`${styles.summary} ${hasImpact ? styles.summaryImpact : styles.summarySafe}`}>
        {buildSummary(rows)}
      </div>
      <div className={styles.grid}>
        {rows.map((row) => (
          <div
            key={row.label}
            className={`${styles.cell} ${row.count > 0 ? styles.cellActive : styles.cellZero}`}
          >
            <span className={styles.cellLabel}>{row.label}</span>
            <span className={styles.cellCount}>{row.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default CascadePreview;
