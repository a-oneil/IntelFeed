import { useNavigate } from "react-router-dom";
import { useRulesAttention } from "@/hooks/useWidgetBoardData";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { daysAgo } from "./boardShared";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

export default function RulesAttentionWidget({ config }: Props) {
  const limit = (config.limit as number) || 10;
  const { data, isLoading } = useRulesAttention(limit);
  const navigate = useNavigate();

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.items.length === 0) {
    return <div className={styles.noData}>No rules with fresh intel since last review</div>;
  }

  return (
    <div className={styles.list}>
      {data.items.map((rule) => (
        <button
          key={rule.rule_id}
          className={styles.boardRow}
          onClick={() => navigate(`/workbench/rule/${rule.rule_id}`)}
        >
          <span className={styles.entityDot} style={{ background: "var(--entity-rule)" }} />
          <span className={styles.boardGrow}>
            <span className={styles.boardPrimary}>{rule.title}</span>
            <span className={styles.boardMeta}>updated {daysAgo(rule.updated_at)}</span>
          </span>
          <Chip className={styles.boardChip}>{rule.rule_type}</Chip>
          <Chip className={styles.boardChip} tone="toned" tint="var(--accent)">
            {rule.new_intel_count} new
          </Chip>
        </button>
      ))}
      <div className={styles.boardFootNote}>
        {data.stale_count} of {data.total_rules} published rules have fresh intel
      </div>
    </div>
  );
}
