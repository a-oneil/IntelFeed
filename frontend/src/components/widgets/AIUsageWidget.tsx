import { useAIUsage } from "@/hooks/useWidgetOpsData";
import { WidgetListSkeleton } from "@/components/Skeleton";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

const numberFmt = new Intl.NumberFormat();

function formatCost(value: number): string {
  return `$${value.toFixed(4)}`;
}

export default function AIUsageWidget({ config }: Props) {
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const params = date_from ? { date_from, ...(date_to ? { date_to } : {}) } : undefined;
  const { data, isLoading } = useAIUsage(params);

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.providers.length === 0) {
    return <div className={styles.noData}>No AI usage in window</div>;
  }

  const { providers, totals } = data;

  return (
    <table className={styles.opsTable}>
      <thead>
        <tr>
          <th>Provider</th>
          <th className={styles.opsTableNumeric}>Calls</th>
          <th className={styles.opsTableNumeric}>In</th>
          <th className={styles.opsTableNumeric}>Out</th>
          <th className={styles.opsTableNumeric}>Cost</th>
        </tr>
      </thead>
      <tbody>
        {providers.map((p) => (
          <tr key={p.provider_id || p.provider_name}>
            <td title={p.model_name || undefined}>{p.provider_name}</td>
            <td className={styles.opsTableNumeric}>{numberFmt.format(p.calls)}</td>
            <td className={styles.opsTableNumeric}>{numberFmt.format(p.tokens_input)}</td>
            <td className={styles.opsTableNumeric}>{numberFmt.format(p.tokens_output)}</td>
            <td className={styles.opsTableNumeric}>{formatCost(p.cost_estimate)}</td>
          </tr>
        ))}
        <tr className={styles.opsTableTotalsRow}>
          <td>Total</td>
          <td className={styles.opsTableNumeric}>{numberFmt.format(totals.calls)}</td>
          <td className={styles.opsTableNumeric}>{numberFmt.format(totals.tokens_input)}</td>
          <td className={styles.opsTableNumeric}>{numberFmt.format(totals.tokens_output)}</td>
          <td className={styles.opsTableNumeric}>{formatCost(totals.cost_estimate)}</td>
        </tr>
      </tbody>
    </table>
  );
}
