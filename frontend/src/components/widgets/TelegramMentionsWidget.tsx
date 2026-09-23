import { useTelegramMentionsWidget } from "@/hooks/useWidgetTriageData";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

function timeAgo(dateStr: string | null): string {
  if (!dateStr) return "";
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "now";
  if (mins < 60) return `${mins}m`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h`;
  return `${Math.floor(hours / 24)}d`;
}

export default function TelegramMentionsWidget({ config }: Props) {
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const limit = (config.limit as number) || 15;
  const params = {
    limit,
    ...(date_from ? { date_from } : {}),
    ...(date_to ? { date_to } : {}),
  };
  const { data, isLoading } = useTelegramMentionsWidget(params);

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.length === 0) return <div className={styles.noData}>No telegram mentions</div>;

  return (
    <div className={styles.list}>
      {data.map((m) => (
        <div
          key={m.handle}
          className={styles.telegramRow}
          onClick={() => window.open(m.canonical_url, "_blank", "noopener,noreferrer")}
          role="button"
          tabIndex={0}
          title={m.canonical_url}
        >
          <span className={styles.telegramHandle}>
            {m.primary_link_type === "channel" ? "\u{1F4E1} " : ""}
            {m.display_handle || m.handle}
          </span>
          <Chip pill className={styles.numBadge}>
            {m.mention_count.toLocaleString()}
          </Chip>
          <span className={styles.telegramTime}>{timeAgo(m.last_seen_at)}</span>
        </div>
      ))}
    </div>
  );
}
