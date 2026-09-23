import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";
import type { CursorPaginatedResponse, Entry } from "@/api/types";
import { formatDate } from "@/utils/formatDate";
import { WidgetListSkeleton } from "@/components/Skeleton";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

export default function LatestEntries({ config }: Props) {
  const feedId = config.feed_id as string | undefined;
  const limit = (config.limit as number) || 10;
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const navigate = useNavigate();

  const { data, isLoading } = useQuery({
    queryKey: ["entries-widget", feedId, limit, date_from, date_to],
    queryFn: async () => {
      const params: Record<string, unknown> = { limit };
      if (feedId) params.feed_id = feedId;
      if (date_from) params.since = date_from;
      if (date_to) params.before = date_to;
      const res = await api.get<CursorPaginatedResponse<Entry>>("/entries", { params });
      return res.data;
    },
  });

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.items.length === 0) return <div className={styles.noData}>No entries</div>;

  return (
    <div className={styles.list}>
      {data.items.map((entry) => (
        <button
          key={entry.id}
          className={styles.listItemClickable}
          onClick={() => navigate(`/?entry=${entry.id}`)}
        >
          <div className={styles.listItemMain}>
            <span className={styles.entryTitle}>{entry.title}</span>
          </div>
          <div className={styles.listItemMeta}>
            {entry.feed_title}
            {entry.published_at && (
              <> &middot; {formatDate(entry.published_at)}</>
            )}
          </div>
        </button>
      ))}
    </div>
  );
}
