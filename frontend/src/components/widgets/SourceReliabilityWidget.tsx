import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import api from "@/api/client";
import { useUIStore } from "@/stores/uiStore";
import { WidgetListSkeleton } from "@/components/Skeleton";

interface SourceStat {
  feed_id: string;
  feed_title: string;
  article_count: number;
  entity_count: number;
}

export default function SourceReliabilityWidget({ config }: { config: Record<string, unknown> }) {
  const navigate = useNavigate();
  const setSelectedFeed = useUIStore((s) => s.setSelectedFeed);
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const params = date_from ? { date_from, ...(date_to ? { date_to } : {}) } : undefined;

  const handleClick = (feedId: string) => {
    setSelectedFeed(feedId);
    navigate("/");
  };
  const { data, isLoading } = useQuery({
    queryKey: ["widget", "source-reliability", params],
    queryFn: async () => {
      const { data } = await api.get<SourceStat[]>("/analytics/source-reliability", { params });
      return data;
    },
    retry: false,
  });

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.length === 0) return <div style={{ color: "var(--text-muted)", fontSize: 13, padding: 16 }}>No source data</div>;

  return (
    <div style={{ padding: "8px 12px", fontSize: 12, overflow: "auto", height: "100%" }}>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr style={{ color: "var(--text-muted)", textAlign: "left", borderBottom: "1px solid var(--border)" }}>
            <th style={{ padding: "4px 8px", fontWeight: 600 }}>Source</th>
            <th style={{ padding: "4px 8px", fontWeight: 600, textAlign: "right" }}>Articles</th>
            <th style={{ padding: "4px 8px", fontWeight: 600, textAlign: "right" }}>Entities</th>
          </tr>
        </thead>
        <tbody>
          {data.slice(0, 10).map((s) => (
            <tr key={s.feed_id} style={{ borderBottom: "1px solid var(--border)", cursor: "pointer" }} onClick={() => handleClick(s.feed_id)} title="View feed entries">
              <td style={{ padding: "4px 8px", color: "var(--text-primary)", maxWidth: 160, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.feed_title}</td>
              <td style={{ padding: "4px 8px", textAlign: "right", color: "var(--text-secondary)" }}>{s.article_count}</td>
              <td style={{ padding: "4px 8px", textAlign: "right", color: "var(--text-secondary)" }}>{s.entity_count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
