import { useAIResults } from "@/hooks/useAI";
import { useUIStore } from "@/stores/uiStore";
import styles from "./ArticleSummaryCard.module.css";

interface ArticleSummaryCardProps {
  entryId: string;
}

function relativeTime(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${Math.max(mins, 0)}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return `${Math.floor(days / 30)}mo ago`;
}

/**
 * "Article Summary" card shown under the article byline when a persisted
 * entry_analysis result exists — the gist without opening any panel.
 * Renders nothing when the entry has no analysis.
 */
export function ArticleSummaryCard({ entryId }: ArticleSummaryCardProps) {
  const { data: results } = useAIResults("entry", entryId);
  const collapsed = useUIStore((s) => s.articleSummaryCollapsed);
  const setCollapsed = useUIStore((s) => s.setArticleSummaryCollapsed);

  const analysis = results?.find(
    (r) => r.is_current && r.task_name === "entry_analysis" && typeof r.parsed_result?.summary === "string" && (r.parsed_result.summary as string).trim() !== ""
  );
  if (!analysis) return null;
  const summary = analysis.parsed_result?.summary as string;

  return (
    <div className={styles.card}>
      <button
        className={styles.header}
        onClick={() => setCollapsed(!collapsed)}
        aria-expanded={!collapsed}
      >
        <span className={styles.label}>Article Summary</span>
        <span className={styles.meta}>
          entry analysis · {relativeTime(analysis.created_at)}
        </span>
        <span className={styles.arrow}>{collapsed ? "▾" : "▴"}</span>
      </button>
      {!collapsed && <p className={styles.summary}>{summary}</p>}
    </div>
  );
}
