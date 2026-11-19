import {
  IconAffiliate,
  IconBook,
  IconBooks,
  IconFileText,
  IconId,
  IconRss,
  IconSearch,
  IconShieldCode,
  IconTool,
  type TablerIcon,
} from "@tabler/icons-react";
import styles from "./ToolTraceChip.module.css";

export interface ToolTrace {
  id: string;
  name: string;
  args: Record<string, unknown>;
  status: "pending" | "success" | "error";
  summary?: string;
}

const TOOL_ICONS: Record<string, TablerIcon> = {
  search_entries: IconSearch,
  search: IconSearch,
  get_entry: IconFileText,
  get_entity: IconId,
  pivot: IconAffiliate,
  generate_rule: IconShieldCode,
  list_feeds: IconRss,
  search_documentation: IconBooks,
  get_documentation_page: IconBook,
  list_documentation_pages: IconBooks,
};

/**
 * Renders the most salient argument inline (e.g. a query string) so the chip
 * reads like "search_entries 'APT29'" after its icon. Falls back to an arg count.
 */
function argHint(args: Record<string, unknown>): string {
  const primary =
    args.query ?? args.q ?? args.name ?? args.cve_id ?? args.technique_id ?? args.slug ?? args.id;
  if (typeof primary === "string" && primary.trim()) {
    const trimmed = primary.length > 40 ? `${primary.slice(0, 40)}…` : primary;
    return `'${trimmed}'`;
  }
  const count = Object.keys(args).length;
  return count > 0 ? `(${count} arg${count === 1 ? "" : "s"})` : "";
}

export function ToolTraceChip({ trace }: { trace: ToolTrace }) {
  const hint = argHint(trace.args);
  const Icon = TOOL_ICONS[trace.name] ?? IconTool;
  const statusClass =
    trace.status === "success"
      ? styles.success
      : trace.status === "error"
        ? styles.error
        : styles.pending;

  return (
    <div
      className={`${styles.chip} ${statusClass}`}
      title={trace.summary || `${trace.name} ${hint}`}
    >
      <Icon className={styles.icon} size="1em" stroke={1.75} aria-hidden />
      <span className={styles.name}>{trace.name}</span>
      {hint && <span className={styles.hint}>{hint}</span>}
      <span className={styles.status}>
        {trace.status === "pending" ? (
          <span className={styles.spinner} aria-label="running" />
        ) : trace.status === "success" ? (
          "✓"
        ) : (
          "✕"
        )}
      </span>
    </div>
  );
}
