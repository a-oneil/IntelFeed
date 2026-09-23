import styles from "./ToolTraceChip.module.css";

export interface ToolTrace {
  id: string;
  name: string;
  args: Record<string, unknown>;
  status: "pending" | "success" | "error";
  summary?: string;
}

const TOOL_ICONS: Record<string, string> = {
  search_entries: "🔍",
  search: "🔍",
  get_entry: "📄",
  get_entity: "🧩",
  pivot: "🔀",
  generate_rule: "🛡",
  list_feeds: "📡",
  search_documentation: "📚",
  get_documentation_page: "📖",
  list_documentation_pages: "📚",
};

function iconFor(name: string): string {
  return TOOL_ICONS[name] ?? "⚙";
}

/**
 * Renders the most salient argument inline (e.g. a query string) so the chip
 * reads like "🔍 search_entries 'APT29'". Falls back to an arg count.
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
      <span className={styles.icon}>{iconFor(trace.name)}</span>
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
