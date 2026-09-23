/**
 * The shared cell vocabulary for every DataTable in the app.
 *
 * These lived as private helpers inside WorkbenchPage, so any table outside
 * that file (campaigns, glossary, watchlist) re-invented "muted text",
 * "a date", "a count" with its own markup — which is exactly how those pages
 * drifted out of the house style. Import from here instead.
 */
import { formatDate } from "@/utils/formatDate";
import table from "./DataTable.module.css";
import styles from "./cells.module.css";

/** Muted, ellipsised text — the default for secondary fields. */
export function MetaCell({ value }: { value: string | null | undefined }) {
  if (!value) return <span className={table.zero}>·</span>;
  return <span className={`${styles.meta} ${table.ellipsis}`} title={value}>{value}</span>;
}

/** Primary label of a row — the column you'd click to open the thing. */
export function NameCell({ value, title }: { value: string; title?: string }) {
  return <span className={`${styles.name} ${table.ellipsis}`} title={title ?? value}>{value}</span>;
}

export function DateCell({ value }: { value: string | null | undefined }) {
  if (!value) return <span className={table.zero}>·</span>;
  return (
    <span className={table.dateCell} title={new Date(value).toLocaleString()}>
      {formatDate(value)}
    </span>
  );
}

export function NumCell({ value, tone }: { value: number | null | undefined; tone?: string }) {
  if (!value) return <span className={table.zero}>·</span>;
  return <span className={`${table.count} ${tone ? table[tone] : ""}`}>{value}</span>;
}

/** External link cell — stops propagation so it doesn't also open the row. */
export function LinkCell({ href, label }: { href: string | null | undefined; label?: string }) {
  if (!href) return <span className={table.zero}>·</span>;
  let text = label;
  if (!text) {
    try {
      text = new URL(href).hostname.replace(/^www\./, "");
    } catch {
      text = href;
    }
  }
  return (
    <a
      className={`${styles.link} ${table.ellipsis}`}
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      title={href}
      onClick={(e) => e.stopPropagation()}
    >
      {text} ↗
    </a>
  );
}

/**
 * Row actions pinned to a `sticky: "right"` column. Clicks never reach the row,
 * so an action can't also trigger the row's navigation.
 */
export function ActionsCell({ children }: { children: React.ReactNode }) {
  return (
    <span className={styles.actions} onClick={(e) => e.stopPropagation()}>
      {children}
    </span>
  );
}

/** The house row-action button. Quiet until hovered. */
export function RowActionButton({
  children,
  onClick,
  title,
  danger = false,
  disabled = false,
}: {
  children: React.ReactNode;
  onClick: () => void;
  title?: string;
  danger?: boolean;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      className={`${styles.rowAction} ${danger ? styles.rowActionDanger : ""}`}
      onClick={onClick}
      title={title}
      disabled={disabled}
    >
      {children}
    </button>
  );
}
