import type { ReactNode } from "react";
import styles from "./PageHeader.module.css";

interface PageHeaderProps {
  /** The page name, as it reads in the workbench nav. */
  title: string;
  /** Quiet row/record count rendered right after the title. */
  count?: number | string;
  /** One line of orientation under the title. Optional by design — most
   *  pages are self-evident and a subtitle on every one is just noise. */
  subtitle?: ReactNode;
  /** Buttons that act on the page: create, import, export. Right-aligned. */
  actions?: ReactNode;
  /** Second row — search, filters, lens/segmented switches. */
  controls?: ReactNode;
  /** Drop the header's own inset, for pages that already pad their content. */
  flush?: boolean;
  className?: string;
}

/**
 * The single page-header treatment. Before this every workbench route rolled
 * its own: h1/h2/span titles at three sizes and two font families, half of
 * them bordered, two on a tinted band, three with no title at all. This is
 * the whole vocabulary — title, count, subtitle, actions, controls.
 */
export function PageHeader({
  title,
  count,
  subtitle,
  actions,
  controls,
  flush = false,
  className,
}: PageHeaderProps) {
  return (
    <header
      className={[styles.head, flush ? styles.flush : "", className || ""]
        .filter(Boolean)
        .join(" ")}
    >
      <div className={styles.titleRow}>
        <h1 className={styles.title}>{title}</h1>
        {count !== undefined && (
          <span className={styles.count}>
            {typeof count === "number" ? count.toLocaleString() : count}
          </span>
        )}
        {actions !== undefined && <div className={styles.actions}>{actions}</div>}
      </div>
      {subtitle !== undefined && <p className={styles.subtitle}>{subtitle}</p>}
      {controls !== undefined && <div className={styles.controls}>{controls}</div>}
    </header>
  );
}
