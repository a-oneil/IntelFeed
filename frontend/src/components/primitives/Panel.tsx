import type { ReactNode } from "react";
import styles from "./Panel.module.css";

type PanelPadding = "none" | "sm" | "md" | "lg";
type PanelSurface = "default" | "card" | "sunken";

interface PanelProps {
  title?: ReactNode;
  /** Secondary line under the title, inside the header block. */
  subtitle?: ReactNode;
  /** Quiet count rendered next to the title, e.g. the number of rows. */
  count?: number | string;
  /** Buttons pinned to the right of the header. */
  actions?: ReactNode;
  children: ReactNode;
  /** Hairline under the header (on by default). Many cards group the header with the body visually and want no rule; in the first adoption pass a forced divider was the most common blocker. */
  divider?: boolean;
  /** Body inset. "none" is for tables and lists that manage their own. */
  padding?: PanelPadding;
  /** Which surface pair to sit on. "default" is --bg-secondary/--border, which the codebase uses far more than the card pair; "card" opts into --card-bg/--card-border. */
  surface?: PanelSurface;
  /** "display" (default) is the app's house style: `index.css` sets `h1,h2,h3 { font-family: var(--font-display) }` globally, so existing card headings already render in the monospace face. "heading" switches to the BODY face at --fs-lg, which is the exception, not the norm. */
  titleVariant?: "display" | "heading";
  /** Panels hosting a tooltip, popover or dropdown that overflows the card must set "visible". Doing this with a consumer className instead relies on bundler chunk order to win the cascade, so a chunking change could silently clip the content. */
  overflow?: "hidden" | "visible";
  /** Raise the card off the page. 0 = flat (default). */
  elevation?: 0 | 1 | 2;
  /** Drop the border/background — for panels that host their own chrome. */
  flush?: boolean;
  className?: string;
  /** ARIA pass-through: some panels are groups or labeled regions. */
  role?: string;
  "aria-label"?: string;
  id?: string;
}

/** Bordered container with an optional header row. */
export function Panel({
  title,
  subtitle,
  count,
  actions,
  children,
  divider = true,
  padding = "md",
  surface = "default",
  titleVariant = "display",
  overflow = "hidden",
  elevation = 0,
  flush = false,
  className,
  role,
  "aria-label": ariaLabel,
  id,
}: PanelProps) {
  const hasHeader = title !== undefined || actions !== undefined;
  return (
    <section
      className={[
        flush ? styles.flush : styles.panel,
        !flush && surface !== "default" ? styles[`surface_${surface}`] : "",
        overflow === "visible" ? styles.overflowVisible : "",
        elevation > 0 ? styles[`elevation_${elevation}`] : "",
        className || "",
      ]
        .filter(Boolean)
        .join(" ")}
      role={role}
      aria-label={ariaLabel}
      id={id}
    >
      {hasHeader && (
        <header
          className={`${styles.header} ${styles[`header_${padding}`]} ${
            divider ? styles.headerDivided : ""
          }`}
        >
          <div className={styles.headerText}>
            {title !== undefined && (
              <h3
                className={`${styles.title} ${
                  titleVariant === "heading" ? styles.title_heading : ""
                }`}
              >
                {title}
                {count !== undefined && <span className={styles.count}>{count}</span>}
              </h3>
            )}
            {subtitle !== undefined && <p className={styles.subtitle}>{subtitle}</p>}
          </div>
          {actions !== undefined && <div className={styles.actions}>{actions}</div>}
        </header>
      )}
      <div className={styles[`body_${padding}`]}>{children}</div>
    </section>
  );
}
