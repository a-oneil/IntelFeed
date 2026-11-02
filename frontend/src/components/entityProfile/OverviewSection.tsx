/**
 * OverviewSection — one row of the Overview's single column. Closed, it is a
 * 46px line: caret, name, count, and a digest that answers the usual question
 * (how many, which top ones, how fresh) without opening anything. Open, the
 * section's own components render beneath it, unchanged.
 *
 * Which rows are open is the analyst's choice, remembered per entity type in
 * uiStore; the Brief / Everything switch in the tab bar opens them all at once.
 */
import type { ReactNode } from "react";
import { Segmented } from "@/components/primitives";
import { useUIStore } from "@/stores/uiStore";
import styles from "./entityProfile.module.css";

export function OverviewSection({
  id,
  title,
  count,
  digest,
  open,
  onToggle,
  children,
}: {
  id: string;
  title: string;
  /** Shown beside the name in mono, muted: "11", "5 sources". */
  count?: ReactNode;
  /** One line, truncated; null when the section has nothing to summarize. */
  digest?: ReactNode;
  open: boolean;
  onToggle: () => void;
  children: ReactNode;
}) {
  const nameId = `overview-${id}`;
  const bodyId = `overview-${id}-body`;
  return (
    <section className={styles.overviewRow} aria-labelledby={nameId}>
      <button
        type="button"
        className={styles.overviewRowToggle}
        aria-expanded={open}
        aria-controls={bodyId}
        onClick={onToggle}
      >
        <svg
          className={`${styles.overviewRowCaret} ${open ? styles.overviewRowCaretOpen : ""}`}
          viewBox="0 0 16 16"
          aria-hidden="true"
        >
          <path d="M6 3.5 10.5 8 6 12.5" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <span id={nameId} className={styles.overviewRowName}>
          {title}
          {count != null && count !== "" && <span className={styles.overviewRowCount}>{count}</span>}
        </span>
        {digest && <span className={styles.overviewRowDigest}>{digest}</span>}
      </button>
      {open && (
        <div id={bodyId} className={styles.overviewRowBody}>
          {children}
        </div>
      )}
    </section>
  );
}

const DENSITY_OPTIONS = [
  { value: "brief" as const, label: "Brief", title: "Only the sections you keep open" },
  { value: "everything" as const, label: "Everything", title: "Every section open" },
];

/** The tab bar's switch for how much of the Overview is open. */
export function OverviewDensityToggle() {
  const mode = useUIStore((s) => s.profileOverviewMode);
  const setMode = useUIStore((s) => s.setProfileOverviewMode);
  return (
    <Segmented
      size="sm"
      label="How much of the Overview is open"
      options={DENSITY_OPTIONS}
      value={mode}
      onChange={setMode}
    />
  );
}
