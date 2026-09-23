import { useMemo, useState } from "react";
import styles from "./FacetSection.module.css";

export interface FacetRow {
  /** The value written to the filter. Matching is case-insensitive. */
  value: string;
  label: string;
  /** Omitted for groups the index can't count (fixed state rows). */
  count?: number;
}

interface Props {
  label: string;
  rows: FacetRow[];
  /** Selected values, lower-cased by the caller. */
  active: Set<string>;
  onToggle: (value: string) => void;
  /** Rows shown before "Show all". Omit to show every row. */
  cap?: number;
  /** Render a filter box once the group has more rows than `cap`. */
  searchable?: boolean;
  /** Trailing element in the title row, e.g. a per-group clear button. */
  titleAccessory?: React.ReactNode;
}

/**
 * One facet group: title, optional filter box, checkbox rows, "Show all" fold.
 *
 * The three behaviours that matter and are easy to get wrong:
 *
 *  - the cap is a *fold*, not a truncation — a group that hides rows says so and
 *    can be opened, rather than silently ending at N;
 *  - a selected row stays visible even when it falls outside the cap or the
 *    filter box excludes it, or there'd be no way to untick it;
 *  - rows are checkboxes because groups are multi-select. A group that behaves
 *    like a radio should not use this component.
 */
export function FacetSection({ label, rows, active, onToggle, cap, searchable, titleAccessory }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [needle, setNeedle] = useState("");

  const filtered = useMemo(() => {
    if (!needle.trim()) return rows;
    const n = needle.trim().toLowerCase();
    return rows.filter((r) => r.label.toLowerCase().includes(n) || active.has(r.value.toLowerCase()));
  }, [rows, needle, active]);

  if (rows.length === 0) return null;

  const limit = cap ?? rows.length;
  const withinCap = expanded || filtered.length <= limit;
  const visible = withinCap
    ? filtered
    : [...filtered.slice(0, limit), ...filtered.slice(limit).filter((r) => active.has(r.value.toLowerCase()))];

  return (
    <div className={styles.group}>
      <div className={styles.groupTitle}>
        {label}
        {titleAccessory}
      </div>
      {searchable && rows.length > limit && (
        <input
          className={styles.facetSearch}
          value={needle}
          onChange={(e) => setNeedle(e.target.value)}
          placeholder={`Filter ${label.toLowerCase()}…`}
          aria-label={`Filter ${label} values`}
        />
      )}
      {visible.length === 0 && <div className={styles.empty}>No match</div>}
      {visible.map((row) => {
        const on = active.has(row.value.toLowerCase());
        return (
          <button
            key={row.value}
            className={`${styles.row} ${on ? styles.rowOn : ""}`}
            onClick={() => onToggle(row.value)}
            title={row.label}
            aria-pressed={on}
          >
            <span className={`${styles.check} ${on ? styles.checkOn : ""}`} />
            <span className={styles.rowLabel}>{row.label}</span>
            {row.count != null && <span className={styles.count}>{row.count.toLocaleString()}</span>}
          </button>
        );
      })}
      {!withinCap && (
        <button className={styles.moreBtn} onClick={() => setExpanded(true)}>
          Show all {filtered.length.toLocaleString()}
        </button>
      )}
      {expanded && filtered.length > limit && (
        <button className={styles.moreBtn} onClick={() => setExpanded(false)}>
          Show fewer
        </button>
      )}
    </div>
  );
}
