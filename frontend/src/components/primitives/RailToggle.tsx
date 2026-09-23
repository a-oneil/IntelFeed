import styles from "./RailToggle.module.css";

interface RailToggleProps {
  /** Which pane the rail collapses — decides the chevron direction and borders. */
  side: "left" | "right" | "both";
  collapsed: boolean;
  onToggle: () => void;
  /** Noun for the pane, e.g. "menu" → "Open menu" / "Close menu". */
  label: string;
  /** Override the default Open/Close verbs (the copilot rail says Expand/Collapse). */
  verbs?: [expand: string, collapse: string];
  className?: string;
}

/**
 * The 16px collapse rail used between layout panes. Chevron points toward the
 * direction the click moves the pane: collapsed → points away from the pane's
 * edge (expand), expanded → points back at it (collapse).
 */
export function RailToggle({ side, collapsed, onToggle, label, verbs, className }: RailToggleProps) {
  const [expandVerb, collapseVerb] = verbs ?? ["Open", "Close"];
  const text = collapsed ? `${expandVerb} ${label}` : `${collapseVerb} ${label}`;
  // A rail on the right of the viewport mirrors: its pane lives to the right,
  // so "expand" points left rather than right.
  const pointsRight = side === "right" ? !collapsed : collapsed;
  return (
    <button
      type="button"
      className={`${styles.rail} ${styles[side]} ${className || ""}`}
      onClick={onToggle}
      aria-label={text}
      aria-expanded={!collapsed}
      title={text}
    >
      <svg className={styles.chevron} viewBox="0 0 10 10" fill="none" aria-hidden="true">
        {pointsRight ? (
          <path d="M3 1L8 5L3 9" stroke="currentColor" strokeWidth="1.5" />
        ) : (
          <path d="M7 1L2 5L7 9" stroke="currentColor" strokeWidth="1.5" />
        )}
      </svg>
    </button>
  );
}
