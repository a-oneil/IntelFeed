import styles from "./Spinner.module.css";

interface SpinnerProps {
  /** sm 14px (inline with text) · md 16px (default) · lg 24px (full pane). */
  size?: "sm" | "md" | "lg";
  className?: string;
}

/**
 * The one spinning ring in the app. Always decorative — pair it with real text
 * (or an `aria-live` container) so assistive tech hears what is happening
 * rather than nothing at all.
 */
export function Spinner({ size = "md", className }: SpinnerProps) {
  return (
    <span
      className={`${styles.spinner} ${styles[size]} ${className ?? ""}`}
      aria-hidden="true"
    />
  );
}
