import { Spinner } from "@/components/primitives";
import styles from "./AsyncState.module.css";

/**
 * Shared loading/error/empty placeholders for pages and panels that don't
 * warrant a bespoke skeleton (see Skeleton.tsx for those). Pick one variant
 * per render — these render a single state, not a state machine.
 */

interface AsyncStateProps {
  icon?: string;
  title: string;
  description?: string;
  onRetry?: () => void;
  retryLabel?: string;
}

/**
 * Spinner + what it is loading. `compact` drops it to a single padded row for
 * a small slot inside an already-populated panel; the default fills the pane.
 */
export function AsyncStateLoading({
  label = "Loading…",
  compact,
}: {
  label?: string;
  compact?: boolean;
}) {
  return (
    <div
      className={`${styles.state} ${styles.loadingState} ${compact ? styles.loadingCompact : ""}`}
      role="status"
      aria-live="polite"
    >
      <Spinner size={compact ? "md" : "lg"} />
      <span className={styles.loadingLabel}>{label}</span>
    </div>
  );
}

export function AsyncStateError({ title, description, onRetry, retryLabel = "Retry" }: AsyncStateProps) {
  return (
    <div className={styles.state}>
      <div className={styles.icon}>⚠</div>
      <div className={styles.title}>{title}</div>
      {description && <div className={styles.desc}>{description}</div>}
      {onRetry && (
        <button className={styles.retryBtn} onClick={onRetry}>
          {retryLabel}
        </button>
      )}
    </div>
  );
}

export function AsyncStateEmpty({ icon, title, description }: AsyncStateProps) {
  return (
    <div className={styles.state}>
      {icon && <div className={styles.icon}>{icon}</div>}
      <div className={styles.title}>{title}</div>
      {description && <div className={styles.desc}>{description}</div>}
    </div>
  );
}
