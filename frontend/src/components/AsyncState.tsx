import { IconAlertTriangle } from "@tabler/icons-react";
import { Spinner } from "@/components/primitives";
import styles from "./AsyncState.module.css";

/** Shared loading/error/empty placeholders for pages and panels that don't need a custom skeleton (see Skeleton.tsx for those). Each component renders one state; the caller picks which one to render. */

interface AsyncStateProps {
  icon?: string;
  title: string;
  description?: string;
  onRetry?: () => void;
  retryLabel?: string;
}

/** Spinner plus a label saying what is loading. `compact` shrinks it to a single padded row for a small slot inside an already-populated panel; the default fills the pane. */
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
      <div className={styles.icon}><IconAlertTriangle size="1em" stroke={1.75} aria-hidden /></div>
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
