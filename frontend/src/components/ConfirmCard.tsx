import type { CopilotConfirmRequest } from "@/hooks/useAI";
import { Chip } from "./primitives";
import styles from "./ConfirmCard.module.css";

/** Lifecycle of a proposed write shown inline in the copilot thread. */
export type ConfirmState =
  | { status: "pending" }
  | { status: "in_flight"; approved: boolean }
  | { status: "executed"; summary: string; link?: string }
  | { status: "cancelled" }
  | { status: "error"; message: string };

/** Human-friendly label for the action's verb (e.g. "create_campaign"). */
function actionLabel(actionType: string): string {
  if (!actionType) return "Proposed action";
  return actionType
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

/** One argument value as the card shows it: strings as-is, the rest as JSON. */
function argText(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value);
}

interface ConfirmCardProps {
  request: CopilotConfirmRequest;
  state: ConfirmState;
  onConfirm: () => void;
  onCancel: () => void;
}

/**
 * Inline "writes-with-confirm" card rendered within the copilot thread after
 * the assistant turn that proposed a write. Shows the exact tool call (its
 * name and every argument) plus Confirm / Cancel, a disabled/pending state
 * while the request is in flight, and a resolved state (executed / cancelled /
 * error) afterward. Nothing runs until Confirm.
 */
export function ConfirmCard({
  request,
  state,
  onConfirm,
  onCancel,
}: ConfirmCardProps) {
  const inFlight = state.status === "in_flight";
  const resolved =
    state.status === "executed" ||
    state.status === "cancelled" ||
    state.status === "error";

  return (
    <div
      className={`${styles.card} ${
        state.status === "executed"
          ? styles.cardExecuted
          : state.status === "error"
            ? styles.cardError
            : state.status === "cancelled"
              ? styles.cardCancelled
              : ""
      }`}
      role="group"
      aria-label="Confirm proposed action"
    >
      <div className={styles.head}>
        <span className={styles.badge}>⚡ Proposed write</span>
        <Chip className={styles.actionType} truncate>
          {actionLabel(request.action_type)}
        </Chip>
      </div>

      {request.tool_name ? (
        <dl className={styles.args}>
          {Object.entries(request.proposed).map(([key, value]) => (
            <div key={key} className={styles.arg}>
              <dt>{key}</dt>
              <dd>
                {request.targets?.[key] && <span className={styles.target}>{request.targets[key]}</span>}
                <span className={request.targets?.[key] ? styles.argId : undefined}>{argText(value)}</span>
              </dd>
            </div>
          ))}
        </dl>
      ) : (
        <div className={styles.description}>{request.description}</div>
      )}
      {request.preview && <div className={styles.preview}>{request.preview}</div>}
      {request.destructive && (
        <div className={styles.warning}>
          This deletes data or changes it for everyone. Check it before you confirm.
        </div>
      )}

      {(state.status === "pending" || inFlight) && (
        <div className={styles.actions}>
          <button
            type="button"
            className={styles.confirmBtn}
            onClick={onConfirm}
            disabled={inFlight}
          >
            {inFlight && state.approved ? (
              <>
                <span className={styles.spinner} aria-hidden />
                Applying…
              </>
            ) : (
              "Confirm"
            )}
          </button>
          <button
            type="button"
            className={styles.cancelBtn}
            onClick={onCancel}
            disabled={inFlight}
          >
            {inFlight && !state.approved ? "Cancelling…" : "Cancel"}
          </button>
        </div>
      )}

      {resolved && (
        <div className={styles.resolved}>
          {state.status === "executed" && (
            <span className={styles.resolvedOk}>
              ✓{" "}
              {state.link ? (
                <a href={state.link} className={styles.resolvedLink}>
                  {state.summary}
                </a>
              ) : (
                state.summary
              )}
            </span>
          )}
          {state.status === "cancelled" && (
            <span className={styles.resolvedMuted}>✕ Cancelled</span>
          )}
          {state.status === "error" && (
            <span className={styles.resolvedError}>⚠ {state.message}</span>
          )}
        </div>
      )}
    </div>
  );
}
