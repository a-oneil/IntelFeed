import { useEffect, useRef, useState } from "react";
import { useFocusTrap } from "@/hooks/useFocusTrap";
import { useDialogStore, type DialogRequest } from "@/stores/dialogStore";

import styles from "./AppDialog.module.css";

const DEFAULT_TITLE: Record<DialogRequest["kind"], string> = {
  confirm: "Are you sure?",
  alert: "Heads up",
  prompt: "Enter a value",
};

/**
 * The app's own confirm / alert / prompt, standing in for the browser's.
 *
 * Focus starts on Cancel for a destructive action and on the accept control
 * otherwise, matching the native dialogs' bias toward the safe choice while
 * keeping a plain "yes?" one Enter away.
 */
export function AppDialog({ request }: { request: DialogRequest }) {
  const trapRef = useFocusTrap<HTMLDivElement>();
  const initialFocusRef = useRef<HTMLButtonElement | HTMLInputElement>(null);
  const settle = useDialogStore((s) => s.settle);
  const [value, setValue] = useState(request.defaultValue ?? "");
  // The capture-phase key handler below is registered once per dialog, so it
  // would close over the first render's `value`. It reads the ref instead.
  const valueRef = useRef(value);
  valueRef.current = value;

  const isPrompt = request.kind === "prompt";
  const isAlert = request.kind === "alert";
  const required = request.required ?? true;
  const canAccept = !isPrompt || !required || value.trim().length > 0;

  const accept = () => {
    const current = valueRef.current.trim();
    if (isPrompt && required && !current) return;
    settle(request.id, isPrompt ? current : true);
  };
  // An alert has nothing to decline — dismissing it is acknowledging it.
  const cancel = () => settle(request.id, isAlert ? true : isPrompt ? null : false);

  // Declared after useFocusTrap so this runs second and wins the initial focus.
  useEffect(() => {
    initialFocusRef.current?.focus();
    if (initialFocusRef.current instanceof HTMLInputElement) initialFocusRef.current.select();
  }, []);

  // The entry list and reader bind j/k/o/Enter/Escape on window/document and
  // only skip text inputs, so without this a focused dialog button would also
  // open the selected article or close the reader behind us. Keys are swallowed
  // in the capture phase, except Tab, which the focus trap needs.
  //
  // Swallowing in capture also means the dialog's own elements never see the
  // event, so Enter-to-submit is handled here rather than on the input. (Enter
  // on a focused button still works: stopPropagation doesn't stop the browser's
  // default activation, and settling twice is a no-op.)
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        cancel();
      } else if (e.key !== "Tab") {
        e.stopPropagation();
        if (e.key === "Enter" && isPrompt && e.target instanceof HTMLInputElement) {
          e.preventDefault();
          accept();
        }
      }
    };
    document.addEventListener("keydown", onKeyDown, true);
    return () => document.removeEventListener("keydown", onKeyDown, true);
    // `cancel` closes over the request, which is stable for this dialog's life.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [request.id]);

  const titleId = `app-dialog-title-${request.id}`;

  return (
    <div className={styles.overlay} onClick={cancel}>
      <div
        className={styles.modal}
        ref={trapRef}
        role={isAlert ? "alertdialog" : "dialog"}
        aria-modal="true"
        aria-labelledby={titleId}
        data-kind={request.kind}
        onClick={(e) => e.stopPropagation()}
      >
        <h3 id={titleId} className={styles.title}>
          {request.title ?? DEFAULT_TITLE[request.kind]}
        </h3>

        {/* pre-wrap so messages carried over from the native dialogs keep the
            line breaks they were written with. */}
        <p className={styles.message} data-testid="app-dialog-message">
          {request.message}
        </p>

        {isPrompt && (
          <input
            ref={initialFocusRef as React.RefObject<HTMLInputElement>}
            className={styles.input}
            type="text"
            value={value}
            placeholder={request.placeholder}
            aria-label={request.message}
            onChange={(e) => setValue(e.target.value)}
          />
        )}

        <div className={styles.actions}>
          {!isAlert && (
            <button
              ref={request.destructive && !isPrompt ? (initialFocusRef as React.RefObject<HTMLButtonElement>) : undefined}
              type="button"
              className={styles.secondaryBtn}
              onClick={cancel}
            >
              {request.cancelLabel ?? "Cancel"}
            </button>
          )}
          <button
            ref={request.destructive || isPrompt ? undefined : (initialFocusRef as React.RefObject<HTMLButtonElement>)}
            type="button"
            className={request.destructive ? styles.dangerBtn : styles.primaryBtn}
            onClick={accept}
            disabled={!canAccept}
            data-testid="app-dialog-accept"
          >
            {request.confirmLabel ?? (isAlert ? "OK" : isPrompt ? "Save" : "Confirm")}
          </button>
        </div>
      </div>
    </div>
  );
}
