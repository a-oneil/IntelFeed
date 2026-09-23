import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";

import { useFocusTrap } from "@/hooks/useFocusTrap";
import {
  useCancelCopilotAuth,
  useCopilotAuthSession,
  useStartCopilotAuth,
  useSubmitCopilotAuthCode,
} from "@/hooks/useCopilotAuth";

import styles from "./CopilotReauthModal.module.css";

interface Props {
  open: boolean;
  onClose: () => void;
  onSuccess?: () => void;
}

/**
 * Compact dialog that runs the copilot OAuth re-auth flow (auto-started on open):
 * shows the Claude sign-in link, takes the pasted code, and reports the result.
 * Reuses the same hooks + backend flow as the Settings card.
 */
export default function CopilotReauthModal({ open, onClose, onSuccess }: Props) {
  const trapRef = useFocusTrap<HTMLDivElement>();
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const startedRef = useRef(false);

  const start = useStartCopilotAuth();
  const submitCode = useSubmitCopilotAuthCode();
  const cancel = useCancelCopilotAuth();
  const { data: session } = useCopilotAuthSession(sessionId);

  const begin = () => {
    setCode("");
    start
      .mutateAsync()
      .then(({ session_id }) => setSessionId(session_id))
      .catch((err) => {
        const msg =
          (err as { response?: { data?: { message?: string } } })?.response?.data?.message ||
          "Couldn't start re-authentication";
        toast.error(msg);
        onClose();
      });
  };

  // Auto-start once per open; reset when closed.
  useEffect(() => {
    if (!open) {
      startedRef.current = false;
      setSessionId(null);
      setCode("");
      return;
    }
    if (startedRef.current) return;
    startedRef.current = true;
    begin();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  // React to terminal states.
  useEffect(() => {
    if (!session) return;
    if (session.state === "success") {
      toast.success("Copilot re-authenticated");
      onSuccess?.();
      onClose();
    } else if (session.state === "cancelled") {
      onClose();
    }
    // error / timeout / expired stay visible with a retry button.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session?.state]);

  const handleSubmit = async () => {
    if (!sessionId || !code.trim()) return;
    try {
      await submitCode.mutateAsync({ sessionId, code: code.trim() });
    } catch {
      toast.error("Couldn't submit code");
    }
  };

  const handleClose = async () => {
    if (sessionId) {
      try {
        await cancel.mutateAsync(sessionId);
      } catch {
        /* best effort */
      }
    }
    onClose();
  };

  const retry = () => {
    setSessionId(null);
    startedRef.current = true;
    begin();
  };

  if (!open) return null;

  const flowState = session?.state ?? "starting";
  const failed = ["error", "timeout", "expired"].includes(flowState);

  return (
    <div className={styles.overlay} onClick={handleClose}>
      <div
        className={styles.modal}
        ref={trapRef}
        role="dialog"
        aria-modal="true"
        aria-label="Re-authenticate copilot"
        onClick={(e) => e.stopPropagation()}
      >
        <h3 className={styles.title}>Re-authenticate copilot</h3>

        {(flowState === "starting" || flowState === undefined) && (
          <p className={styles.note}>Contacting the CLI worker…</p>
        )}

        {flowState === "awaiting_code" && session?.url && (
          <>
            <ol className={styles.steps}>
              <li>
                <a className={styles.link} href={session.url} target="_blank" rel="noreferrer">
                  Open the Claude sign-in page ↗
                </a>{" "}
                and authorize with your Max account.
              </li>
              <li>Copy the code it gives you and paste it below.</li>
            </ol>
            <div className={styles.codeRow}>
              <input
                className={styles.codeInput}
                value={code}
                onChange={(e) => setCode(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
                placeholder="Paste authorization code"
                autoFocus
                spellCheck={false}
              />
              <button
                className={styles.primaryBtn}
                onClick={handleSubmit}
                disabled={!code.trim() || submitCode.isPending}
              >
                {submitCode.isPending ? "Submitting…" : "Submit"}
              </button>
            </div>
          </>
        )}

        {flowState === "exchanging" && <p className={styles.note}>Completing sign-in…</p>}

        {failed && (
          <>
            <p className={styles.error}>{session?.message || "Re-authentication failed."}</p>
            <button className={styles.primaryBtn} onClick={retry}>
              Try again
            </button>
          </>
        )}

        <button className={styles.cancelBtn} onClick={handleClose}>
          Cancel
        </button>
      </div>
    </div>
  );
}
