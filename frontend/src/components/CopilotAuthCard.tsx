import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import {
  useCancelCopilotAuth,
  useCopilotAuthSession,
  useCopilotAuthStatus,
  useStartCopilotAuth,
  useSubmitCopilotAuthCode,
  type CopilotAuthStatus,
} from "@/hooks/useCopilotAuth";

import { Chip } from "./primitives";
import styles from "./CopilotAuthCard.module.css";

type Health = "authenticated" | "expiring" | "expired" | "unknown";

function classifyHealth(status: CopilotAuthStatus | undefined): { health: Health; label: string } {
  if (!status || status.state === "unknown") return { health: "unknown", label: "Checking…" };
  if (!status.exists) return { health: "expired", label: "Not authenticated" };
  if (!status.valid) return { health: "expired", label: "Expired — re-authenticate" };

  if (status.expires_at) {
    const msLeft = status.expires_at - Date.now();
    const days = Math.floor(msLeft / 86_400_000);
    const hours = Math.floor(msLeft / 3_600_000);
    const left = days >= 1 ? `${days} day${days === 1 ? "" : "s"}` : `${Math.max(hours, 0)}h`;
    return { health: hours < 48 ? "expiring" : "authenticated", label: `Authenticated · expires in ${left}` };
  }
  return { health: "authenticated", label: "Authenticated" };
}

export default function CopilotAuthCard({ embedded = false }: { embedded?: boolean }) {
  const qc = useQueryClient();
  const { data: status, isLoading } = useCopilotAuthStatus();

  const [sessionId, setSessionId] = useState<string | null>(null);
  const [code, setCode] = useState("");

  const start = useStartCopilotAuth();
  const submitCode = useSubmitCopilotAuthCode();
  const cancel = useCancelCopilotAuth();
  const { data: session } = useCopilotAuthSession(sessionId);

  const flowState = session?.state ?? (sessionId ? "starting" : null);

  // React to terminal states.
  useEffect(() => {
    if (!session) return;
    if (session.state === "success") {
      toast.success("Copilot re-authenticated");
      qc.invalidateQueries({ queryKey: ["copilot-auth-status"] });
      setSessionId(null);
      setCode("");
    } else if (["error", "timeout", "expired"].includes(session.state)) {
      toast.error(session.message || "Re-authentication failed");
    } else if (session.state === "cancelled") {
      setSessionId(null);
      setCode("");
    }
  }, [session, qc]);

  const { health, label } = classifyHealth(status);

  const beginReauth = async () => {
    setCode("");
    try {
      const { session_id } = await start.mutateAsync();
      setSessionId(session_id);
    } catch (err) {
      const msg =
        (err as { response?: { data?: { message?: string } } })?.response?.data?.message ||
        "Couldn't start re-authentication";
      toast.error(msg);
    }
  };

  const handleSubmitCode = async () => {
    if (!sessionId || !code.trim()) return;
    try {
      await submitCode.mutateAsync({ sessionId, code: code.trim() });
    } catch {
      toast.error("Couldn't submit code");
    }
  };

  const handleCancel = async () => {
    if (sessionId) {
      try {
        await cancel.mutateAsync(sessionId);
      } catch {
        /* best effort */
      }
    }
    setSessionId(null);
    setCode("");
  };

  const active = sessionId !== null && !["success", "cancelled"].includes(session?.state ?? "");

  return (
    <div className={`${styles.card} ${embedded ? styles.embedded : ""}`}>
      <div className={styles.header}>
        <div>
          <h3 className={styles.title}>Copilot authentication</h3>
          <p className={styles.subtitle}>
            The Ask&nbsp;IntelFeed copilot signs in to Claude with a Max-plan OAuth session that
            expires periodically. Re-authenticate here when it lapses.
          </p>
        </div>
        {!active && (
          <button className={styles.primaryBtn} onClick={beginReauth} disabled={start.isPending || isLoading}>
            {start.isPending ? "Starting…" : health === "authenticated" ? "Re-authenticate" : "Authenticate"}
          </button>
        )}
      </div>

      <div className={styles.statusRow}>
        <span className={`${styles.dot} ${styles[health]}`} />
        <span className={styles.statusLabel}>{label}</span>
        {status?.subscription_type && (
          <Chip tone="toned" tint="var(--accent)" className={styles.pill}>
            {status.subscription_type}
          </Chip>
        )}
      </div>

      {active && (
        <div className={styles.flow}>
          {(flowState === "starting" || flowState === undefined) && (
            <p className={styles.flowNote}>Contacting the CLI worker…</p>
          )}

          {flowState === "awaiting_code" && session?.url && (
            <>
              <ol className={styles.steps}>
                <li>
                  <a className={styles.authLink} href={session.url} target="_blank" rel="noreferrer">
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
                  onKeyDown={(e) => e.key === "Enter" && handleSubmitCode()}
                  placeholder="Paste authorization code"
                  autoFocus
                  spellCheck={false}
                />
                <button
                  className={styles.primaryBtn}
                  onClick={handleSubmitCode}
                  disabled={!code.trim() || submitCode.isPending}
                >
                  {submitCode.isPending ? "Submitting…" : "Submit"}
                </button>
              </div>
            </>
          )}

          {flowState === "exchanging" && <p className={styles.flowNote}>Completing sign-in…</p>}

          {["error", "timeout", "expired"].includes(flowState ?? "") && (
            <p className={styles.flowError}>{session?.message || "Re-authentication failed."}</p>
          )}

          <button className={styles.cancelBtn} onClick={handleCancel}>
            Cancel
          </button>
        </div>
      )}
    </div>
  );
}
