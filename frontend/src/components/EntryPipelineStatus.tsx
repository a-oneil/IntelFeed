import { useEffect, useRef, useState, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import api from "@/api/client";
import { skipReason, waitingOn } from "@/components/engine/adjudicationCopy";
import { useAuthStore } from "@/stores/authStore";

import styles from "./EntryPipelineStatus.module.css";

export type StageStatus = "success" | "error" | "retry" | "queued" | "skipped" | "not_run";

export interface StageRun {
  stage: string;
  label: string;
  status: StageStatus;
  duration_ms: number | null;
  error: string | null;
  created_at: string | null;
  retryable: boolean;
  detail: { waiting_on?: string; skipped?: string; reused_from?: string | null } | null;
}

export interface EntryRuns {
  /** Overall verdict: an error outranks a finished score, and a queued AI
   *  pass behind a finished score is still in flight. */
  status: "complete" | "errored" | "in_flight" | "unknown";
  /** Every pipeline stage in execution order (translate only when it ran). */
  runs: StageRun[];
}

const GLYPH: Record<StageStatus, string> = {
  success: "✓",
  error: "✕",
  retry: "↻",
  queued: "◌",
  skipped: "—",
  not_run: "·",
};

const GLYPH_CLASS: Record<StageStatus, string> = {
  success: styles.ok,
  error: styles.err,
  retry: styles.warn,
  queued: styles.warn,
  skipped: styles.dim,
  not_run: styles.dim,
};

/** One line under a stage's name, when the status alone does not say enough. */
function subline(run: StageRun): string | null {
  switch (run.status) {
    case "queued":
      return waitingOn(run);
    case "skipped":
      return skipReason(run.detail?.skipped ?? "skipped");
    case "error":
      return run.error;
    case "success":
      return run.detail?.reused_from ? "copied from a near-duplicate" : null;
    default:
      return null;
  }
}

/** The right-hand cell: how long the stage took, or why there is no timing. */
function stateText(run: StageRun): string {
  if (run.duration_ms != null) return `${run.duration_ms}ms`;
  switch (run.status) {
    case "queued":
      return "queued";
    case "skipped":
      return "skipped";
    case "not_run":
      return "not run";
    case "error":
      return "failed";
    default:
      return "";
  }
}

/** Per-entry pipeline status (engine phase 5). The trigger is whatever the
 *  caller passes as children — in the reader, the published timestamp — turned
 *  into a quiet link; nothing is fetched until it is opened. */
export function EntryPipelineStatus({
  entryId,
  className,
  children,
}: {
  entryId: string;
  /** Styles the trigger text (the reader passes its date class). */
  className?: string;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLSpanElement>(null);
  // Stage retry is an admin-only endpoint.
  const isAdmin = useAuthStore((s) => s.user?.role === "admin");
  const qc = useQueryClient();
  const { data } = useQuery({
    queryKey: ["engine", "entry-runs", entryId],
    queryFn: async () => (await api.get<EntryRuns>(`/engine/entries/${entryId}/runs`)).data,
    enabled: open,
    staleTime: 30_000,
  });

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!wrapRef.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const retry = async (stage: string) => {
    try {
      await api.post(`/engine/entries/${entryId}/stages/${stage}/retry`);
      toast.success(`${stage} re-dispatched`);
      setTimeout(() => qc.invalidateQueries({ queryKey: ["engine", "entry-runs", entryId] }), 3000);
    } catch (err) {
      const body = (err as { response?: { data?: { error?: { message?: string }; detail?: string } } })
        ?.response?.data;
      toast.error(body?.error?.message || body?.detail || "Retry failed");
    }
  };

  return (
    <span className={styles.wrap} ref={wrapRef}>
      <button
        type="button"
        className={`${styles.trigger} ${className ?? ""}`}
        title="What the pipeline has done with this article"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        {children}
      </button>
      {open && (
        <div className={styles.popover} role="dialog" aria-label="Pipeline processing">
          <div className={styles.popoverTitle}>Processing</div>
          {!data && <div className={styles.empty}>Loading…</div>}
          {data && !data.runs.length && (
            <div className={styles.empty}>
              No stage runs recorded — this entry was ingested before pipeline
              logging was enabled. Stages are recorded for every entry ingested
              from then on.
            </div>
          )}
          {data?.runs.map((run) => {
            const sub = subline(run);
            return (
              <div key={run.stage} className={styles.row} title={run.error ?? undefined}>
                <span className={`${styles.glyph} ${GLYPH_CLASS[run.status] ?? ""}`} aria-hidden="true">
                  {GLYPH[run.status] ?? "?"}
                </span>
                <span className={styles.label}>
                  <span className={run.status === "not_run" ? styles.labelDim : undefined} data-testid="stage-label">
                    {run.label}
                  </span>
                  {sub && <span className={styles.sub}>{sub}</span>}
                </span>
                <span className={`${styles.state} ${run.status === "error" ? styles.err : ""}`}>
                  {stateText(run)}
                </span>
                {isAdmin && run.status === "error" && run.retryable && (
                  <button className={styles.retryBtn} onClick={() => retry(run.stage)}>
                    retry
                  </button>
                )}
              </div>
            );
          })}
        </div>
      )}
    </span>
  );
}
