import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import api from "@/api/client";
import { useAuthStore } from "@/stores/authStore";

import styles from "./EntryPipelineStatus.module.css";

interface StageRun {
  stage: string;
  label: string;
  status: string;
  duration_ms: number | null;
  error: string | null;
  created_at: string | null;
  retryable: boolean;
}

/** Per-entry pipeline stage runs popover (engine phase 5). Renders nothing until opened. */
export function EntryPipelineStatus({ entryId }: { entryId: string }) {
  const [open, setOpen] = useState(false);
  // Stage retry is an admin-only endpoint.
  const isAdmin = useAuthStore((s) => s.user?.role === "admin");
  const qc = useQueryClient();
  const { data } = useQuery({
    queryKey: ["engine", "entry-runs", entryId],
    queryFn: async () => {
      const res = await api.get<{ runs: StageRun[] }>(`/engine/entries/${entryId}/runs`);
      return res.data.runs;
    },
    enabled: open,
    staleTime: 15_000,
  });

  const retry = async (stage: string) => {
    try {
      await api.post(`/engine/entries/${entryId}/stages/${stage}/retry`);
      toast.success(`${stage} re-dispatched`);
      setTimeout(() => qc.invalidateQueries({ queryKey: ["engine", "entry-runs", entryId] }), 3000);
    } catch (err) {
      const data = (err as { response?: { data?: { error?: { message?: string }; detail?: string } } })
        ?.response?.data;
      toast.error(data?.error?.message || data?.detail || "Retry failed");
    }
  };

  const hasError = data?.some((r) => r.status === "error");

  return (
    <span className={styles.wrap}>
      <button
        className={`${styles.trigger} ${hasError ? styles.triggerError : ""}`}
        onClick={() => setOpen((o) => !o)}
        title="Pipeline processing status"
      >
        ⚙
      </button>
      {open && (
        <div className={styles.popover}>
          <div className={styles.popoverTitle}>Processing</div>
          {!data?.length && (
            <div className={styles.empty}>
              No stage runs recorded — this entry was ingested before pipeline
              logging was enabled. Stages are recorded for every entry ingested
              from then on.
            </div>
          )}
          {data?.map((run) => (
            <div key={run.stage} className={styles.row} title={run.error ?? undefined}>
              <span className={run.status === "error" ? styles.statusError : styles.statusOk}>
                {run.status === "error" ? "✕" : run.status === "retry" ? "↻" : "✓"}
              </span>
              <span className={styles.label}>{run.label}</span>
              <span className={styles.duration}>{run.duration_ms != null ? `${run.duration_ms}ms` : ""}</span>
              {isAdmin && run.status === "error" && run.retryable && (
                <button className={styles.retryBtn} onClick={() => retry(run.stage)}>
                  retry
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </span>
  );
}
