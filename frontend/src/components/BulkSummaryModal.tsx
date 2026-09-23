import { useEffect, useRef } from "react";
import { useBulkSummarize } from "@/hooks/useAI";
import styles from "./BulkSummaryModal.module.css";

interface Props {
  entryIds: string[];
  onClose: () => void;
}

export function BulkSummaryModal({ entryIds, onClose }: Props) {
  const summarize = useBulkSummarize();
  const triggered = useRef(false);

  useEffect(() => {
    if (!triggered.current && entryIds.length > 0) {
      triggered.current = true;
      summarize.mutate(entryIds);
    }
  }, [entryIds, summarize]);

  return (
    <div className={styles.overlay} onClick={onClose}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
        <div className={styles.header}>
          <span className={styles.title}>
            Summary — {entryIds.length} articles
          </span>
          <button className={styles.closeBtn} onClick={onClose}>
            &times;
          </button>
        </div>

        <div className={styles.body}>
          {summarize.isPending && (
            <div className={styles.loading}>
              <div className={styles.spinner} />
              <span>Summarizing {entryIds.length} articles...</span>
            </div>
          )}

          {summarize.isError && (
            <div className={styles.error}>
              {(summarize.error as Error)?.message || "Failed to generate summary"}
            </div>
          )}

          {summarize.isSuccess && (
            <div className={styles.summary}>
              {summarize.data.summary}
            </div>
          )}
        </div>

        {summarize.isSuccess && (
          <div className={styles.footer}>
            <button
              className={styles.copyBtn}
              onClick={() => {
                navigator.clipboard.writeText(summarize.data.summary);
              }}
            >
              Copy
            </button>
            <button className={styles.closeFooterBtn} onClick={onClose}>
              Close
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
