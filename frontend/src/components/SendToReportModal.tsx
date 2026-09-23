import { toast } from "sonner";
import { useNavigate } from "react-router-dom";
import { useUIStore } from "@/stores/uiStore";
import { useIntelReports, useAttachToReport } from "@/hooks/useIntelReports";
import styles from "./SendToReportModal.module.css";

/**
 * The one send-to-report surface. Every report button in the app opens this:
 * add the current context (entries + entities) to an open draft, or start a
 * new report seeded from it. Replaces the seven bespoke "Report" buttons that
 * each opened a blank wizard.
 */
export function SendToReportModal() {
  const state = useUIStore((s) => s.sendToReportState);
  const close = useUIStore((s) => s.closeSendToReport);
  const navigate = useNavigate();
  const attach = useAttachToReport();
  const { data: drafts } = useIntelReports({
    status: "draft",
    sort_by: "updated_at",
    sort_order: "desc",
    limit: 8,
  });

  if (!state?.isOpen) return null;
  const { payload } = state;
  const hasEvidence = (payload.entryIds?.length ?? 0) > 0 || Object.keys(payload.entityIds ?? {}).length > 0;

  const addToDraft = async (reportId: string, title: string) => {
    try {
      await attach.mutateAsync({
        reportId,
        entry_ids: payload.entryIds,
        entity_ids: payload.entityIds,
        note: payload.note,
      });
      toast.success(`Added to “${title}”`, {
        action: { label: "Open", onClick: () => navigate(`/workbench/report/${reportId}`) },
      });
      close();
    } catch {
      /* interceptor toasts */
    }
  };

  return (
    <div className={styles.overlay} onClick={close}>
      <div className={styles.modal} role="dialog" aria-label="Send to report" onClick={(e) => e.stopPropagation()}>
        <div className={styles.header}>
          <span className={styles.title}>Send to report</span>
          {payload.label && <span className={styles.context}>{payload.label}</span>}
        </div>

        {hasEvidence && (drafts?.items.length ?? 0) > 0 && (
          <div className={styles.group}>
            <span className={styles.groupLabel}>Add to an open draft</span>
            {drafts!.items.map((d) => (
              <button
                key={d.id}
                className={styles.item}
                disabled={attach.isPending}
                onClick={() => addToDraft(d.id, d.title)}
              >
                <span className={styles.itemTitle}>{d.title}</span>
                <span className={styles.itemMeta}>
                  {d.template_type.replace(/_/g, " ")} · {d.tlp_marking}
                </span>
              </button>
            ))}
          </div>
        )}

        <div className={styles.group}>
          <span className={styles.groupLabel}>Start new</span>
          {payload.wizardState && (
            <button
              className={styles.item}
              onClick={() => {
                const wizard = payload.wizardState!;
                close();
                useUIStore.getState().openReportWizard(wizard);
              }}
            >
              <span className={styles.itemTitle}>AI report from this</span>
              <span className={styles.itemMeta}>Pick a template — sections draft from the selected sources</span>
            </button>
          )}
          <button
            className={styles.item}
            onClick={() => {
              close();
              navigate("/workbench/report/exposure");
            }}
          >
            <span className={styles.itemTitle}>Threat Exposure Report</span>
            <span className={styles.itemMeta}>From an intel profile — regions × verticals</span>
          </button>
        </div>

        <button className={styles.cancel} onClick={close}>
          Cancel
        </button>
      </div>
    </div>
  );
}
