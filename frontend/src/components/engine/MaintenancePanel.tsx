/**
 * MaintenancePanel — the Engine console's Maintenance drawer: global sweeps
 * (orphan prune, full re-extract, proximity backfill) and the destructive
 * resets, with inline confirm. Native replacement for the last remnant of the
 * old WorkbenchHygiene surface.
 */
import { useState } from "react";
import { toast } from "sonner";

import api from "@/api/client";
import { useHygieneStats, usePruneOrphans } from "@/hooks/useHygiene";

import styles from "./MaintenancePanel.module.css";

export function MaintenancePanel() {
  const stats = useHygieneStats();
  const pruneOrphans = usePruneOrphans();

  const [rescanning, setRescanning] = useState(false);
  const [backfilling, setBackfilling] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [deletingRules, setDeletingRules] = useState(false);
  const [confirming, setConfirming] = useState<"reset" | "rules" | null>(null);

  const runOrphanSweep = async () => {
    try {
      const r = await pruneOrphans.mutateAsync({ mode: "apply" });
      toast.success(`Pruned ${r.pruned} orphans` + (r.skipped ? ` (skipped ${r.skipped})` : ""));
    } catch (e) {
      toast.error(`Orphan sweep failed: ${(e as Error).message}`);
    }
  };

  const rescanAll = async () => {
    setRescanning(true);
    try {
      await api.post("/intelligence/rescan-all-extraction");
      toast.success("Rescan queued — regex extraction running on all entries");
    } catch {
      toast.error("Failed to queue rescan");
    } finally {
      setRescanning(false);
    }
  };

  const backfillProximity = async () => {
    setBackfilling(true);
    try {
      await api.post("/autolink/rescan", null, { params: { backfill_proximity: true } });
      toast.success("Proximity backfill queued");
    } catch {
      toast.error("Failed to queue backfill");
    } finally {
      setBackfilling(false);
    }
  };

  const resetCorrelation = async () => {
    setResetting(true);
    setConfirming(null);
    try {
      await api.post("/intelligence/reset-correlation");
      toast.success("Correlation reset queued");
    } catch {
      toast.error("Failed to queue correlation reset");
    } finally {
      setResetting(false);
    }
  };

  const deleteAllRules = async () => {
    setDeletingRules(true);
    setConfirming(null);
    try {
      const res = await api.delete<{ rules_deleted: number }>("/intelligence/detection-rules");
      toast.success(`Deleted ${res.data.rules_deleted} detection rules`);
    } catch {
      toast.error("Failed to delete detection rules");
    } finally {
      setDeletingRules(false);
    }
  };

  return (
    <div className={styles.wrap}>
      <div className={styles.row}>
        <button
          type="button"
          className={styles.btn}
          onClick={runOrphanSweep}
          disabled={pruneOrphans.isPending}
          title="Delete entities with zero linked entries (skips watchlisted / manually curated)"
        >
          {pruneOrphans.isPending ? "Pruning…" : `Prune orphans (${stats.data?.orphan_count ?? 0})`}
        </button>
        <button
          type="button"
          className={styles.btn}
          onClick={rescanAll}
          disabled={rescanning}
          title="Re-run regex TTP/CVE/rule extraction over every stored entry"
        >
          {rescanning ? "Queueing…" : "Rescan all feeds"}
        </button>
        <button
          type="button"
          className={styles.btn}
          onClick={backfillProximity}
          disabled={backfilling}
          title="Recompute paragraph-proximity scores for existing entity links"
        >
          {backfilling ? "Queueing…" : "Backfill proximity"}
        </button>

        <span className={styles.divider} aria-hidden />

        {confirming === "reset" ? (
          <span className={styles.confirm}>
            <span className={styles.confirmText}>Reset correlation — cannot be undone.</span>
            <button type="button" className={styles.btnDanger} onClick={resetCorrelation} disabled={resetting}>
              {resetting ? "Queueing…" : "Confirm reset"}
            </button>
            <button type="button" className={styles.btn} onClick={() => setConfirming(null)} disabled={resetting}>
              Cancel
            </button>
          </span>
        ) : (
          <button
            type="button"
            className={styles.btnDanger}
            onClick={() => setConfirming("reset")}
            disabled={resetting}
            title="Unlink every entity from every entry and zero all article counts. Entities themselves stay; use before a clean re-extract."
          >
            Reset correlation
          </button>
        )}
        {confirming === "rules" ? (
          <span className={styles.confirm}>
            <span className={styles.confirmText}>Delete all rules — cannot be undone.</span>
            <button type="button" className={styles.btnDanger} onClick={deleteAllRules} disabled={deletingRules}>
              {deletingRules ? "Deleting…" : "Confirm delete"}
            </button>
            <button type="button" className={styles.btn} onClick={() => setConfirming(null)} disabled={deletingRules}>
              Cancel
            </button>
          </span>
        ) : (
          <button
            type="button"
            className={styles.btnDanger}
            onClick={() => setConfirming("rules")}
            disabled={deletingRules}
            title="Permanently delete every detection rule and version history (Sigma, Splunk SPL, CrowdStrike QL, Elastic QL, KQL, YARA, Snort/Suricata)."
          >
            Delete all rules
          </button>
        )}
      </div>
    </div>
  );
}
