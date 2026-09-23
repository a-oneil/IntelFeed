import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import api from "@/api/client";
import { useApplyMaintenanceProposal } from "@/hooks/useEntityMaintenance";
import {
  useApplyAdvisories,
  useApplyAliasCollision,
  useApplyIdHygiene,
  useApplyNormalizeName,
  useApplyVendorAutolink,
  useDismissFeedRow,
  type FeedRow,
} from "@/hooks/useHygiene";

/** Backend feed ids are "{source}:{uuid}"; the per-row endpoints want the uuid. */
export function extractLogId(row: FeedRow): string {
  const sep = row.id.indexOf(":");
  return sep >= 0 ? row.id.slice(sep + 1) : row.id;
}

/** The one place that routes a proposal-row action ("apply" / "apply_reclassify"
 *  / "promote_to_remove" / "restore" / "dismiss") to the right endpoint. Shared
 *  by the standalone hygiene surface and the Engine console's Proposals queue so
 *  both apply through identical code paths. */
export function useHygieneRowAction() {
  const qc = useQueryClient();
  const dismissRow = useDismissFeedRow();
  const applyMaintenance = useApplyMaintenanceProposal();
  const applyNormalizeName = useApplyNormalizeName();
  const applyAliasCollision = useApplyAliasCollision();
  const applyVendorAutolink = useApplyVendorAutolink();
  const applyIdHygiene = useApplyIdHygiene();
  const applyAdvisories = useApplyAdvisories();

  const invalidate = () => qc.invalidateQueries({ queryKey: ["hygiene"] });

  return async function handleRowAction(row: FeedRow, action: string) {
    if (action === "dismiss") {
      try {
        await dismissRow.mutateAsync({ source: row.source, id: extractLogId(row) });
        toast.success("Dismissed");
      } catch (e) {
        toast.error(`Dismiss failed: ${(e as Error).message}`);
      }
      return;
    }
    if (action === "restore") {
      try {
        await api.post(`/admin/link-validation/log/${extractLogId(row)}/restore`);
        toast.success("Link restored");
        invalidate();
      } catch (e) {
        toast.error(`Restore failed: ${(e as Error).message}`);
      }
      return;
    }
    if (action === "apply" && row.source === "entity_maintenance") {
      if (row.action === "normalize_name") {
        try {
          const result = await applyNormalizeName.mutateAsync(extractLogId(row));
          if (result.skipped) toast.message("Already gone — proposal marked applied");
          else if (result.kind === "merge_into_canonical")
            toast.success(`Merged into ${result.new_name ?? "canonical entity"}`);
          else toast.success(`Renamed to ${result.new_name ?? "new name"}`);
        } catch (e) {
          toast.error(`Apply failed: ${(e as Error).message}`);
        }
        return;
      }
      if (row.action === "alias_collision") {
        try {
          const r = await applyAliasCollision.mutateAsync(extractLogId(row));
          if (r.skipped) toast.message("Alias was already gone — marked applied.");
          else toast.success(`Removed alias '${r.removed_alias ?? "?"}'`);
        } catch (e) {
          toast.error(`Apply failed: ${(e as Error).message}`);
        }
        return;
      }
      if (row.action === "vendor_autolink") {
        try {
          const r = await applyVendorAutolink.mutateAsync(extractLogId(row));
          if (r.skipped) toast.message("Product or vendor missing — marked applied.");
          else toast.success("Vendor linked");
        } catch (e) {
          toast.error(`Apply failed: ${(e as Error).message}`);
        }
        return;
      }
      if (row.action === "ttp_malformed_id" || row.action === "cve_malformed_id" || row.action === "cve_withdrawn") {
        try {
          const r = await applyIdHygiene.mutateAsync(extractLogId(row));
          if (r.skipped) toast.message("Entity already gone — marked applied.");
          else if (r.action_taken === "renamed") toast.success(`Renamed to ${r.new_id ?? "canonical id"}`);
          else if (r.action_taken === "deleted") toast.success("Withdrawn CVE deleted");
          else toast.success("Applied");
        } catch (e) {
          toast.error(`Apply failed: ${(e as Error).message}`);
        }
        return;
      }
      // merge_cluster_summary + orphan_prune go through the legacy apply endpoint.
      try {
        const result = await applyMaintenance.mutateAsync(extractLogId(row));
        toast.success(`Applied ${result.succeeded}/${result.attempted} (skipped ${result.skipped})`);
      } catch (e) {
        toast.error(`Apply failed: ${(e as Error).message}`);
      }
      return;
    }
    if (action === "apply_reclassify" && row.source === "link_validator") {
      if (!row.entity_type) {
        toast.error("Missing entity type on advisory");
        return;
      }
      try {
        const result = await applyAdvisories.mutateAsync({ mode: "apply", entity_type: row.entity_type, limit: 50 });
        toast.success(`Applied ${result.applied} reclassifications for ${row.entity_type}`);
      } catch (e) {
        toast.error(`Apply failed: ${(e as Error).message}`);
      }
      return;
    }
    if (action === "promote_to_remove") {
      try {
        const res = await api.post<{ already_removed: boolean }>(
          `/admin/link-validation/log/${extractLogId(row)}/apply-removal`,
        );
        toast.success(res.data.already_removed ? "Link was already removed" : "Link removed");
        invalidate();
      } catch (e) {
        toast.error(`Promote failed: ${(e as Error).message}`);
      }
      return;
    }
  };
}
