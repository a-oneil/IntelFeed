import { useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import styles from "./UnlinkArticleButton.module.css";

/**
 * The campaign profile's row action.
 *
 * Its sibling, UnlinkArticleButton, severs an extraction link — it says "this
 * article does not mention that entity". A campaign article was never matched;
 * an analyst put it there, so the only thing this can mean is taking it back
 * out. Different verb, different endpoint, same affordance on the row.
 */
export function RemoveFromCampaignButton({ campaignId, entryId }: { campaignId: string; entryId: string }) {
  const qc = useQueryClient();
  const undoableDelete = useUndoableDelete();

  const remove = useMutation({
    mutationFn: async () => {
      await api.delete(`/campaigns/${campaignId}/entries/${entryId}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["pivot", "campaign", campaignId] });
      qc.invalidateQueries({ queryKey: ["entity-timeline", "campaign", campaignId] });
      qc.invalidateQueries({ queryKey: ["campaign", campaignId] });
      qc.invalidateQueries({ queryKey: ["campaign-suggestions", campaignId] });
    },
  });

  return (
    <button
      className={styles.unlinkBtn}
      title="Remove from campaign"
      onClick={(e) => {
        e.stopPropagation();
        undoableDelete({
          label: "Campaign article",
          key: `campaign-entry-${campaignId}-${entryId}`,
          onDelete: () => remove.mutate(),
        });
      }}
      disabled={remove.isPending}
    >
      {remove.isPending ? "..." : "✗"}
    </button>
  );
}
