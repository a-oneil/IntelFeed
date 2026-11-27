import { useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import styles from "./UnlinkArticleButton.module.css";

/**
 * The row action on the campaign profile's article list.
 *
 * Its sibling, UnlinkArticleButton, removes an extraction link, meaning "this article does not mention that entity". A campaign article was never matched automatically; an analyst added it, so the only meaning here is removing it from the campaign again. It uses a different label and endpoint, in the same place on the row.
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
