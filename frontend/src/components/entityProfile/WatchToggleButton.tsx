/** WatchToggleButton: one-click watch toggle in the entity profile header. Mute stays in the ⋯ menu (EntityActionsMenu) because it is used less often; watching is common enough to get its own button. */
import { toast } from "sonner";
import { useDeleteWatch, useUpsertWatch, useWatchlist } from "@/hooks/useWatchlist";
import type { EntityType } from "@/stores/intelStore";
import styles from "./entityProfile.module.css";

// The profile types from WATCHABLE_ENTITY_TYPES in backend/app/api/watchlist.py (the backend set also has ransomware_victim and observable, which have no entity profile header).
const WATCHABLE_TYPES = new Set(["threat_actor", "malware", "cve", "cwe", "tool", "vendor", "product", "country", "sector"]);

export function WatchToggleButton({
  entityType,
  entityId,
  displayName,
}: {
  entityType: EntityType;
  entityId: string;
  displayName: string;
}) {
  const { data: watchlist } = useWatchlist();
  const upsertWatch = useUpsertWatch();
  const deleteWatch = useDeleteWatch();

  if (!WATCHABLE_TYPES.has(entityType)) return null;

  const mode = watchlist?.find((w) => w.entity_type === entityType && w.entity_id === entityId)?.mode ?? null;
  const isWatching = mode === "watch";
  const isMuted = mode === "mute";

  // Watch and the Threats board's Track are the same action. Watching an actor, malware family or CVE boosts it in the Priority Queue and pins it to the Threats board; unwatching clears the pin (handled/muted decisions are kept).
  const onBoard = entityType === "threat_actor" || entityType === "malware" || entityType === "cve";

  const toggle = async () => {
    try {
      if (isWatching) {
        await deleteWatch.mutateAsync({ entity_type: entityType, entity_id: entityId });
        toast.success(
          onBoard ? `Stopped watching ${displayName}. Unpinned from Threats.` : `Stopped watching ${displayName}`
        );
      } else {
        await upsertWatch.mutateAsync({ entity_type: entityType, entity_id: entityId, mode: "watch" });
        toast.success(
          onBoard
            ? `Watching ${displayName}. Boosted in the Priority Queue and pinned to Threats.`
            : `Watching ${displayName}. Boosted in the Priority Queue.`
        );
      }
    } catch {
      toast.error("Could not update the watch");
    }
  };

  return (
    <button
      className={styles.primaryBtn}
      onClick={toggle}
      disabled={isMuted || upsertWatch.isPending || deleteWatch.isPending}
      title={
        isMuted
          ? "Muted. Remove the mute in the ⋯ menu to watch."
          : isWatching
            ? "Stop watching (removes the boost and the Threats pin)"
            : "Watch this entity. It is boosted in the Priority Queue and pinned to the Threats board."
      }
    >
      {isWatching ? "Watching" : "Watch"}
    </button>
  );
}
