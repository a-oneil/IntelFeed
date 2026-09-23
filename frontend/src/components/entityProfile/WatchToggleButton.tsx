/** WatchToggleButton — one-click watch toggle for entity profiles.
 * Mute stays in the ⋯ menu (EntityActionsMenu) since it's a rarer action;
 * watching is common enough to deserve a one-click header button. */
import { toast } from "sonner";
import { useDeleteWatch, useUpsertWatch, useWatchlist } from "@/hooks/useWatchlist";
import type { EntityType } from "@/stores/intelStore";
import styles from "./entityProfile.module.css";

// Mirrors WATCHABLE_ENTITY_TYPES in backend/app/api/watchlist.py.
const WATCHABLE_TYPES = new Set(["threat_actor", "malware", "cve", "cwe", "tool", "vendor", "product", "country"]);

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

  // Watch IS the Threats board's Track: one verb. Watching an actor, malware
  // family or CVE boosts it in the Priority Queue AND pins it to the Threats
  // board; unwatching clears the pin (handled/muted decisions survive).
  const onBoard = entityType === "threat_actor" || entityType === "malware" || entityType === "cve";

  const toggle = async () => {
    try {
      if (isWatching) {
        await deleteWatch.mutateAsync({ entity_type: entityType, entity_id: entityId });
        toast.success(
          onBoard ? `Stopped watching ${displayName} — unpinned from Threats` : `Stopped watching ${displayName}`
        );
      } else {
        await upsertWatch.mutateAsync({ entity_type: entityType, entity_id: entityId, mode: "watch" });
        toast.success(
          onBoard
            ? `Watching ${displayName} — boosted in Triage and pinned to Threats`
            : `Watching ${displayName} — boosted in Triage`
        );
      }
    } catch {
      toast.error("Failed to update watch state");
    }
  };

  return (
    <button
      className={styles.primaryBtn}
      onClick={toggle}
      disabled={isMuted || upsertWatch.isPending || deleteWatch.isPending}
      title={
        isMuted
          ? "Muted — remove the mute in the ⋯ menu to watch"
          : isWatching
            ? "Stop watching (removes the boost and the Threats pin)"
            : "Watch this entity (boosts it in the Priority Queue and pins threats to the Threats board)"
      }
    >
      {isWatching ? "Watching" : "Watch"}
    </button>
  );
}
