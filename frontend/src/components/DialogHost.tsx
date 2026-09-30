import { useEffect } from "react";
import { useDialogStore } from "@/stores/dialogStore";
import { setDialogHostMounted } from "@/utils/dialog";
import { AppDialog } from "@/components/AppDialog";

/**
 * Renders whichever confirm/alert/prompt is at the head of the queue.
 *
 * The native dialogs block the thread, so only one could ever be on screen.
 * These don't, so two overlapping calls queue instead of stacking — the second
 * appears once the first is answered.
 */
export function DialogHost() {
  const request = useDialogStore((s) => s.queue[0]);

  useEffect(() => {
    setDialogHostMounted(true);
    return () => setDialogHostMounted(false);
  }, []);

  // Keyed so switching to the next request remounts (fresh input, fresh focus).
  return request ? <AppDialog key={request.id} request={request} /> : null;
}
