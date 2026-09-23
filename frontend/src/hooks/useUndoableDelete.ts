import { useCallback, useRef } from "react";
import { toast } from "sonner";

const UNDO_DELAY_MS = 5000;

/**
 * Returns a function that, when called, shows an undo toast and delays the
 * actual delete by 5 seconds. If the user clicks "Undo", the delete is cancelled.
 *
 * The delete is triggered by sonner's own toast lifecycle (onAutoClose / onDismiss),
 * which lives in the root <Toaster> provider — independent of the calling component's
 * mount state. This means the delete fires even if the component unmounts (e.g. modal
 * closes, page navigates away) during the undo window.
 *
 * Usage:
 *   const deleteFeed = useDeleteFeed();
 *   const undoableDelete = useUndoableDelete();
 *
 *   // Instead of: if (confirm("Delete?")) deleteFeed.mutate(id);
 *   // Do:
 *   undoableDelete({
 *     label: 'Feed "My Feed"',
 *     onDelete: () => deleteFeed.mutate(id),
 *   });
 */
export function useUndoableDelete() {
  const pendingKeys = useRef(new Set<string>());
  const counterRef = useRef(0);

  return useCallback(
    (opts: {
      /** Human-readable label, e.g. 'Feed "My Feed"' or 'detection rule' */
      label: string;
      /** Called after the undo window if user does NOT undo */
      onDelete: () => void;
      /** Called immediately before showing the toast (e.g. close a modal) */
      onInitiate?: () => void;
      /** Optional unique key to prevent duplicate pending deletes for the same item */
      key?: string;
      /** Past-tense verb for the toast, when "deleted" would misdescribe it
       *  (e.g. an observable that is tombstoned rather than removed). */
      verb?: string;
    }) => {
      const key = opts.key ?? `undo-${++counterRef.current}`;

      // If there's already a pending delete for this key, skip
      if (pendingKeys.current.has(key)) return;
      pendingKeys.current.add(key);

      // Run any immediate side effects (close modal, context menu, etc.)
      opts.onInitiate?.();

      let cancelled = false;

      const doDelete = () => {
        pendingKeys.current.delete(key);
        if (!cancelled) {
          opts.onDelete();
        }
      };

      toast(`${opts.label} ${opts.verb ?? "deleted"}`, {
        duration: UNDO_DELAY_MS,
        action: {
          label: "Undo",
          onClick: () => {
            cancelled = true;
            pendingKeys.current.delete(key);
            toast.success("Restored");
          },
        },
        onAutoClose: doDelete,
        onDismiss: doDelete,
      });
    },
    []
  );
}
