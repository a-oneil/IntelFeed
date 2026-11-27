import { useState } from "react";
import { useUIStore } from "@/stores/uiStore";
import { AddFeedModal } from "@/components/AddFeedModal";
import { EditFeedModal } from "@/components/feedModal/EditFeedModal";
import type { Feed } from "@/api/types";
import { KeyboardShortcutsHelp } from "@/components/KeyboardShortcutsHelp";
import { IngestModal } from "@/components/IngestModal";
import { ExternalLinkGuard } from "@/components/ExternalLinkGuard";
import { DialogHost } from "@/components/DialogHost";

/** App-shell modals whose triggers are spread across layouts, the sidebar and the command palette. Rendering them once at the root keeps them reachable from all of those; the add-feed dialog in particular can't live inside the sidebar, which sets `visibility: hidden` when collapsed. */
export function GlobalModals() {
  const addFeedOpen = useUIStore((s) => s.addFeedOpen);
  const closeAddFeed = useUIStore((s) => s.closeAddFeed);
  const ingestOpen = useUIStore((s) => s.ingestOpen);
  const closeIngest = useUIStore((s) => s.closeIngest);
  const shortcutsHelpOpen = useUIStore((s) => s.shortcutsHelpOpen);
  const closeShortcutsHelp = useUIStore((s) => s.closeShortcutsHelp);
  // A feed just added opens straight into its settings.
  const [addedFeed, setAddedFeed] = useState<Feed | null>(null);

  return (
    <>
      {addFeedOpen && (
        <AddFeedModal
          onClose={closeAddFeed}
          onAdded={(feed) => {
            closeAddFeed();
            setAddedFeed(feed);
          }}
        />
      )}
      {addedFeed && <EditFeedModal subscription={addedFeed} onClose={() => setAddedFeed(null)} />}
      {ingestOpen && <IngestModal onClose={closeIngest} />}
      {shortcutsHelpOpen && <KeyboardShortcutsHelp onClose={closeShortcutsHelp} />}
      <ExternalLinkGuard />
      <DialogHost />
    </>
  );
}
