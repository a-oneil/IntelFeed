import { useUIStore } from "@/stores/uiStore";
import { AddFeedModal } from "@/components/AddFeedModal";
import { KeyboardShortcutsHelp } from "@/components/KeyboardShortcutsHelp";
import { IngestModal } from "@/components/IngestModal";
import { ExternalLinkGuard } from "@/components/ExternalLinkGuard";

/**
 * App-shell modals whose triggers are scattered across layouts, the sidebar and
 * the command palette. Rendering them once at the root keeps them reachable
 * from any of those — the add-feed dialog in particular used to live inside the
 * sidebar, which sets `visibility: hidden` when collapsed.
 */
export function GlobalModals() {
  const addFeedOpen = useUIStore((s) => s.addFeedOpen);
  const closeAddFeed = useUIStore((s) => s.closeAddFeed);
  const ingestOpen = useUIStore((s) => s.ingestOpen);
  const closeIngest = useUIStore((s) => s.closeIngest);
  const shortcutsHelpOpen = useUIStore((s) => s.shortcutsHelpOpen);
  const closeShortcutsHelp = useUIStore((s) => s.closeShortcutsHelp);

  return (
    <>
      {addFeedOpen && <AddFeedModal onClose={closeAddFeed} />}
      {ingestOpen && <IngestModal onClose={closeIngest} />}
      {shortcutsHelpOpen && <KeyboardShortcutsHelp onClose={closeShortcutsHelp} />}
      <ExternalLinkGuard />
    </>
  );
}
