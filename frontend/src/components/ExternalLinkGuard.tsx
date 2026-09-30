import { useEffect } from "react";
import { useExternalLinkStore } from "@/stores/externalLinkStore";
import { evaluateLinkClick } from "@/utils/externalLinks";
import { currentInterceptContext } from "@/utils/openExternal";
import { ExternalLinkModal } from "@/components/ExternalLinkModal";

/**
 * Holds clicks on off-site links for a confirmation dialog.
 *
 * One capture-phase listener on the document rather than a handler per link:
 * ~60 `target="_blank"` links plus every link inside sanitised feed HTML all go
 * through the same check, and a capture listener runs before any React
 * `onClick` (so a link inside a clickable row can't also trigger the row).
 *
 * `click` covers the mouse, Enter on a focused link, and ⌘/Ctrl/Shift-click;
 * `auxclick` covers middle-click, which browsers do not deliver as a `click`.
 * Right-click → "Open in new tab" is a deliberate act on the browser's own menu
 * and is not intercepted.
 *
 * Preferences are read from the stores at click time, not captured, so
 * changing the setting takes effect without re-subscribing.
 */
export function ExternalLinkGuard() {
  const pending = useExternalLinkStore((s) => s.pending);

  useEffect(() => {
    const handler = (event: MouseEvent) => {
      if (event.type === "click" && event.button !== 0) return;
      if (event.type === "auxclick" && event.button !== 1) return;
      if (!(event.target instanceof Element)) return;

      const anchor = event.target.closest("a[href]");
      if (!(anchor instanceof HTMLAnchorElement)) return;

      const info = evaluateLinkClick(anchor, event, currentInterceptContext());
      if (!info) return;

      event.preventDefault();
      event.stopPropagation();
      useExternalLinkStore.getState().hold(info);
    };

    document.addEventListener("click", handler, true);
    document.addEventListener("auxclick", handler, true);
    return () => {
      document.removeEventListener("click", handler, true);
      document.removeEventListener("auxclick", handler, true);
    };
  }, []);

  return pending ? <ExternalLinkModal info={pending} /> : null;
}
