import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { Feed, PaginatedResponse } from "@/api/types";
import { readExternalLinkSettings } from "@/hooks/useExternalLinkSettings";
import { useAuthStore } from "@/stores/authStore";
import { useExternalLinkStore } from "@/stores/externalLinkStore";
import { evaluateLinkClick, hostsFromUrls } from "@/utils/externalLinks";
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
  const queryClient = useQueryClient();
  const pending = useExternalLinkStore((s) => s.pending);

  useEffect(() => {
    const handler = (event: MouseEvent) => {
      if (event.type === "click" && event.button !== 0) return;
      if (event.type === "auxclick" && event.button !== 1) return;
      if (!(event.target instanceof Element)) return;

      const anchor = event.target.closest("a[href]");
      if (!(anchor instanceof HTMLAnchorElement)) return;

      const { mode, trustedHosts } = readExternalLinkSettings(useAuthStore.getState().user);
      // Feeds are only ever read from the cache: fetching here would fire an
      // authenticated request from public pages (shared entries) that have none.
      const feeds = queryClient.getQueryData<PaginatedResponse<Feed>>(["feeds"])?.items ?? [];
      const feedHosts = hostsFromUrls(feeds.flatMap((f) => [f.site_url, f.url]));

      const info = evaluateLinkClick(anchor, event, {
        origin: window.location.origin,
        mode,
        trustedHosts: [...trustedHosts, ...useExternalLinkStore.getState().sessionTrustedHosts],
        feedHosts,
      });
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
  }, [queryClient]);

  return pending ? <ExternalLinkModal info={pending} /> : null;
}
