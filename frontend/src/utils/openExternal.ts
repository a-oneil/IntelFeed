import type { QueryClient } from "@tanstack/react-query";
import type { Feed, PaginatedResponse } from "@/api/types";
import { readExternalLinkSettings } from "@/hooks/useExternalLinkSettings";
import { queryClient as appQueryClient } from "@/queryClient";
import { useAuthStore } from "@/stores/authStore";
import { readSessionTrustedHosts, useExternalLinkStore } from "@/stores/externalLinkStore";
import {
  evaluateProgrammaticOpen,
  hostsFromUrls,
  isExternalWebUrl,
  type InterceptContext,
} from "@/utils/externalLinks";

/**
 * Everything the link decision needs, read from the stores at call time.
 * Feeds come from the query cache only: fetching here would fire an
 * authenticated request from public pages (shared entries) that have none.
 */
export function currentInterceptContext(queryClient: QueryClient = appQueryClient): InterceptContext {
  const { mode, trustedHosts } = readExternalLinkSettings(useAuthStore.getState().user);
  const feeds = queryClient.getQueryData<PaginatedResponse<Feed>>(["feeds"])?.items ?? [];
  return {
    origin: window.location.origin,
    mode,
    trustedHosts: [...trustedHosts, ...readSessionTrustedHosts()],
    // site_url comes from the feed's own metadata and can name any host. Only
    // the subscribed feed URL identifies a host the user actually selected.
    feedHosts: hostsFromUrls(feeds.map((f) => f.url)),
  };
}

/**
 * `window.open` for a URL that came from feed content, behind the same
 * confirmation as a clicked link. Use this instead of `window.open` wherever
 * the app opens a feed-supplied external URL from code, because the click
 * listener in ExternalLinkGuard never sees those.
 *
 * `features` is passed through untouched when no confirmation is needed, so
 * swapping this in doesn't change what the caller's tab gets.
 */
export function openExternalUrl(
  url: string,
  { features = "noopener,noreferrer", text = "" }: { features?: string; text?: string } = {},
): void {
  // Not an outside link (same site, or not a web URL): exactly the plain
  // window.open this replaced. The guard and the caller's features are for
  // outside links only.
  if (!isExternalWebUrl(url)) {
    window.open(url, "_blank");
    return;
  }
  const info = evaluateProgrammaticOpen(url, currentInterceptContext(), text);
  if (info) {
    useExternalLinkStore.getState().hold(info);
    return;
  }
  window.open(url, "_blank", features);
}
