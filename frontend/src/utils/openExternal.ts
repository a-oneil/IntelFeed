import { readExternalLinkSettings } from "@/hooks/useExternalLinkSettings";
import { currentReadingPrefs } from "@/hooks/useReadingPrefs";
import { useAuthStore } from "@/stores/authStore";
import { readSessionTrustedHosts, useExternalLinkStore } from "@/stores/externalLinkStore";
import {
  evaluateProgrammaticOpen,
  isExternalWebUrl,
  type InterceptContext,
} from "@/utils/externalLinks";

/** Everything the link decision needs, read from the stores at call time. */
export function currentInterceptContext(): InterceptContext {
  const { mode, trustedHosts } = readExternalLinkSettings(useAuthStore.getState().user);
  return {
    origin: window.location.origin,
    mode,
    trustedHosts: [...trustedHosts, ...readSessionTrustedHosts()],
  };
}

/**
 * `window.open` for a URL that came from feed content, behind the same confirmation as a clicked link. Use this instead of `window.open` wherever the app opens a feed-supplied external URL from code, because the click listener in ExternalLinkGuard never sees those.
 *
 * `features` is passed through untouched when no confirmation is needed, so swapping this in doesn't change what the caller's tab gets.
 */
export function openExternalUrl(
  url: string,
  { features = "noopener,noreferrer", text = "" }: { features?: string; text?: string } = {},
): void {
  // Not an outside link (same site, or not a web URL): only allow safe same-origin relative paths (never protocol-relative // or javascript:/data:).
  if (!isExternalWebUrl(url)) {
    const trimmed = url.trim();
    if (trimmed.startsWith("/") && !trimmed.startsWith("//")) {
      window.open(trimmed, "_blank");
    } else {
      try {
        const parsed = new URL(trimmed, window.location.origin);
        if ((parsed.protocol === "http:" || parsed.protocol === "https:") && parsed.origin === window.location.origin) {
          window.open(parsed.href, "_blank");
        }
      } catch {
        // Ignore malformed or non-HTTP(S) schemes (javascript:, data:, etc.)
      }
    }
    return;
  }
  const info = evaluateProgrammaticOpen(url, currentInterceptContext(), text);
  if (info) {
    useExternalLinkStore.getState().hold(info);
    return;
  }
  openAllowedExternal(url, features);
}

/** Open an outside URL that has already passed the confirmation: a new tab by default, or this tab when Settings → Reading → "Open links in new tab" is off. */
export function openAllowedExternal(url: string, features = "noopener,noreferrer"): void {
  if (currentReadingPrefs().open_links_new_tab) {
    window.open(url, "_blank", features);
  } else {
    window.location.assign(url);
  }
}
