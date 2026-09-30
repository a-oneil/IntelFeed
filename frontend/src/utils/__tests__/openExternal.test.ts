import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient } from "@tanstack/react-query";
import { useAuthStore } from "@/stores/authStore";
import { useExternalLinkStore } from "@/stores/externalLinkStore";
import { clearAllSessionTrust } from "@/utils/sessionTrust";
import { evaluateProgrammaticOpen } from "@/utils/externalLinks";
import { currentInterceptContext, openExternalUrl } from "@/utils/openExternal";
import { queryClient } from "@/queryClient";
import type { User } from "@/api/types";

function user(settings: Record<string, unknown> = {}): User {
  return {
    id: "u1", username: "analyst", role: "analyst", is_active: true, settings,
    theme_id: null, custom_css: null, last_login: null, created_at: "2026-01-01T00:00:00Z",
  };
}

const ctx = (over = {}) => ({
  origin: "https://intelfeed.example",
  baseUri: "https://intelfeed.example/",
  mode: "article" as const,
  trustedHosts: [] as string[],
  feedHosts: [] as string[],
  ...over,
});

describe("evaluateProgrammaticOpen", () => {
  it("holds a foreign URL in the default scope (feed-supplied URLs are untrusted)", () => {
    expect(evaluateProgrammaticOpen("https://evil.example/x", ctx())).not.toBeNull();
  });

  it("does nothing when switched off", () => {
    expect(evaluateProgrammaticOpen("https://evil.example/x", ctx({ mode: "off" }))).toBeNull();
  });

  it("lets an entry on its own feed's site straight through", () => {
    const c = ctx({ feedHosts: ["krebsonsecurity.com"] });
    expect(evaluateProgrammaticOpen("https://krebsonsecurity.com/2026/09/post/", c)).toBeNull();
  });

  it("still holds an entry whose URL points away from its feed's site", () => {
    const c = ctx({ feedHosts: ["krebsonsecurity.com"] });
    expect(evaluateProgrammaticOpen("https://evil.example/2026/09/post/", c)).not.toBeNull();
  });

  it("ignores same-origin and non-web URLs", () => {
    expect(evaluateProgrammaticOpen("https://intelfeed.example/documentation", ctx())).toBeNull();
    expect(evaluateProgrammaticOpen("/documentation", ctx())).toBeNull();
    expect(evaluateProgrammaticOpen("mailto:a@b.example", ctx())).toBeNull();
  });

  it("opens in a new tab once confirmed", () => {
    expect(evaluateProgrammaticOpen("https://evil.example/x", ctx())!.newTab).toBe(true);
  });
});

describe("openExternalUrl", () => {
  beforeEach(() => {
    clearAllSessionTrust();
  sessionStorage.clear();
    useAuthStore.setState({ accessToken: null, refreshToken: null, user: null });
    useExternalLinkStore.setState({ pending: null, sessionTrustedHosts: [] });
    queryClient.clear();
  });
  afterEach(() => vi.restoreAllMocks());

  it("holds a foreign URL for confirmation instead of opening it", () => {
    const open = vi.spyOn(window, "open").mockReturnValue(null);
    openExternalUrl("https://evil.example/landing");
    expect(open).not.toHaveBeenCalled();
    expect(useExternalLinkStore.getState().pending?.host).toBe("evil.example");
  });

  it("opens straight away, with the caller's features, when the host is a feed host", () => {
    queryClient.setQueryData(["feeds"], {
      items: [{ url: "https://krebsonsecurity.com/feed/", site_url: "https://krebsonsecurity.com/" }],
      total: 1, limit: 1000, offset: 0, has_more: false,
    });
    const open = vi.spyOn(window, "open").mockReturnValue(null);
    openExternalUrl("https://krebsonsecurity.com/post", { features: "noopener" });
    expect(open).toHaveBeenCalledWith("https://krebsonsecurity.com/post", "_blank", "noopener");
    expect(useExternalLinkStore.getState().pending).toBeNull();
  });

  it("does not trust a host supplied only in feed metadata", () => {
    queryClient.setQueryData(["feeds"], {
      items: [{ url: "https://news.example/feed.xml", site_url: "https://evil.example/" }],
      total: 1, limit: 1000, offset: 0, has_more: false,
    });
    const open = vi.spyOn(window, "open").mockReturnValue(null);
    openExternalUrl("https://evil.example/collect");
    expect(open).not.toHaveBeenCalled();
    expect(useExternalLinkStore.getState().pending?.host).toBe("evil.example");
  });

  it("opens a same-site URL exactly as the old plain window.open did", () => {
    const open = vi.spyOn(window, "open").mockReturnValue(null);
    openExternalUrl(`${window.location.origin}/entries/1`, { features: "noopener" });
    expect(open).toHaveBeenCalledWith(`${window.location.origin}/entries/1`, "_blank");
    expect(useExternalLinkStore.getState().pending).toBeNull();
  });

  it("opens straight away when the feature is off", () => {
    useAuthStore.setState({ user: user({ external_link_mode: "off" }) });
    const open = vi.spyOn(window, "open").mockReturnValue(null);
    openExternalUrl("https://evil.example/landing");
    expect(open).toHaveBeenCalledWith("https://evil.example/landing", "_blank", "noopener,noreferrer");
  });

  it("uses a user-trusted host from the account settings", () => {
    useAuthStore.setState({ user: user({ external_link_trusted_hosts: ["evil.example"] }) });
    const open = vi.spyOn(window, "open").mockReturnValue(null);
    openExternalUrl("https://evil.example/landing");
    expect(open).toHaveBeenCalled();
  });

  it("builds its context from whichever query client it is given", () => {
    const other = new QueryClient();
    other.setQueryData(["feeds"], {
      items: [{ url: "https://a.example/feed", site_url: null }],
      total: 1, limit: 1, offset: 0, has_more: false,
    });
    expect(currentInterceptContext(other).feedHosts).toEqual(["a.example"]);
    expect(currentInterceptContext(queryClient).feedHosts).toEqual([]);
  });

  it("keeps session trust across reloads without sharing it with another account", () => {
    useAuthStore.setState({ user: user() });
    useExternalLinkStore.getState().trustForSession("evil.example");
    useExternalLinkStore.setState({ sessionTrustedHosts: [] });
    expect(currentInterceptContext().trustedHosts).toContain("evil.example");

    useAuthStore.setState({ user: { ...user(), id: "u2" } });
    expect(currentInterceptContext().trustedHosts).not.toContain("evil.example");
  });
});
