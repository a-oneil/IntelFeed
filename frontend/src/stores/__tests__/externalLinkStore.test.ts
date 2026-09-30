import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useAuthStore } from "@/stores/authStore";
import { clearUserScopedState } from "@/stores/clearUserScopedState";
import { readSessionTrustedHosts, useExternalLinkStore } from "@/stores/externalLinkStore";
import { EXTERNAL_LINK_SESSION_TRUST_PREFIX } from "@/utils/externalLinks";
import { clearAllSessionTrust } from "@/utils/sessionTrust";
import type { User } from "@/api/types";

const user = (id: string): User => ({
  id, username: id, role: "analyst", is_active: true, settings: {},
  theme_id: null, custom_css: null, last_login: null, created_at: "2026-01-01T00:00:00Z",
});


/** jsdom's Storage ignores method spies (assigning stores a key), so swap the whole object, like test/setup.ts does for localStorage. */
function withSessionStorage(fake: Partial<Storage>): () => void {
  const real = Object.getOwnPropertyDescriptor(window, "sessionStorage")!;
  const realGlobal = Object.getOwnPropertyDescriptor(globalThis, "sessionStorage");
  Object.defineProperty(window, "sessionStorage", { configurable: true, value: fake });
  Object.defineProperty(globalThis, "sessionStorage", { configurable: true, value: fake });
  return () => {
    Object.defineProperty(window, "sessionStorage", real);
    if (realGlobal) Object.defineProperty(globalThis, "sessionStorage", realGlobal);
  };
}

beforeEach(() => {
  clearAllSessionTrust();
  sessionStorage.clear();
  useAuthStore.setState({ accessToken: null, refreshToken: null, user: null });
  useExternalLinkStore.setState({ pending: null, sessionTrustedHosts: [] });
});
afterEach(() => vi.restoreAllMocks());

describe("session-trusted hosts", () => {
  it("persist in sessionStorage per account and never cross accounts", () => {
    useAuthStore.setState({ user: user("a") });
    useExternalLinkStore.getState().trustForSession("Example.com");
    expect(readSessionTrustedHosts()).toEqual(["example.com"]);

    useAuthStore.setState({ user: user("b") });
    expect(readSessionTrustedHosts()).toEqual([]);

    useAuthStore.setState({ user: user("a") });
    expect(readSessionTrustedHosts()).toEqual(["example.com"]);
  });

  it("fall back to the in-memory copy when storage rejects writes but reads back null", () => {
    // Restrictive private modes: setItem throws QuotaExceededError, getItem returns null.
    const restore = withSessionStorage({
      getItem: () => null,
      setItem: () => {
        throw new DOMException("full", "QuotaExceededError");
      },
      removeItem: () => {},
      key: () => null,
      length: 0,
    });
    try {
      useAuthStore.setState({ user: user("private-mode") });
      useExternalLinkStore.getState().trustForSession("mem.example");
      expect(readSessionTrustedHosts()).toEqual(["mem.example"]);
    } finally {
      restore();
    }
  });

  it("fall back to the in-memory copy when storage throws on read", () => {
    useAuthStore.setState({ user: user("throws") });
    useExternalLinkStore.getState().trustForSession("mem2.example");
    const restore = withSessionStorage({
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {},
      removeItem: () => {},
      key: () => null,
      length: 0,
    });
    try {
      expect(readSessionTrustedHosts()).toEqual(["mem2.example"]);
    } finally {
      restore();
    }
  });

  it("cannot be resurrected from memory after logout clears them", () => {
    useAuthStore.setState({ user: user("a") });
    useExternalLinkStore.getState().trustForSession("example.com");
    clearUserScopedState();
    expect(readSessionTrustedHosts()).toEqual([]);
  });

  it("are dropped from sessionStorage on logout, without touching unrelated keys", () => {
    useAuthStore.setState({ user: user("a") });
    useExternalLinkStore.getState().trustForSession("example.com");
    useAuthStore.setState({ user: null });
    useExternalLinkStore.getState().trustForSession("public.example");
    sessionStorage.setItem("unrelated-key", "keep");

    clearUserScopedState();

    for (let i = 0; i < sessionStorage.length; i++) {
      expect(sessionStorage.key(i)!.startsWith(EXTERNAL_LINK_SESSION_TRUST_PREFIX)).toBe(false);
    }
    expect(sessionStorage.getItem("unrelated-key")).toBe("keep");
  });
});
