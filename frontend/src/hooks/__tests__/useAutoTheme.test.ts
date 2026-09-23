import { renderHook, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createElement } from "react";
import type { ReactNode } from "react";

vi.mock("@/api/client", () => ({
  default: { get: vi.fn(), post: vi.fn(), put: vi.fn(), patch: vi.fn(), delete: vi.fn() },
}));

import api from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import { useAutoTheme, applyTheme } from "../useThemes";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const mockedApi = api as any;

const theme = (id: string, name: string, bg: string, isDefault = false) => ({
  id,
  name,
  css_variables: { "bg-primary": bg, accent: "#f78166" },
  is_system: true,
  is_default: isDefault,
  created_by: null,
  created_at: "2026-01-01T00:00:00Z",
});

const BLACKLIGHT = theme("t-black", "Blacklight (Orange)", "#000000", true);
const GITHUB_DARK = theme("t-gh", "GitHub Dark", "#0d1117");

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return function Wrapper({ children }: { children: ReactNode }) {
    return createElement(QueryClientProvider, { client: queryClient }, children);
  };
}

const bgPrimary = () => document.documentElement.style.getPropertyValue("--bg-primary");

describe("useAutoTheme (logged out)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    document.documentElement.removeAttribute("style");
    useAuthStore.setState({ accessToken: null, refreshToken: null, user: null });
    mockedApi.get.mockImplementation((url: string) =>
      url === "/themes/default" ? Promise.resolve({ data: BLACKLIGHT }) : Promise.resolve({ data: [] })
    );
  });

  it("styles a first-time visitor with the instance default", async () => {
    renderHook(() => useAutoTheme(), { wrapper: createWrapper() });

    await waitFor(() => expect(bgPrimary()).toBe("#000000"));
    expect(localStorage.getItem("intelfeed-theme-source")).toBe("default");
  });

  it("keeps a signed-out user's own theme instead of the instance default", async () => {
    // Simulates the state left behind by a session where the user picked a theme
    applyTheme(GITHUB_DARK, "user");
    document.documentElement.removeAttribute("style");

    renderHook(() => useAutoTheme(), { wrapper: createWrapper() });

    await waitFor(() => expect(bgPrimary()).toBe("#0d1117"));
  });

  it("treats a pre-marker cache that isn't the instance default as a personal pick", async () => {
    applyTheme(GITHUB_DARK, "user");
    localStorage.removeItem("intelfeed-theme-source");
    document.documentElement.removeAttribute("style");

    renderHook(() => useAutoTheme(), { wrapper: createWrapper() });

    await waitFor(() => expect(bgPrimary()).toBe("#0d1117"));
  });

  it("follows the instance default when the cache only mirrors the old default", async () => {
    const oldDefault = theme("t-black", "Blacklight (Orange)", "#111111", true);
    applyTheme(oldDefault, "default");
    document.documentElement.removeAttribute("style");

    renderHook(() => useAutoTheme(), { wrapper: createWrapper() });

    await waitFor(() => expect(bgPrimary()).toBe("#000000"));
  });
});
