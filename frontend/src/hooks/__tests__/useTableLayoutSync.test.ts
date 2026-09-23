import { renderHook, waitFor, act } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createElement } from "react";
import type { ReactNode } from "react";

vi.mock("@/api/client", () => ({
  default: { get: vi.fn(), post: vi.fn(), put: vi.fn(), patch: vi.fn(), delete: vi.fn() },
}));

import api from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import { useUIStore } from "@/stores/uiStore";
import { useTableLayoutSync } from "../useTableLayoutSync";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const mockedApi = api as any;

const userWithLayouts = (layouts: unknown, id = "u1") => ({
  id,
  username: "analyst",
  role: "user",
  is_active: true,
  settings: layouts === undefined ? {} : { table_layouts: layouts },
  created_at: "2026-01-01T00:00:00Z",
});

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return function Wrapper({ children }: { children: ReactNode }) {
    return createElement(QueryClientProvider, { client: queryClient }, children);
  };
}

describe("useTableLayoutSync", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useUIStore.setState({ tables: {}, tablesOwnerId: null });
    useAuthStore.setState({ accessToken: "token", refreshToken: "refresh", user: null });
  });

  it("hydrates the store from the layouts saved on the profile", async () => {
    mockedApi.get.mockResolvedValue({
      data: userWithLayouts({
        "entity:threat_actor": {
          columnVisibility: { aliases: true },
          columnWidths: { name: 320 },
          columnOrder: ["name", "aliases"],
          updatedAt: 5000,
        },
      }),
    });

    renderHook(() => useTableLayoutSync(), { wrapper: createWrapper() });

    await waitFor(() => {
      expect(useUIStore.getState().tables["entity:threat_actor"]?.columnOrder).toEqual([
        "name",
        "aliases",
      ]);
    });
    expect(useUIStore.getState().tables["entity:threat_actor"].columnWidths).toEqual({ name: 320 });
    // Hydration alone must not bounce straight back to the server.
    expect(mockedApi.patch).not.toHaveBeenCalled();
  });

  it("pushes a local column change up to the profile as a settings patch", async () => {
    mockedApi.get.mockResolvedValue({ data: userWithLayouts(undefined) });
    mockedApi.patch.mockImplementation((_url: string, body: { settings: Record<string, unknown> }) =>
      Promise.resolve({ data: { ...userWithLayouts(undefined), settings: body.settings } }),
    );

    renderHook(() => useTableLayoutSync(), { wrapper: createWrapper() });
    await waitFor(() => expect(mockedApi.get).toHaveBeenCalled());

    act(() => {
      useUIStore.getState().setTableColumnVisible("entries", "feed", false);
    });

    await waitFor(() => expect(mockedApi.patch).toHaveBeenCalled(), { timeout: 4000 });
    const [url, body] = mockedApi.patch.mock.calls[0];
    expect(url).toBe("/auth/me/settings");
    expect(body.settings.table_layouts.entries.columnVisibility).toEqual({ feed: false });
    expect(body.settings.table_layouts.entries.updatedAt).toBeGreaterThan(0);
    // Only the layout key is patched, so a concurrent saver's keys survive.
    expect(Object.keys(body.settings)).toEqual(["table_layouts"]);
  });

  it("does not push device-local filters or sort to the profile", async () => {
    mockedApi.get.mockResolvedValue({ data: userWithLayouts(undefined) });
    mockedApi.patch.mockResolvedValue({ data: userWithLayouts({}) });

    renderHook(() => useTableLayoutSync(), { wrapper: createWrapper() });
    await waitFor(() => expect(mockedApi.get).toHaveBeenCalled());

    act(() => {
      useUIStore.getState().setTableTextFilter("entries", "title", "ransomware");
      useUIStore.getState().setTableClientSort("entries", { key: "title", dir: "asc" });
    });
    await new Promise((r) => setTimeout(r, 1500));

    expect(mockedApi.patch).not.toHaveBeenCalled();
  });

  it("drops the previous account's layouts when someone else signs in here", async () => {
    // u1 arranged the table on this browser and it is still in localStorage.
    useUIStore.setState({
      tablesOwnerId: "u1",
      tables: {
        entries: {
          columnVisibility: { feed: false },
          columnWidths: {},
          columnOrder: ["title"],
          textFilters: {},
          hasFilters: {},
          choiceFilters: {},
          clientSort: null,
          layoutUpdatedAt: Date.now(),
        },
      },
    });
    mockedApi.get.mockResolvedValue({
      data: userWithLayouts(
        { entries: { columnVisibility: {}, columnWidths: {}, columnOrder: ["published_at"], updatedAt: 10 } },
        "u2",
      ),
    });

    renderHook(() => useTableLayoutSync(), { wrapper: createWrapper() });

    await waitFor(() => expect(useUIStore.getState().tablesOwnerId).toBe("u2"));
    // u2's own (older-stamped) layout wins outright — no merge with u1's.
    expect(useUIStore.getState().tables.entries.columnOrder).toEqual(["published_at"]);
    expect(useUIStore.getState().tables.entries.columnVisibility).toEqual({});
    await new Promise((r) => setTimeout(r, 1200));
    expect(mockedApi.patch).not.toHaveBeenCalled();
  });

  it("claims an unowned browser without wiping layouts it already had", async () => {
    useUIStore.setState({
      tablesOwnerId: null,
      tables: {
        entries: {
          columnVisibility: { feed: false },
          columnWidths: {},
          columnOrder: [],
          textFilters: {},
          hasFilters: {},
          choiceFilters: {},
          clientSort: null,
          layoutUpdatedAt: Date.now(),
        },
      },
    });
    mockedApi.get.mockResolvedValue({ data: userWithLayouts(undefined) });
    mockedApi.patch.mockImplementation((_url: string, body: { settings: Record<string, unknown> }) =>
      Promise.resolve({ data: { ...userWithLayouts(undefined), settings: body.settings } }),
    );

    renderHook(() => useTableLayoutSync(), { wrapper: createWrapper() });

    await waitFor(() => expect(useUIStore.getState().tablesOwnerId).toBe("u1"));
    expect(useUIStore.getState().tables.entries.columnVisibility).toEqual({ feed: false });
    // Layouts predating the sync get uploaded rather than sitting local-only.
    await waitFor(() => expect(mockedApi.patch).toHaveBeenCalled(), { timeout: 4000 });
  });

  it("saves a change made while the profile fetch was still in flight", async () => {
    let resolveGet: (v: unknown) => void = () => {};
    mockedApi.get.mockReturnValue(new Promise((r) => { resolveGet = r; }));
    mockedApi.patch.mockImplementation((_url: string, body: { settings: Record<string, unknown> }) =>
      Promise.resolve({ data: { ...userWithLayouts(undefined), settings: body.settings } }),
    );

    renderHook(() => useTableLayoutSync(), { wrapper: createWrapper() });
    act(() => {
      useUIStore.getState().setTableColumnVisible("entries", "feed", false);
    });
    expect(mockedApi.patch).not.toHaveBeenCalled();

    await act(async () => {
      resolveGet({ data: userWithLayouts(undefined) });
    });

    await waitFor(() => expect(mockedApi.patch).toHaveBeenCalled(), { timeout: 4000 });
    const [, body] = mockedApi.patch.mock.calls[0];
    expect(body.settings.table_layouts.entries.columnVisibility).toEqual({ feed: false });
  });
});
