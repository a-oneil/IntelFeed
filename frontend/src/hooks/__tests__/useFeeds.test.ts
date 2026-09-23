import { renderHook, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createElement } from "react";
import type { ReactNode } from "react";

vi.mock("@/api/client", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}));

import api from "@/api/client";
import { useFeeds, useAddFeed, useDeleteFeed } from "../useFeeds";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const mockedApi = api as any;

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  return function Wrapper({ children }: { children: ReactNode }) {
    return createElement(QueryClientProvider, { client: queryClient }, children);
  };
}

describe("useFeeds", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns feed data from the API", async () => {
    const feedsResponse = {
      items: [
        {
          id: "feed-1",
          title: "Security Blog",
          url: "https://example.com/feed.xml",
          category_id: null,
          custom_title: null,
          is_muted: false,
          unread_count: 5,
        },
      ],
      total: 1,
      limit: 200,
      offset: 0,
      has_more: false,
    };

    mockedApi.get.mockResolvedValueOnce({ data: feedsResponse });

    const { result } = renderHook(() => useFeeds(), { wrapper: createWrapper() });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockedApi.get).toHaveBeenCalledWith("/feeds", { params: { limit: 1000 } });
    expect(result.current.data).toEqual(feedsResponse);
    expect(result.current.data?.items).toHaveLength(1);
    expect(result.current.data?.items[0].title).toBe("Security Blog");
  });

  it("useAddFeed calls API with correct data", async () => {
    const newFeed = { id: "feed-2", title: "New Feed" };
    mockedApi.post.mockResolvedValueOnce({ data: newFeed });

    const { result } = renderHook(() => useAddFeed(), { wrapper: createWrapper() });

    result.current.mutate({ url: "https://example.com/new-feed.xml" });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockedApi.post).toHaveBeenCalledWith("/feeds", {
      url: "https://example.com/new-feed.xml",
    });
  });

  it("useDeleteFeed calls API with feed ID", async () => {
    mockedApi.delete.mockResolvedValueOnce({ data: undefined });

    const { result } = renderHook(() => useDeleteFeed(), { wrapper: createWrapper() });

    result.current.mutate("feed-1");

    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockedApi.delete).toHaveBeenCalledWith("/feeds/feed-1");
  });
});
