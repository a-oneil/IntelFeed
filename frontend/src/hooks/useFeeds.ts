import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type {
  Category,
  Feed,
  FeedPipeline,
  FeedSubscribersResponse,
  FeedValueDetail,
  PaginatedResponse,
} from "@/api/types";

export function useFeeds() {
  return useQuery({
    queryKey: ["feeds"],
    queryFn: async () => {
      const res = await api.get<PaginatedResponse<Feed>>("/feeds", {
        params: { limit: 1000 },
      });
      return res.data;
    },
  });
}

export function useCategories() {
  return useQuery({
    queryKey: ["categories"],
    queryFn: async () => {
      const res = await api.get<Category[]>("/categories");
      return res.data;
    },
  });
}

export function useAddFeed() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: {
      url: string;
      category_id?: string;
      feed_type?: string;
      adapter_config?: Record<string, unknown>;
      fetch_interval_minutes?: number;
      custom_title?: string;
      intel_extraction_mode?: string;
      auto_extract_on_ingest?: boolean;
      extract_detection_rules?: boolean;
      extract_tools?: boolean;
    }) => {
      const res = await api.post("/feeds", data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["feeds"] });
    },
  });
}

export function useDeleteFeed() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (feedId: string) => {
      await api.delete(`/feeds/${feedId}`);
    },
    onMutate: async (feedId: string) => {
      await queryClient.cancelQueries({ queryKey: ["feeds"] });
      const previous = queryClient.getQueryData<PaginatedResponse<Feed>>(["feeds"]);
      if (previous) {
        queryClient.setQueryData<PaginatedResponse<Feed>>(["feeds"], {
          ...previous,
          items: previous.items.filter((f) => f.id !== feedId),
          total: previous.total - 1,
        });
      }
      return { previous };
    },
    onError: (_err, _feedId, context) => {
      if (context?.previous) {
        queryClient.setQueryData(["feeds"], context.previous);
      }
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ["feeds"] });
      queryClient.invalidateQueries({ queryKey: ["entries"] });
    },
  });
}

export function useRefreshFeed() {
  return useMutation({
    mutationFn: async (feedId: string) => {
      const res = await api.post(`/feeds/${feedId}/refresh`);
      return res.data;
    },
  });
}

/** Full tree re-import. GitHub repo feeds only — the API 400s on anything else. */
export function useFullSyncFeed() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (feedId: string) => {
      const res = await api.post(`/feeds/${feedId}/full-sync`);
      return res.data;
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["feeds"] }),
  });
}

/**
 * One feed's intelligence value score, for the edit modal's Overview pane.
 *
 * Scoring is corpus-wide on the server (entity introductions only mean
 * anything against every feed), so this is deliberately not cheap — it is
 * fetched lazily, when the pane that shows it mounts.
 */
export function useFeedValue(feedId: string | null) {
  return useQuery({
    queryKey: ["feed-value", feedId],
    queryFn: async () => {
      const res = await api.get<FeedValueDetail>(`/feeds/${feedId}/value`);
      return res.data;
    },
    enabled: Boolean(feedId),
    staleTime: 300_000,
  });
}

/**
 * Which stages actually run for this feed, and what decided each one.
 *
 * Resolution (legacy booleans -> global -> category -> feed plan) happens on
 * the server; re-implementing that merge in the client would drift the moment
 * either side changed.
 */
export function useFeedPipeline(feedId: string | null) {
  return useQuery({
    queryKey: ["feed-pipeline", feedId],
    queryFn: async () => {
      const res = await api.get<FeedPipeline>(`/feeds/${feedId}/pipeline`);
      return res.data;
    },
    enabled: Boolean(feedId),
    staleTime: 60_000,
  });
}

export function useDiscoverFeed() {
  return useMutation({
    mutationFn: async (url: string) => {
      const res = await api.post<{
        url: string;
        title: string | null;
        feed_type: string;
        description: string | null;
      }>("/feeds/discover", { url });
      return res.data;
    },
  });
}

export function useResolveBlueskyFeedUrl() {
  return useMutation({
    mutationFn: async (url: string) => {
      const res = await api.post<{
        feed_uri: string;
        did: string;
        handle: string;
      }>("/feeds/bluesky/resolve-feed-url", { url });
      return res.data;
    },
  });
}

export function useUpdateFeed() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      feedId,
      data,
    }: {
      feedId: string;
      data: {
        url?: string;
        custom_title?: string;
        category_id?: string | null;
        is_muted?: boolean;
        is_active?: boolean;
        fetch_interval_minutes?: number;
        exclude_shorts?: boolean;
        feed_type?: string;
        retention_days?: number | null;
        intel_extraction_mode?: "full" | "selective" | "manual" | "none";
        ai_analysis_enabled?: boolean;
        auto_extract_on_ingest?: boolean;
        extract_detection_rules?: boolean;
        extract_tools?: boolean;
        reliability_rating?: string;
        timeliness_rating?: string;
        relevance_rating?: string;
        analyst_notes?: string;
        adapter_config?: Record<string, unknown>;
      };
    }) => {
      const res = await api.put(`/feeds/${feedId}`, data);
      return res.data;
    },
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ["feeds"] });
      if (variables.data.is_muted !== undefined) {
        queryClient.invalidateQueries({ queryKey: ["entries"] });
      }
    },
  });
}

export function useBulkExcludeShorts() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (excludeShorts: boolean) => {
      const res = await api.put<{ updated: number }>("/feeds/youtube/exclude-shorts", {
        exclude_shorts: excludeShorts,
      });
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["feeds"] });
    },
  });
}

export function useCreateCategory() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: { name: string; parent_id?: string }) => {
      const res = await api.post("/categories", data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["categories"] });
    },
  });
}

export function useUpdateCategory() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ categoryId, data }: { categoryId: string; data: { name?: string } }) => {
      const res = await api.put(`/categories/${categoryId}`, data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["categories"] });
    },
  });
}

export function useDeleteCategory() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (categoryId: string) => {
      await api.delete(`/categories/${categoryId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["categories"] });
      queryClient.invalidateQueries({ queryKey: ["feeds"] });
    },
  });
}

export function useReorderCategories() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (items: { id: string; position: number; parent_id?: string | null }[]) => {
      const res = await api.put("/categories/reorder", { items });
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["categories"] });
    },
  });
}

export function useBulkSetupGitHubRepos() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const res = await api.post<{
        created: { url: string; title: string; feed_id: string }[];
        skipped: { url: string; title: string; reason: string }[];
        total_created: number;
        total_skipped: number;
        category_id: string;
        category_name: string;
      }>("/feeds/github-repo/bulk-setup");
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["feeds"] });
      queryClient.invalidateQueries({ queryKey: ["categories"] });
    },
  });
}

export function useBulkUpdateCategoryFeeds() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      categoryId,
      data,
    }: {
      categoryId: string;
      data: {
        fetch_interval_minutes?: number;
        retention_days?: number | null;
        clear_retention?: boolean;
        reliability_rating?: string;
        intel_extraction_mode?: "full" | "selective" | "manual" | "none";
        auto_extract_on_ingest?: boolean;
        extract_detection_rules?: boolean;
        extract_tools?: boolean;
      };
    }) => {
      const res = await api.put<{ updated: number }>(
        `/feeds/category/${categoryId}/bulk-update`,
        data
      );
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["feeds"] });
    },
  });
}

export function useBulkSetIntelMode() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      categoryId,
      mode,
    }: {
      categoryId: string;
      mode: "full" | "selective" | "manual" | "none";
    }) => {
      const res = await api.put<{ updated: number }>(
        `/feeds/category/${categoryId}/intel-mode`,
        { intel_extraction_mode: mode }
      );
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["feeds"] });
    },
  });
}

/* ─── Subscribers (admin) ─────────────────────────────────────────────────
 * Who reads a feed, and admin-side control over that list. Only meaningful
 * with per-user subscriptions on (the response says which), but the rows are
 * maintained either way so a push survives a later flag flip.
 */

export function useFeedSubscribers(feedId: string | null, enabled = true) {
  return useQuery({
    queryKey: ["feeds", feedId, "subscribers"],
    enabled: Boolean(feedId) && enabled,
    queryFn: async () => {
      const res = await api.get<FeedSubscribersResponse>(`/feeds/${feedId}/subscribers`);
      return res.data;
    },
  });
}

/** Subscribe users on their behalf. Omit userIds to push to everyone. */
export function usePushFeedToUsers() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ feedId, userIds }: { feedId: string; userIds?: string[] }) => {
      const res = await api.post<{
        added: number;
        subscriber_count: number;
        is_active: boolean;
        per_user_active: boolean;
      }>(`/feeds/${feedId}/subscribers`, userIds ? { user_ids: userIds } : {});
      return res.data;
    },
    onSuccess: (_data, { feedId }) => {
      queryClient.invalidateQueries({ queryKey: ["feeds", feedId, "subscribers"] });
      queryClient.invalidateQueries({ queryKey: ["feeds"] });
      queryClient.invalidateQueries({ queryKey: ["feed-health"] });
      queryClient.invalidateQueries({ queryKey: ["admin", "users"] });
    },
  });
}

export function useRemoveFeedSubscriber() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ feedId, userId }: { feedId: string; userId: string }) => {
      await api.delete(`/feeds/${feedId}/subscribers/${userId}`);
    },
    onSuccess: (_data, { feedId }) => {
      queryClient.invalidateQueries({ queryKey: ["feeds", feedId, "subscribers"] });
      queryClient.invalidateQueries({ queryKey: ["feeds"] });
      queryClient.invalidateQueries({ queryKey: ["feed-health"] });
      queryClient.invalidateQueries({ queryKey: ["admin", "users"] });
    },
  });
}

/* ─── OPML import ─────────────────────────────────────────────────────────
 * Bulk subscription import. The backend creates categories from outline
 * groups, skips URLs already in the pool, and queues a first fetch for each
 * feed it adds. Bad files come back as 200 + {error}, not an HTTP error. */

export interface OpmlImportResult {
  feeds_added: number;
  feeds_skipped: number;
  categories_created: number;
  feeds_skipped_invalid?: number;
  errors?: string[];
  error?: string;
}

export function useImportOpml() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (file: File) => {
      const formData = new FormData();
      formData.append("file", file);
      const res = await api.post<OpmlImportResult>("/opml/import", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      return res.data;
    },
    onSuccess: (data) => {
      if (data.error) return;
      queryClient.invalidateQueries({ queryKey: ["feeds"] });
      queryClient.invalidateQueries({ queryKey: ["categories"] });
      queryClient.invalidateQueries({ queryKey: ["entries"] });
    },
  });
}
