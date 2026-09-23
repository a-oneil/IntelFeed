import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type { SearchResponse, SavedSearch } from "@/api/types";

export interface SearchFilters {
  q?: string;
  feed_id?: string[];
  category_id?: string[];
  feed_type?: string[];
  tags?: string[];
  date_from?: string;
  date_to?: string;
  is_read?: boolean;
  is_starred?: boolean;
  is_bookmarked?: boolean;
  has_notes?: boolean;
  media_type?: string;
  sort?: "relevance" | "newest" | "oldest" | "title_asc" | "title_desc";
  limit?: number;
  offset?: number;
}

export function useSearch(filters: SearchFilters, enabled = true) {
  return useQuery({
    queryKey: ["search", filters],
    queryFn: async () => {
      const res = await api.post<SearchResponse>("/search/advanced", {
        q: filters.q || "",
        feed_id: filters.feed_id,
        category_id: filters.category_id,
        feed_type: filters.feed_type,
        tags: filters.tags,
        date_from: filters.date_from,
        date_to: filters.date_to,
        is_read: filters.is_read,
        is_starred: filters.is_starred,
        is_bookmarked: filters.is_bookmarked,
        has_notes: filters.has_notes,
        media_type: filters.media_type,
        sort: filters.sort || "relevance",
        limit: filters.limit || 20,
        offset: filters.offset || 0,
      });
      return res.data;
    },
    enabled: enabled && !!filters.q,
    staleTime: 30_000,
  });
}

export function useSearchFacets(q = "") {
  return useQuery({
    queryKey: ["search-facets", q],
    queryFn: async () => {
      const res = await api.get<{ facets: Record<string, Record<string, number>> }>("/search/facets", {
        params: { q },
      });
      return res.data.facets;
    },
    staleTime: 60_000,
  });
}

export function useSavedSearches() {
  return useQuery({
    queryKey: ["saved-searches"],
    queryFn: async () => {
      const res = await api.get<SavedSearch[]>("/saved-searches");
      return res.data;
    },
    refetchInterval: 300_000,
  });
}

export function useCreateSavedSearch() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: { name: string; query?: string; filters?: Record<string, unknown> }) => {
      const res = await api.post<SavedSearch>("/saved-searches", data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["saved-searches"] });
    },
  });
}

export function useUpdateSavedSearch() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      id,
      data,
    }: {
      id: string;
      data: { name?: string; display_name?: string | null; query?: string; filters?: Record<string, unknown> };
    }) => {
      const res = await api.put<SavedSearch>(`/saved-searches/${id}`, data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["saved-searches"] });
    },
  });
}

export function useDeleteSavedSearch() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/saved-searches/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["saved-searches"] });
    },
  });
}
