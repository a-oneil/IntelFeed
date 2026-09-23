import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";
import type { UnifiedSearchResponse, AutocompleteSuggestion } from "@/api/types";

export function useUnifiedSearch(
  query: string,
  options?: {
    limit?: number;
    offset?: number;
    entityLimit?: number;
    entityGroupLimit?: number;
    hideRead?: boolean;
  },
) {
  return useQuery({
    queryKey: [
      "unified-search",
      query,
      options?.limit,
      options?.offset,
      options?.entityLimit,
      options?.entityGroupLimit,
      options?.hideRead,
    ],
    queryFn: async () => {
      const res = await api.post<UnifiedSearchResponse>("/search/unified", {
        q: query,
        limit: options?.limit ?? 20,
        offset: options?.offset ?? 0,
        // The server's own defaults (200 total / 25 per type) are the right
        // ones for a plain call; only pass an override when one is given.
        ...(options?.entityLimit != null ? { entity_limit: options.entityLimit } : {}),
        ...(options?.entityGroupLimit != null ? { entity_group_limit: options.entityGroupLimit } : {}),
        // Read state is per-user and lives in Postgres, so only the server can
        // apply it across the whole match set rather than the fetched page.
        ...(options?.hideRead ? { hide_read: true } : {}),
      });
      return res.data;
    },
    enabled: query.length > 0,
    staleTime: 30_000,
  });
}

export function useSearchAutocomplete(partialQuery: string) {
  return useQuery({
    queryKey: ["search-autocomplete", partialQuery],
    queryFn: async () => {
      const res = await api.get<AutocompleteSuggestion[]>("/search/autocomplete", {
        params: { q: partialQuery },
      });
      return res.data;
    },
    enabled: partialQuery.length > 0,
    staleTime: 60_000,
  });
}
