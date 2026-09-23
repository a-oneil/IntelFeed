import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";

export interface AutocompleteSuggestion {
  /** "field" completes a field name (`mal` → `malware:`), "value" completes its value. */
  type: "field" | "value";
  /** The label shown in the dropdown. */
  text: string;
  /** What replaces the token at the cursor when accepted. */
  insert: string;
  /** Field suggestions only. */
  description?: string;
  category?: "entity" | "entry" | "meta" | string;
  /** Value suggestions only — which field the value belongs to. */
  field?: string;
}

/**
 * Type-ahead for the search query language, backed by /search/autocomplete.
 *
 * The endpoint decides what a token means: a bare prefix completes field names,
 * and anything containing `:` completes that field's values (from the database
 * for entity names, from a fixed list for enums). Passing the whole query rather
 * than just the token lets it use the preceding text for context.
 */
export function useSearchAutocomplete(partial: string, enabled: boolean) {
  const trimmed = partial.trim();
  return useQuery({
    queryKey: ["search-autocomplete", trimmed],
    queryFn: async () => {
      const res = await api.get<AutocompleteSuggestion[]>("/search/autocomplete", {
        params: { q: trimmed },
      });
      return res.data;
    },
    enabled: enabled && trimmed.length > 0,
    // Suggestions are cheap and highly repetitive as the user types.
    staleTime: 60_000,
    retry: false,
    placeholderData: (prev) => prev,
  });
}
