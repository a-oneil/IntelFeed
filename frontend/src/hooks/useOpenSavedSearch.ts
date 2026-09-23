import { useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useUIStore } from "@/stores/uiStore";
import type { SavedSearch } from "@/api/types";

/**
 * Open a saved search on the search page.
 *
 * Every entry point — the app sidebar, the dashboard widgets, tag and glossary
 * pivots — routes through here so a saved search always lands on the one
 * surface that knows how to restore it. `loadSavedSearch` only parks it in the
 * store; SearchPage is what unpacks the query, the scope and the facet state.
 */
export function useOpenSavedSearch() {
  const navigate = useNavigate();
  const loadSavedSearch = useUIStore((s) => s.loadSavedSearch);

  return useCallback(
    (saved: SavedSearch) => {
      loadSavedSearch(saved);
      navigate("/search");
    },
    [loadSavedSearch, navigate],
  );
}
