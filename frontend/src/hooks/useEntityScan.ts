import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";

export interface EntityScanMatch {
  entity_type: string;
  entity_id: string;
  canonical_name: string;
  surface_forms: string[];
  /** Full entity payload — the same shape the entry-entity endpoints return —
   *  so hover popovers can show description, facts, aliases and links. */
  entity?: Record<string, unknown> | null;
}

/**
 * Scan arbitrary text (e.g. an entity profile description) for known
 * intelligence entities via the auto-linker. Returns the matched entities with
 * their surface forms so callers can highlight + link them inline, exactly like
 * the daily AI summary does.
 */
export function useEntityScan(text: string | undefined | null, enabled = true) {
  const trimmed = (text ?? "").trim();
  return useQuery({
    queryKey: ["entity-scan", trimmed],
    queryFn: async () => {
      const { data } = await api.post<{ matches: EntityScanMatch[] }>(
        "/autolink/scan",
        { text: trimmed },
      );
      return data.matches;
    },
    enabled: enabled && trimmed.length > 0,
    staleTime: 5 * 60 * 1000,
  });
}
