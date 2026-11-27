import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";
import type { EntityScanMatch } from "@/api/types";

export type { EntityScanMatch };

/** Scan arbitrary text (e.g. an entity profile description) for known intelligence entities via the autolinker. Returns the matched entities with the matched text so callers can highlight + link them inline, the same way the daily AI summary does. */
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
