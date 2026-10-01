import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";
import type { SectorProfile } from "@/api/types";

/** The sector's victimology — who targets it, leak-site victims, the country cross-tab. */
export function useSectorProfile(sectorId: string | undefined, windowDays = 90) {
  return useQuery({
    queryKey: ["sector-profile", sectorId, windowDays],
    queryFn: async () => {
      const { data } = await api.get<SectorProfile>(`/sectors/${sectorId}/profile`, {
        params: { window_days: windowDays },
      });
      return data;
    },
    enabled: !!sectorId,
  });
}
