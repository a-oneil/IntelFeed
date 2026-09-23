import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";
import type { CountryProfile, RegionSummary } from "@/api/types";

export function useCountryProfile(countryId: string | undefined) {
  return useQuery({
    queryKey: ["country-profile", countryId],
    queryFn: async () => {
      const { data } = await api.get<CountryProfile>(
        `/countries/${countryId}/profile`
      );
      return data;
    },
    enabled: !!countryId,
  });
}

export function useRegions() {
  return useQuery({
    queryKey: ["regions"],
    queryFn: async () => {
      const { data } = await api.get<{ regions: RegionSummary[] }>(
        "/regions"
      );
      return data.regions;
    },
  });
}
