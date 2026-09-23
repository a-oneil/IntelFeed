import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";
import type { AttackDomain, AttackMatrixData } from "@/utils/attackMatrix";

/**
 * Navigator-style matrix data for a domain: tactics in kill-chain order with
 * per-technique feed frequency and telemetry-aware detection coverage.
 * One call per domain + window; the backend caches the aggregate in Redis.
 */
export function useAttackMatrix(domain: AttackDomain, days: number | null) {
  return useQuery({
    queryKey: ["attack-matrix", domain, days],
    queryFn: async () => {
      const { data } = await api.get<AttackMatrixData>("/attack/matrix", {
        params: { domain, ...(days ? { days } : {}) },
      });
      return data;
    },
    staleTime: 2 * 60 * 1000,
  });
}
