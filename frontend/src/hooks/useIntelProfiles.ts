import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type {
  PaginatedResponse,
  IntelProfile,
  IntelProfileCreate,
  ThreatSurface,
} from "@/api/types";

export function useIntelProfiles() {
  return useQuery({
    queryKey: ["intel-profiles"],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<IntelProfile>>("/intel-profiles", {
        params: { limit: 200 },
      });
      return data.items;
    },
  });
}

export function useCreateIntelProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: IntelProfileCreate) => {
      const { data } = await api.post<IntelProfile>("/intel-profiles", body);
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["intel-profiles"] }),
  });
}

export function useUpdateIntelProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, ...body }: Partial<IntelProfileCreate> & { id: string }) => {
      const { data } = await api.put<IntelProfile>(`/intel-profiles/${id}`, body);
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["intel-profiles"] }),
  });
}

export function useDeleteIntelProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/intel-profiles/${id}`);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["intel-profiles"] }),
  });
}

/** Matched threat surface for a saved profile (actors + malware with evidence). */
export function useProfileThreatSurface(profileId: string | undefined) {
  return useQuery({
    queryKey: ["intel-profile-surface", profileId],
    queryFn: async () => {
      const { data } = await api.get<ThreatSurface>(`/intel-profiles/${profileId}/surface`, {
        params: { limit: 50 },
      });
      return data;
    },
    enabled: !!profileId,
    staleTime: 60_000,
  });
}

export function useSectorVocabulary() {
  return useQuery({
    queryKey: ["sector-vocabulary"],
    queryFn: async () => {
      const { data } = await api.get<{ slug: string; label: string }[]>(
        "/intel-profiles/sector-vocabulary"
      );
      return data;
    },
    staleTime: Infinity,
  });
}
