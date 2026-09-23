import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type {
  PaginatedResponse,
  IntelligenceRequirement,
  RequirementCreate,
  RequirementUpdate,
  RequirementMatch,
  RequirementCoverageSummary,
  RequirementEntities,
} from "@/api/types";

export function useRequirements(params?: {
  status?: string;
  priority?: string;
  category?: string;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: ["requirements", params],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<IntelligenceRequirement>>(
        "/requirements",
        { params }
      );
      return data;
    },
  });
}

export function useRequirement(id: string | undefined) {
  return useQuery({
    queryKey: ["requirement", id],
    queryFn: async () => {
      const { data } = await api.get<IntelligenceRequirement>(`/requirements/${id}`);
      return data;
    },
    enabled: !!id,
  });
}

export function useRequirementCoverage(params?: { date_from?: string; date_to?: string }) {
  return useQuery({
    queryKey: ["requirement-coverage", params],
    queryFn: async () => {
      const { data } = await api.get<RequirementCoverageSummary>("/requirements/coverage", { params });
      return data;
    },
  });
}

export function useRequirementMatches(id: string | undefined, params?: { limit?: number; offset?: number }) {
  return useQuery({
    queryKey: ["requirement-matches", id, params],
    queryFn: async () => {
      const { data } = await api.get<PaginatedResponse<RequirementMatch>>(
        `/requirements/${id}/matches`,
        { params }
      );
      return data;
    },
    enabled: !!id,
  });
}

export function useCreateRequirement() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: RequirementCreate) => {
      const { data } = await api.post<IntelligenceRequirement>("/requirements", body);
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["requirements"] });
      qc.invalidateQueries({ queryKey: ["requirement-coverage"] });
    },
  });
}

export function useUpdateRequirement() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, ...body }: RequirementUpdate & { id: string }) => {
      const { data } = await api.patch<IntelligenceRequirement>(`/requirements/${id}`, body);
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["requirements"] });
      qc.invalidateQueries({ queryKey: ["requirement", vars.id] });
      qc.invalidateQueries({ queryKey: ["requirement-coverage"] });
    },
  });
}

export function useFulfillRequirement() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, reportId }: { id: string; reportId?: string | null }) => {
      const { data } = await api.post<IntelligenceRequirement>(
        `/requirements/${id}/fulfill`,
        { report_id: reportId ?? null }
      );
      return data;
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["requirements"] });
      qc.invalidateQueries({ queryKey: ["requirement", vars.id] });
      qc.invalidateQueries({ queryKey: ["requirement-coverage"] });
    },
  });
}

export function useDeleteRequirement() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/requirements/${id}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["requirements"] });
      qc.invalidateQueries({ queryKey: ["requirement-coverage"] });
    },
  });
}

export function useRemoveRequirementMatch() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ requirementId, entryId }: { requirementId: string; entryId: string }) => {
      await api.delete(`/requirements/${requirementId}/matches/${entryId}`);
    },
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["requirement-matches", vars.requirementId] });
      qc.invalidateQueries({ queryKey: ["requirements"] });
      qc.invalidateQueries({ queryKey: ["requirement-coverage"] });
    },
  });
}

export function useRequirementEntities(id: string | undefined) {
  return useQuery({
    queryKey: ["requirement-entities", id],
    queryFn: async () => {
      const { data } = await api.get<RequirementEntities>(`/requirements/${id}/entities`);
      return data;
    },
    enabled: !!id,
  });
}
