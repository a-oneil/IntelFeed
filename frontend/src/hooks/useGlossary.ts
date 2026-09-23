import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type {
  GlossaryTerm,
  GlossaryTermCreate,
  GlossaryTermUpdate,
  GlossaryMatch,
  GlossaryCategory,
} from "@/api/types";

export function useGlossaryTerms(params?: {
  category?: string;
  search?: string;
  is_system?: boolean;
}) {
  return useQuery({
    queryKey: ["glossary-terms", params],
    queryFn: async () => {
      const res = await api.get<GlossaryTerm[]>("/glossary", { params });
      return res.data;
    },
  });
}

export function useGlossaryArticleCounts() {
  return useQuery({
    queryKey: ["glossary-counts"],
    queryFn: async () => {
      const res = await api.get<{ counts: Record<string, number> }>("/glossary/counts");
      return res.data.counts;
    },
    staleTime: 10 * 60 * 1000,
  });
}

export function articleCountToMaturity(count: number): string | null {
  if (count >= 20) return "mature";
  if (count >= 5) return "trending";
  if (count >= 1) return "emerging";
  return null;
}

export function useGlossaryCategories() {
  return useQuery({
    queryKey: ["glossary-categories"],
    queryFn: async () => {
      const res = await api.get<GlossaryCategory[]>("/glossary/categories");
      return res.data;
    },
  });
}

export function useDetectGlossaryTerms(entryId: string | null) {
  return useQuery({
    queryKey: ["glossary-detect", entryId],
    queryFn: async () => {
      const res = await api.post<GlossaryMatch[]>("/glossary/detect", {
        entry_id: entryId,
      });
      return res.data;
    },
    enabled: !!entryId,
    staleTime: 5 * 60 * 1000,
  });
}

export interface GlossaryEntryHit {
  id: string;
  title: string;
  feed_title: string;
  published_at: string | null;
}

export function useGlossaryTermEntries(termId: string | null) {
  return useQuery({
    queryKey: ["glossary-term-entries", termId],
    queryFn: async () => {
      const res = await api.get<{ entries: GlossaryEntryHit[]; total: number }>(
        `/glossary/${termId}/entries`,
      );
      return res.data;
    },
    enabled: !!termId,
    staleTime: 5 * 60 * 1000,
  });
}

export function useCreateGlossaryTerm() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: GlossaryTermCreate) => {
      const res = await api.post<GlossaryTerm>("/glossary", data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["glossary-terms"] });
      queryClient.invalidateQueries({ queryKey: ["glossary-categories"] });
      queryClient.invalidateQueries({ queryKey: ["glossary-detect"] });
    },
  });
}

export function useUpdateGlossaryTerm() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, data }: { id: string; data: GlossaryTermUpdate }) => {
      const res = await api.put<GlossaryTerm>(`/glossary/${id}`, data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["glossary-terms"] });
      queryClient.invalidateQueries({ queryKey: ["glossary-detect"] });
    },
  });
}

export function useDeleteGlossaryTerm() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/glossary/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["glossary-terms"] });
      queryClient.invalidateQueries({ queryKey: ["glossary-categories"] });
      queryClient.invalidateQueries({ queryKey: ["glossary-detect"] });
    },
  });
}
