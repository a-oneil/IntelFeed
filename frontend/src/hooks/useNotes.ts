import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type { Note, PaginatedResponse } from "@/api/types";

export function useNotes(params?: { entry_id?: string; is_pinned?: boolean; q?: string; limit?: number; offset?: number }) {
  return useQuery({
    queryKey: ["notes", params],
    queryFn: async () => {
      const res = await api.get<PaginatedResponse<Note>>("/notes", { params });
      return res.data;
    },
  });
}

export function useNote(noteId: string | null) {
  return useQuery({
    queryKey: ["notes", noteId],
    queryFn: async () => {
      const res = await api.get<Note>(`/notes/${noteId}`);
      return res.data;
    },
    enabled: !!noteId,
  });
}

export function useEntryNotes(entryId: string | null) {
  return useQuery({
    queryKey: ["entry-notes", entryId],
    queryFn: async () => {
      const res = await api.get<Note[]>(`/notes/entry/${entryId}`);
      return res.data;
    },
    enabled: !!entryId,
  });
}

export function useCreateNote() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: { title: string; content_markdown?: string; is_pinned?: boolean }) => {
      const res = await api.post<Note>("/notes", data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notes"] });
    },
  });
}

export function useCreateEntryNote() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      entryId,
      data,
    }: {
      entryId: string;
      data: { title: string; content_markdown?: string; is_pinned?: boolean };
    }) => {
      const res = await api.post<Note>(`/notes/entry/${entryId}`, data);
      return res.data;
    },
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ["notes"] });
      queryClient.invalidateQueries({ queryKey: ["entry-notes", variables.entryId] });
      queryClient.invalidateQueries({ queryKey: ["entry-intel-badges"] });
    },
  });
}

export function useUpdateNote() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      noteId,
      data,
    }: {
      noteId: string;
      data: { title?: string; content_markdown?: string; is_pinned?: boolean };
    }) => {
      const res = await api.put<Note>(`/notes/${noteId}`, data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notes"] });
    },
  });
}

export function useDeleteNote() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (noteId: string) => {
      await api.delete(`/notes/${noteId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notes"] });
      queryClient.invalidateQueries({ queryKey: ["entry-notes"] });
      queryClient.invalidateQueries({ queryKey: ["entry-intel-badges"] });
    },
  });
}
