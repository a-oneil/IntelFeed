import { useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";

interface IngestResponse {
  id: string;
  title: string;
  url: string | null;
  word_count: number | null;
  feed_id: string;
  content_hash: string | null;
  message: string;
}

export function useIngestURL() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (url: string) => {
      const res = await api.post<IngestResponse>("/entries/ingest/url", { url });
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["entries"] });
      queryClient.invalidateQueries({ queryKey: ["feeds"] });
    },
  });
}

export function useIngestPDF() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ file, title }: { file: File; title?: string }) => {
      const formData = new FormData();
      formData.append("file", file);
      if (title) formData.append("title", title);
      const res = await api.post<IngestResponse>("/entries/ingest/pdf", formData, {
        headers: { "Content-Type": "multipart/form-data" },
        timeout: 60000,
      });
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["entries"] });
      queryClient.invalidateQueries({ queryKey: ["feeds"] });
    },
  });
}
