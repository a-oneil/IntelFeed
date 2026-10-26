import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";

/**
 * Bulk ingest. A batch is opened once; files, URLs and pastes are added to it
 * one request each (production sits behind an edge that caps a request at
 * 100 MB, so a forty-file form would never arrive), and every item is queued
 * on the worker the moment it is added. `useIngestBatch` is the status view:
 * the SSE `ingest_item_updated` event invalidates it, and it also polls while
 * anything is still queued or parsing in case the event stream is down.
 */

export type IngestItemStatus =
  | "queued"
  | "parsing"
  | "created"
  | "expanded"
  | "duplicate"
  | "no_text"
  | "unsupported"
  | "too_large"
  | "failed"
  | "cancelled";

export interface IngestFileInfo {
  id: string;
  filename: string;
  content_type: string;
  size_bytes: number;
  retained: boolean;
  download_url: string;
}

export interface IngestItem {
  id: string;
  batch_id: string;
  parent_item_id: string | null;
  position: number;
  kind: "url" | "file" | "text" | "github_repo" | "github_file";
  status: IngestItemStatus;
  /** created items only: "analyzing" until the one-pass AI analysis lands, then "done" */
  phase: "analyzing" | "done" | null;
  filename: string | null;
  content_type: string | null;
  size_bytes: number | null;
  title: string | null;
  source_url: string | null;
  is_ioc_list: boolean;
  entry_id: string | null;
  entry_title: string | null;
  error: string | null;
  attempts: number;
  retryable: boolean;
  file: IngestFileInfo | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface IngestBatchSummary {
  total: number;
  active: number;
  created: number;
  duplicate: number;
  failed: number;
  status: "processing" | "complete";
  by_status: Record<string, number>;
}

export interface IngestBatch {
  id: string;
  user_id: string | null;
  label: string | null;
  source: string;
  created_at: string;
  summary: IngestBatchSummary;
  items: IngestItem[];
}

export interface IngestCapabilities {
  extensions: string[];
  max_file_mb: number;
  max_batch_items: number;
  zip_max_members: number;
}

export const ingestBatchKey = (batchId: string | null) => ["ingest-batch", batchId] as const;

export function useIngestCapabilities() {
  return useQuery({
    queryKey: ["ingest-capabilities"],
    queryFn: async () => (await api.get<IngestCapabilities>("/entries/ingest/capabilities")).data,
    staleTime: 10 * 60 * 1000,
  });
}

export function useIngestBatch(batchId: string | null) {
  return useQuery({
    queryKey: ingestBatchKey(batchId),
    queryFn: async () => (await api.get<IngestBatch>(`/entries/ingest/batches/${batchId}`)).data,
    enabled: !!batchId,
    // SSE is the primary signal; this is the fallback while work is in flight.
    refetchInterval: (query) => (query.state.data?.summary.active ? 3000 : false),
  });
}

export function useCreateIngestBatch() {
  return useMutation({
    mutationFn: async (label?: string) => {
      const res = await api.post<IngestBatch>("/entries/ingest/batches", label ? { label } : {});
      return res.data;
    },
  });
}

/** One request per file. The 60s default timeout is too short for a 50 MB upload on a slow link. */
export function useAddIngestFile() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      batchId,
      file,
      title,
      isIocList,
    }: {
      batchId: string;
      file: File;
      title?: string;
      isIocList?: boolean;
    }) => {
      const formData = new FormData();
      formData.append("file", file);
      if (title) formData.append("title", title);
      if (isIocList) formData.append("is_ioc_list", "true");
      const res = await api.post<IngestItem>(`/entries/ingest/batches/${batchId}/files`, formData, {
        headers: { "Content-Type": "multipart/form-data" },
        timeout: 10 * 60 * 1000,
      });
      return res.data;
    },
    onSuccess: (item) => {
      queryClient.invalidateQueries({ queryKey: ingestBatchKey(item.batch_id) });
    },
  });
}

export function useAddIngestUrls() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ batchId, urls, isIocList }: { batchId: string; urls: string[]; isIocList?: boolean }) => {
      const res = await api.post<IngestItem[]>(`/entries/ingest/batches/${batchId}/urls`, {
        urls,
        is_ioc_list: !!isIocList,
      });
      return res.data;
    },
    onSuccess: (_items, vars) => {
      queryClient.invalidateQueries({ queryKey: ingestBatchKey(vars.batchId) });
    },
  });
}

export function useAddIngestText() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      batchId,
      text,
      title,
      sourceUrl,
      isIocList,
    }: {
      batchId: string;
      text: string;
      title?: string;
      sourceUrl?: string;
      isIocList?: boolean;
    }) => {
      const res = await api.post<IngestItem>(`/entries/ingest/batches/${batchId}/text`, {
        text,
        title: title || null,
        source_url: sourceUrl || null,
        is_ioc_list: !!isIocList,
      });
      return res.data;
    },
    onSuccess: (item) => {
      queryClient.invalidateQueries({ queryKey: ingestBatchKey(item.batch_id) });
    },
  });
}

export function useRetryIngestItem() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ batchId, itemId }: { batchId: string; itemId: string }) => {
      const res = await api.post<IngestItem>(`/entries/ingest/batches/${batchId}/items/${itemId}/retry`);
      return res.data;
    },
    onSuccess: (item) => {
      queryClient.invalidateQueries({ queryKey: ingestBatchKey(item.batch_id) });
    },
  });
}

export function useDeleteIngestItem() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ batchId, itemId }: { batchId: string; itemId: string }) => {
      await api.delete(`/entries/ingest/batches/${batchId}/items/${itemId}`);
    },
    onSuccess: (_void, vars) => {
      queryClient.invalidateQueries({ queryKey: ingestBatchKey(vars.batchId) });
    },
  });
}
