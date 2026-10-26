import { useAuthStore } from "@/stores/authStore";

/** `metadata` keys services/ingest_batches.py writes on a manual-upload entry. */
export interface UploadMeta {
  source?: string;
  batch_id?: string;
  ingest_item_id?: string;
  ingest_file_id?: string;
  filename?: string;
  file_content_type?: string;
  size_bytes?: number;
  original_retained?: boolean;
  uploaded_by?: string;
}

const MANUAL_SOURCES = new Set(["url_ingest", "pdf_upload", "file_upload", "text_paste", "github_repo"]);

/** The upload facts behind an entry, or null when it did not come through the ingest door. */
export function uploadMeta(metadata: Record<string, unknown> | null | undefined): UploadMeta | null {
  if (!metadata) return null;
  const m = metadata as UploadMeta;
  if (!m.batch_id && !m.ingest_file_id && !(m.source && MANUAL_SOURCES.has(m.source))) return null;
  return m;
}

/** Whether the entry has (or once had) a file behind it, as opposed to a fetched page. */
export function isFileUpload(meta: UploadMeta | null): boolean {
  return !!meta && (!!meta.ingest_file_id || meta.source === "pdf_upload" || meta.source === "file_upload" || meta.source === "text_paste");
}

/**
 * Three states the reader distinguishes: a downloadable original, one that the
 * retention sweep removed, and a file ingested before originals were kept.
 */
export type OriginalState = "available" | "evicted" | "not_kept" | "none";

export function originalState(meta: UploadMeta | null): OriginalState {
  if (!meta) return "none";
  if (meta.ingest_file_id) return meta.original_retained === false ? "evicted" : "available";
  if (meta.source === "pdf_upload") return "not_kept";
  return "none";
}

/** The auth-gated download route, signed with the access token because a plain link cannot send a header. */
export function ingestFileUrl(fileId: string, opts: { inline?: boolean } = {}): string {
  const token = useAuthStore.getState().accessToken;
  const params = new URLSearchParams();
  if (opts.inline) params.set("inline", "true");
  if (token) params.set("token", token);
  const qs = params.toString();
  return `/api/ingest-files/${fileId}${qs ? `?${qs}` : ""}`;
}

export function formatBytes(n: number | null | undefined): string {
  if (n == null || !Number.isFinite(n)) return "";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(n < 10 * 1024 * 1024 ? 1 : 0)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

/** Short type label from a MIME type or filename, for chips and table cells. */
export function fileTypeLabel(contentType?: string | null, filename?: string | null): string {
  const ext = (filename ?? "").match(/\.([A-Za-z0-9]{1,8})$/)?.[1]?.toUpperCase();
  if (ext) return ext;
  const mime = (contentType ?? "").split(";")[0].trim();
  const known: Record<string, string> = {
    "application/pdf": "PDF",
    "text/plain": "TXT",
    "text/markdown": "MD",
    "text/html": "HTML",
    "text/csv": "CSV",
    "message/rfc822": "EML",
    "application/zip": "ZIP",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "DOCX",
  };
  return known[mime] ?? (mime ? mime.split("/").pop()!.toUpperCase() : "FILE");
}
