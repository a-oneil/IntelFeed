import { Chip } from "@/components/primitives";
import { DropdownItem } from "@/components/ToolbarDropdown";
import { useUIStore } from "@/stores/uiStore";
import { fileTypeLabel, formatBytes, ingestFileUrl, isFileUpload, originalState, uploadMeta } from "@/utils/ingest";
import styles from "./EntryUploadInfo.module.css";

/**
 * The upload facts an entry carries, shown in the reader's byline: the
 * original file (filename, type, size, Download) and the batch it arrived in.
 * Three states for the file: downloadable, removed by the retention sweep, or
 * ingested before originals were kept — each says so rather than offering a
 * dead link. Nothing renders for an ordinary polled entry.
 */
export function UploadByline({
  metadata,
  feedId,
}: {
  metadata: Record<string, unknown> | null | undefined;
  feedId: string;
}) {
  const setSelectedFeed = useUIStore((s) => s.setSelectedFeed);
  const setViewMode = useUIStore((s) => s.setViewMode);
  const meta = uploadMeta(metadata);
  if (!meta) return null;
  const state = originalState(meta);
  const fileish = isFileUpload(meta);

  return (
    <>
      {fileish && (
        <span className={styles.original} data-testid="upload-original">
          Original:{" "}
          {meta.filename && <span className={styles.filename}>{meta.filename}</span>}
          {meta.filename && (meta.file_content_type || meta.filename) && (
            <> · {fileTypeLabel(meta.file_content_type, meta.filename)}</>
          )}
          {meta.size_bytes != null && <> · {formatBytes(meta.size_bytes)}</>}
          {state === "available" && meta.ingest_file_id && (
            <>
              {" · "}
              <a className={styles.link} href={ingestFileUrl(meta.ingest_file_id)} download={meta.filename ?? true}>
                Download
              </a>
            </>
          )}
          {state === "evicted" && <> · <span className={styles.dim}>removed by retention</span></>}
          {state === "not_kept" && <> · <span className={styles.dim}>not kept</span></>}
        </span>
      )}
      {meta.batch_id && (
        <Chip
          pill
          title="Open the Manual Uploads feed as a file table"
          onClick={() => {
            setSelectedFeed(feedId);
            setViewMode("table");
          }}
        >
          Batch · manual upload
        </Chip>
      )}
    </>
  );
}

/** "Download original" in the reader toolbar's overflow menu, when there is a file to download. */
export function UploadDownloadItem({ metadata }: { metadata: Record<string, unknown> | null | undefined }) {
  const meta = uploadMeta(metadata);
  if (!meta || originalState(meta) !== "available" || !meta.ingest_file_id) return null;
  return (
    <DropdownItem
      icon={
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
          <polyline points="7 10 12 15 17 10" />
          <line x1="12" y1="15" x2="12" y2="3" />
        </svg>
      }
      label="Download original"
      href={ingestFileUrl(meta.ingest_file_id)}
      newTab
    />
  );
}
