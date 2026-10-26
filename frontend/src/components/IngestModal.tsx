import { useState, useRef, useCallback, useEffect, useMemo } from "react";
import {
  useAddIngestFile,
  useAddIngestText,
  useAddIngestUrls,
  useCreateIngestBatch,
  useDeleteIngestItem,
  useIngestBatch,
  useIngestCapabilities,
  useRetryIngestItem,
  type IngestItem,
} from "@/hooks/useIngest";
import { useFeeds } from "@/hooks/useFeeds";
import { useFocusTrap } from "@/hooks/useFocusTrap";
import { useUIStore } from "@/stores/uiStore";
import { Hint, Segmented, Spinner } from "@/components/primitives";
import { IngestStatusChip } from "./IngestStatusChip";
import { fileTypeLabel, formatBytes } from "@/utils/ingest";
import styles from "./IngestModal.module.css";

type IngestMode = "urls" | "files" | "paste";

const MANUAL_FEED_URL = "manual://uploads";

const MODE_OPTIONS = [
  { value: "urls" as const, label: "URLs", title: "One link per line; GitHub repo links expand into one item per file" },
  { value: "files" as const, label: "Files", title: "Drop many files at once; .zip expands into its members" },
  { value: "paste" as const, label: "Paste", title: "A report body, an advisory, a chat log, an indicator list" },
];

/** A file still travelling to the server — shown in the queue before its item row exists. */
interface PendingUpload {
  key: string;
  name: string;
  size: number;
  error?: string;
}

interface Props {
  onClose: () => void;
}

function getErrorMessage(err: unknown): string {
  if (!err) return "";
  const axiosErr = err as { response?: { data?: { message?: string; error?: { message?: string } } }; message?: string };
  return (
    axiosErr?.response?.data?.error?.message ||
    axiosErr?.response?.data?.message ||
    axiosErr?.message ||
    "Something went wrong. Try again."
  );
}

/**
 * The ingest door. One batch per open modal: files, URLs and pastes all land in
 * it, each one queued the moment it is added, and the queue list below the
 * inputs shows one row per item with its live outcome. Nothing here waits on
 * a parse — the request stores and returns, the worker does the rest.
 */
export function IngestModal({ onClose }: Props) {
  const [mode, setMode] = useState<IngestMode>("files");
  const [batchId, setBatchId] = useState<string | null>(null);
  const [iocList, setIocList] = useState(false);
  const [urlsText, setUrlsText] = useState("");
  const [pasteText, setPasteText] = useState("");
  const [pasteTitle, setPasteTitle] = useState("");
  const [pasteSource, setPasteSource] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const [pending, setPending] = useState<PendingUpload[]>([]);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const trapRef = useFocusTrap<HTMLDivElement>();

  const createBatch = useCreateIngestBatch();
  const addFile = useAddIngestFile();
  const addUrls = useAddIngestUrls();
  const addText = useAddIngestText();
  const retryItem = useRetryIngestItem();
  const deleteItem = useDeleteIngestItem();
  const { data: batch } = useIngestBatch(batchId);
  const { data: caps } = useIngestCapabilities();
  const { data: feedsData, refetch: refetchFeeds } = useFeeds();

  const setSelectedEntry = useUIStore((s) => s.setSelectedEntry);
  const setSelectedFeed = useUIStore((s) => s.setSelectedFeed);
  const setViewMode = useUIStore((s) => s.setViewMode);

  const manualFeedId = feedsData?.items.find((f) => f.url === MANUAL_FEED_URL)?.id ?? null;
  const createdCount = batch?.summary.created ?? 0;
  // The very first batch on an instance mints the Manual Uploads feed; the
  // sidebar's feed list does not know about it until it is refetched.
  useEffect(() => {
    if (createdCount > 0 && !manualFeedId) refetchFeeds();
  }, [createdCount, manualFeedId, refetchFeeds]);

  const items: IngestItem[] = useMemo(() => batch?.items ?? [], [batch]);
  const busy = addUrls.isPending || addText.isPending || createBatch.isPending || pending.length > 0;

  // Batches are created lazily: open the modal and close it again and nothing is written.
  const batchIdRef = useRef<string | null>(null);
  batchIdRef.current = batchId;
  const ensureBatch = useCallback(async (): Promise<string> => {
    if (batchIdRef.current) return batchIdRef.current;
    const created = await createBatch.mutateAsync(undefined);
    batchIdRef.current = created.id;
    setBatchId(created.id);
    return created.id;
  }, [createBatch]);

  const handleFiles = useCallback(
    async (fileList: FileList | File[]) => {
      const files = Array.from(fileList);
      if (files.length === 0) return;
      setError(null);
      const stamped = files.map((f, i) => ({ key: `${Date.now()}-${i}-${f.name}`, name: f.name, size: f.size }));
      setPending((p) => [...p, ...stamped]);
      let id: string;
      try {
        id = await ensureBatch();
      } catch (e) {
        setError(getErrorMessage(e));
        setPending((p) => p.filter((x) => !stamped.some((s) => s.key === x.key)));
        return;
      }
      // One request per file, in order: a slow link finishes the first PDF
      // and the worker starts parsing it while the rest are still uploading.
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const key = stamped[i].key;
        try {
          await addFile.mutateAsync({ batchId: id, file, isIocList: iocList });
          setPending((p) => p.filter((x) => x.key !== key));
        } catch (e) {
          const message = getErrorMessage(e);
          setPending((p) => p.map((x) => (x.key === key ? { ...x, error: message } : x)));
        }
      }
    },
    [ensureBatch, addFile, iocList],
  );

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      if (e.dataTransfer.files.length) void handleFiles(e.dataTransfer.files);
    },
    [handleFiles],
  );

  const handleUrls = useCallback(async () => {
    const urls = urlsText
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean);
    if (urls.length === 0 || busy) return;
    setError(null);
    try {
      const id = await ensureBatch();
      await addUrls.mutateAsync({ batchId: id, urls, isIocList: iocList });
      setUrlsText("");
    } catch (e) {
      setError(getErrorMessage(e));
    }
  }, [urlsText, busy, ensureBatch, addUrls, iocList]);

  const handlePaste = useCallback(async () => {
    if (!pasteText.trim() || busy) return;
    setError(null);
    try {
      const id = await ensureBatch();
      await addText.mutateAsync({
        batchId: id,
        text: pasteText,
        title: pasteTitle.trim() || undefined,
        sourceUrl: pasteSource.trim() || undefined,
        isIocList: iocList,
      });
      setPasteText("");
      setPasteTitle("");
      setPasteSource("");
    } catch (e) {
      setError(getErrorMessage(e));
    }
  }, [pasteText, pasteTitle, pasteSource, busy, ensureBatch, addText, iocList]);

  const openEntry = useCallback(
    (entryId: string) => {
      if (manualFeedId) setSelectedFeed(manualFeedId);
      setSelectedEntry(entryId);
      onClose();
    },
    [manualFeedId, setSelectedFeed, setSelectedEntry, onClose],
  );

  const openManualUploads = useCallback(() => {
    if (!manualFeedId) return;
    setSelectedFeed(manualFeedId);
    setViewMode("table");
    onClose();
  }, [manualFeedId, setSelectedFeed, setViewMode, onClose]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") onClose();
  };

  const acceptAttr = caps ? caps.extensions.map((e) => `.${e}`).join(",") : undefined;
  const acceptHint = "PDF, DOCX, TXT, MD, HTML, CSV, EML, ZIP";
  const maxMb = caps?.max_file_mb ?? 50;
  const summary = batch?.summary;

  return (
    <div className={styles.overlay} onClick={onClose} onKeyDown={handleKeyDown}>
      <div
        className={`${styles.modal} ${styles.modalWide}`}
        onClick={(e) => e.stopPropagation()}
        ref={trapRef}
        role="dialog"
        aria-modal="true"
        aria-label="Ingest content"
      >
        <div className={styles.header}>
          <h2>Ingest Content</h2>
          <button onClick={onClose} className={styles.closeBtn} aria-label="Close">
            &times;
          </button>
        </div>

        <div className={styles.body}>
          <div className={styles.modeRow}>
            <Segmented<IngestMode>
              options={MODE_OPTIONS}
              value={mode}
              onChange={(m) => {
                setMode(m);
                setError(null);
              }}
              label="Ingest source"
              role="tablist"
            />
            <Hint
              title="Indicator list"
              body="Treat each item as one indicator per line (IPs, domains, hashes, URLs) and record them at feed trust."
              aside="Leave it off for prose: regex never creates an observable from an article."
              align="end"
            >
              <label className={styles.checkbox}>
                <input
                  id="ingest-ioc-list"
                  type="checkbox"
                  checked={iocList}
                  onChange={(e) => setIocList(e.target.checked)}
                />
                Indicator list
              </label>
            </Hint>
          </div>

          {mode === "urls" && (
            <>
              <div className={styles.field}>
                <label htmlFor="ingest-urls">URLs, one per line</label>
                <textarea
                  id="ingest-urls"
                  value={urlsText}
                  onChange={(e) => setUrlsText(e.target.value)}
                  placeholder={"https://vendor.example/report\nhttps://github.com/owner/repo/tree/main/rules"}
                  className={`${styles.urlInput} ${styles.textarea}`}
                  rows={4}
                  autoFocus
                  disabled={busy}
                />
                <p className={styles.fieldHint}>
                  A GitHub repository link is fetched once and becomes one entry per file.
                </p>
              </div>
              <button onClick={handleUrls} disabled={busy || !urlsText.trim()} className={styles.submitBtn}>
                {addUrls.isPending && <span className={styles.spinner} />}
                {addUrls.isPending ? "Adding…" : "Ingest URLs"}
              </button>
            </>
          )}

          {mode === "files" && (
            <div
              className={`${styles.dropZone} ${dragOver ? styles.dropZoneDragOver : ""}`}
              onClick={() => fileInputRef.current?.click()}
              onDragOver={(e) => {
                e.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") fileInputRef.current?.click();
              }}
              aria-label="Drop files or click to browse"
            >
              <div className={styles.dropZoneIcon}>
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                  <polyline points="14 2 14 8 20 8" />
                  <line x1="12" y1="18" x2="12" y2="12" />
                  <polyline points="9 15 12 12 15 15" />
                </svg>
              </div>
              <p className={styles.dropZoneText}>Drop files here or click to browse</p>
              <p className={styles.dropZoneHint}>
                {acceptHint} · up to {maxMb} MB each · .zip expands into its files
              </p>
              <input
                ref={fileInputRef}
                id="ingest-files"
                type="file"
                multiple
                accept={acceptAttr}
                style={{ display: "none" }}
                onChange={(e) => {
                  if (e.target.files?.length) void handleFiles(e.target.files);
                  e.target.value = "";
                }}
              />
            </div>
          )}

          {mode === "paste" && (
            <>
              <div className={styles.field}>
                <label htmlFor="ingest-paste">Text</label>
                <textarea
                  id="ingest-paste"
                  value={pasteText}
                  onChange={(e) => setPasteText(e.target.value)}
                  placeholder="Paste a report, an advisory, a chat log, or an indicator list…"
                  className={`${styles.urlInput} ${styles.textarea}`}
                  rows={7}
                  autoFocus
                  disabled={busy}
                />
              </div>
              <div className={styles.field}>
                <label htmlFor="ingest-paste-title">Title (optional)</label>
                <input
                  id="ingest-paste-title"
                  type="text"
                  value={pasteTitle}
                  onChange={(e) => setPasteTitle(e.target.value)}
                  placeholder="Defaults to the first line"
                  className={styles.urlInput}
                  disabled={busy}
                />
              </div>
              <div className={styles.field}>
                <label htmlFor="ingest-paste-source">Source URL (optional)</label>
                <input
                  id="ingest-paste-source"
                  type="url"
                  value={pasteSource}
                  onChange={(e) => setPasteSource(e.target.value)}
                  placeholder="https://"
                  className={styles.urlInput}
                  disabled={busy}
                />
              </div>
              <button onClick={handlePaste} disabled={busy || !pasteText.trim()} className={styles.submitBtn}>
                {addText.isPending && <span className={styles.spinner} />}
                {addText.isPending ? "Adding…" : "Ingest text"}
              </button>
            </>
          )}

          {error && <p className={styles.error}>{error}</p>}

          {(items.length > 0 || pending.length > 0) && (
            <div className={styles.queue} aria-live="polite">
              {items.map((item) => (
                <QueueRow
                  key={item.id}
                  item={item}
                  onOpen={item.entry_id ? () => openEntry(item.entry_id!) : undefined}
                  onRetry={
                    item.retryable && batchId
                      ? () => retryItem.mutate({ batchId, itemId: item.id })
                      : undefined
                  }
                  onRemove={
                    batchId && (item.status === "queued" || item.retryable)
                      ? () => deleteItem.mutate({ batchId, itemId: item.id })
                      : undefined
                  }
                />
              ))}
              {pending.map((p) => (
                <div key={p.key} className={styles.queueRow} data-testid="pending-upload">
                  <FileGlyph />
                  <span className={styles.queueName}>
                    {p.name}
                    <span className={styles.queueMeta}>
                      {fileTypeLabel(null, p.name)} · {formatBytes(p.size)}
                      {p.error ? ` · ${p.error}` : ""}
                    </span>
                  </span>
                  {p.error ? (
                    <button
                      className={styles.rowBtn}
                      onClick={() => setPending((x) => x.filter((y) => y.key !== p.key))}
                      aria-label={`Dismiss ${p.name}`}
                    >
                      &times;
                    </button>
                  ) : (
                    <span className={styles.uploading}>
                      <Spinner size="sm" /> uploading
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}

          {summary && (
            <div className={styles.footer}>
              <span className={styles.footerText}>
                {summary.total} item{summary.total === 1 ? "" : "s"}
                {summary.created ? ` · ${summary.created} created` : ""}
                {summary.active ? ` · ${summary.active} working` : ""}
                {summary.duplicate ? ` · ${summary.duplicate} duplicate` : ""}
                {summary.failed ? ` · ${summary.failed} failed` : ""}
                {summary.status === "complete" && summary.created > 0
                  ? " · AI analysis continues in the background"
                  : ""}
              </span>
              <span className={styles.footerActions}>
                <button
                  className={styles.rowBtn}
                  onClick={() => {
                    setBatchId(null);
                    batchIdRef.current = null;
                    setPending([]);
                  }}
                >
                  New batch
                </button>
                <button className={styles.viewBtn} onClick={openManualUploads} disabled={!manualFeedId}>
                  Open Manual Uploads
                </button>
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function kindGlyph(item: IngestItem) {
  if (item.kind === "url") return <LinkGlyph />;
  if (item.kind === "github_repo" || item.kind === "github_file") return <RepoGlyph />;
  if (item.kind === "text") return <TextGlyph />;
  return <FileGlyph />;
}

function rowName(item: IngestItem): string {
  if (item.kind === "url") return item.source_url ?? "URL";
  if (item.kind === "github_repo") return item.filename ?? item.source_url ?? "GitHub repository";
  return item.title || item.filename || item.source_url || "Item";
}

function rowMeta(item: IngestItem): string {
  const parts: string[] = [];
  if (item.kind === "github_repo") parts.push("GitHub repository");
  else if (item.kind === "github_file") parts.push("repo file");
  else if (item.kind === "text") parts.push("pasted text");
  else if (item.kind === "file") parts.push(fileTypeLabel(item.content_type, item.filename));
  if (item.size_bytes != null && item.kind !== "url" && item.kind !== "github_repo") parts.push(formatBytes(item.size_bytes));
  if (item.is_ioc_list) parts.push("indicator list");
  if (item.status === "created" && item.entry_title && item.entry_title !== rowName(item)) parts.push(item.entry_title);
  if (item.status === "duplicate" && item.entry_title) parts.push(`same as “${item.entry_title}”`);
  if (item.error && item.status !== "duplicate") parts.push(item.error);
  if (item.status === "expanded") {
    parts.push("expanded into files below");
  }
  return parts.join(" · ");
}

function QueueRow({
  item,
  onOpen,
  onRetry,
  onRemove,
}: {
  item: IngestItem;
  onOpen?: () => void;
  onRetry?: () => void;
  onRemove?: () => void;
}) {
  return (
    <div className={`${styles.queueRow} ${item.parent_item_id ? styles.queueRowChild : ""}`} data-testid="ingest-item">
      {kindGlyph(item)}
      <span className={styles.queueName} title={rowName(item)}>
        {rowName(item)}
        <span className={styles.queueMeta}>{rowMeta(item)}</span>
      </span>
      <IngestStatusChip status={item.status} phase={item.phase} />
      <span className={styles.queueActions}>
        {onOpen && (
          <button className={styles.rowBtn} onClick={onOpen}>
            Open
          </button>
        )}
        {onRetry && (
          <button className={styles.rowBtn} onClick={onRetry}>
            Retry
          </button>
        )}
        {onRemove && (
          <button className={styles.rowBtn} onClick={onRemove} aria-label={`Remove ${rowName(item)}`}>
            &times;
          </button>
        )}
      </span>
    </div>
  );
}

function FileGlyph() {
  return (
    <svg className={styles.queueIcon} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
    </svg>
  );
}

function LinkGlyph() {
  return (
    <svg className={styles.queueIcon} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
      <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
    </svg>
  );
}

function RepoGlyph() {
  return (
    <svg className={styles.queueIcon} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M6 3v12" />
      <circle cx="18" cy="6" r="3" />
      <circle cx="6" cy="18" r="3" />
      <path d="M18 9a9 9 0 0 1-9 9" />
    </svg>
  );
}

function TextGlyph() {
  return (
    <svg className={styles.queueIcon} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <line x1="4" y1="6" x2="20" y2="6" />
      <line x1="4" y1="12" x2="20" y2="12" />
      <line x1="4" y1="18" x2="14" y2="18" />
    </svg>
  );
}
