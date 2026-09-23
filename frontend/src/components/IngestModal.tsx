import { useState, useRef, useCallback } from "react";
import { useIngestURL, useIngestPDF } from "@/hooks/useIngest";
import { useFocusTrap } from "@/hooks/useFocusTrap";
import { useUIStore } from "@/stores/uiStore";
import styles from "./IngestModal.module.css";

type IngestMode = "url" | "pdf";

interface Props {
  onClose: () => void;
}

export function IngestModal({ onClose }: Props) {
  const [mode, setMode] = useState<IngestMode>("url");
  const [url, setUrl] = useState("");
  const [pdfFile, setPdfFile] = useState<File | null>(null);
  const [pdfTitle, setPdfTitle] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const trapRef = useFocusTrap<HTMLDivElement>();

  const ingestURL = useIngestURL();
  const ingestPDF = useIngestPDF();
  const setSelectedEntry = useUIStore((s) => s.setSelectedEntry);
  const setSelectedFeed = useUIStore((s) => s.setSelectedFeed);

  const isLoading = ingestURL.isPending || ingestPDF.isPending;
  const result = ingestURL.data || ingestPDF.data;
  const error = ingestURL.error || ingestPDF.error;

  const handleIngestURL = useCallback(() => {
    if (!url.trim() || isLoading) return;
    ingestURL.mutate(url.trim());
  }, [url, isLoading, ingestURL]);

  const handleIngestPDF = useCallback(() => {
    if (!pdfFile || isLoading) return;
    ingestPDF.mutate({ file: pdfFile, title: pdfTitle.trim() || undefined });
  }, [pdfFile, pdfTitle, isLoading, ingestPDF]);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file && file.type === "application/pdf") {
      setPdfFile(file);
    }
  }, []);

  const handleViewEntry = useCallback(() => {
    if (!result) return;
    setSelectedFeed(result.feed_id);
    setSelectedEntry(result.id);
    onClose();
  }, [result, setSelectedFeed, setSelectedEntry, onClose]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") onClose();
  };

  const getErrorMessage = (err: unknown): string => {
    if (!err) return "";
    const axiosErr = err as { response?: { data?: { message?: string } } };
    return axiosErr?.response?.data?.message || "An error occurred. Please try again.";
  };

  return (
    <div className={styles.overlay} onClick={onClose} onKeyDown={handleKeyDown}>
      <div
        className={styles.modal}
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
          {/* Mode tabs */}
          <div className={styles.modeTabs}>
            <button
              className={`${styles.modeTab} ${mode === "url" ? styles.modeTabActive : ""}`}
              onClick={() => { setMode("url"); ingestURL.reset(); ingestPDF.reset(); }}
            >
              URL
            </button>
            <button
              className={`${styles.modeTab} ${mode === "pdf" ? styles.modeTabActive : ""}`}
              onClick={() => { setMode("pdf"); ingestURL.reset(); ingestPDF.reset(); }}
            >
              PDF Upload
            </button>
          </div>

          {/* Success state */}
          {result && (
            <div className={styles.success}>
              <p className={styles.successTitle}>{result.title}</p>
              <p className={styles.successMeta}>
                {result.word_count ? `${result.word_count.toLocaleString()} words` : "Ingested"}
                {" \u2014 intelligence extraction in progress"}
              </p>
              <button onClick={handleViewEntry} className={styles.viewBtn}>
                View Entry
              </button>
            </div>
          )}

          {/* URL mode */}
          {mode === "url" && !result && (
            <>
              <div className={styles.urlRow}>
                <input
                  type="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleIngestURL()}
                  placeholder="Paste article or blog post URL..."
                  className={styles.urlInput}
                  autoFocus
                  disabled={isLoading}
                />
              </div>
              <button
                onClick={handleIngestURL}
                disabled={isLoading || !url.trim()}
                className={styles.submitBtn}
              >
                {isLoading && <span className={styles.spinner} />}
                {isLoading ? "Extracting content..." : "Ingest URL"}
              </button>
            </>
          )}

          {/* PDF mode */}
          {mode === "pdf" && !result && (
            <>
              {!pdfFile ? (
                <div
                  className={`${styles.dropZone} ${dragOver ? styles.dropZoneDragOver : ""}`}
                  onClick={() => fileInputRef.current?.click()}
                  onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                  onDragLeave={() => setDragOver(false)}
                  onDrop={handleDrop}
                >
                  <div className={styles.dropZoneIcon}>
                    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                      <polyline points="14 2 14 8 20 8" />
                      <line x1="12" y1="18" x2="12" y2="12" />
                      <polyline points="9 15 12 12 15 15" />
                    </svg>
                  </div>
                  <p className={styles.dropZoneText}>
                    Drop a PDF here or click to browse
                  </p>
                  <p className={styles.dropZoneHint}>Maximum file size: 50 MB</p>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".pdf,application/pdf"
                    style={{ display: "none" }}
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      if (file) setPdfFile(file);
                    }}
                  />
                </div>
              ) : (
                <div className={styles.selectedFile}>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                    <polyline points="14 2 14 8 20 8" />
                  </svg>
                  <span className={styles.selectedFileName}>{pdfFile.name}</span>
                  <button
                    onClick={() => { setPdfFile(null); if (fileInputRef.current) fileInputRef.current.value = ""; }}
                    className={styles.clearFileBtn}
                    aria-label="Remove file"
                  >
                    &times;
                  </button>
                </div>
              )}

              <div className={styles.field} style={{ marginTop: "0.75rem" }}>
                <label>Title (optional)</label>
                <input
                  type="text"
                  value={pdfTitle}
                  onChange={(e) => setPdfTitle(e.target.value)}
                  placeholder="Override the filename as the entry title..."
                  className={styles.urlInput}
                  disabled={isLoading}
                />
              </div>

              <button
                onClick={handleIngestPDF}
                disabled={isLoading || !pdfFile}
                className={styles.submitBtn}
              >
                {isLoading && <span className={styles.spinner} />}
                {isLoading ? "Processing PDF..." : "Upload & Ingest"}
              </button>
            </>
          )}

          {/* Error */}
          {error && (
            <p className={styles.error}>{getErrorMessage(error)}</p>
          )}
        </div>
      </div>
    </div>
  );
}
