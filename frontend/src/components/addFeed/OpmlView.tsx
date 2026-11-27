import { useState } from "react";
import { useImportOpml } from "@/hooks/useFeeds";
import styles from "../AddFeedModal.module.css";

interface OpmlPreview {
  feeds: number;
  categories: string[];
  invalid: number;
}

/** Walk an OPML document the same way the server does (app/api/opml.py): one
 *  level of outline groups becomes folders, and a feed is any outline
 *  carrying an http(s) xmlUrl. Keeping the two walks in step means the counts
 *  shown before importing match what actually gets created. */
export function parseOpml(text: string): OpmlPreview | null {
  const doc = new DOMParser().parseFromString(text, "application/xml");
  if (doc.getElementsByTagName("parsererror").length > 0) return null;
  const root = doc.documentElement;
  if (!root) return null;
  const body = Array.from(root.children).find((el) => el.nodeName.toLowerCase() === "body");
  if (!body) return null;

  const preview: OpmlPreview = { feeds: 0, categories: [], invalid: 0 };
  const countFeed = (el: Element) => {
    const xmlUrl = el.getAttribute("xmlUrl");
    if (!xmlUrl) return;
    if (/^https?:\/\//.test(xmlUrl)) preview.feeds += 1;
    else preview.invalid += 1;
  };

  for (const outline of Array.from(body.children)) {
    const children = Array.from(outline.children);
    if (children.length > 0) {
      preview.categories.push(outline.getAttribute("text") || outline.getAttribute("title") || "Unnamed");
      children.forEach(countFeed);
    } else {
      countFeed(outline);
    }
  }
  return preview;
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** Import a subscription list exported from another reader. */
export function OpmlView({ onBack, onDone }: { onBack: () => void; onDone: () => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<OpmlPreview | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const importOpml = useImportOpml();

  const pick = async (picked: File | null | undefined) => {
    importOpml.reset();
    setPreview(null);
    setFileError(null);
    setFile(picked ?? null);
    if (!picked) return;
    if (picked.size > 10 * 1024 * 1024) {
      setFileError("File is larger than the 10 MB limit.");
      return;
    }
    const parsed = parseOpml(await picked.text());
    if (!parsed) {
      setFileError("This file is not an OPML subscription file.");
      return;
    }
    if (parsed.feeds === 0) {
      setFileError("No feed URLs found in this file.");
      return;
    }
    setPreview(parsed);
  };

  const result = importOpml.data && !importOpml.data.error ? importOpml.data : null;
  const importError = importOpml.isError
    ? ((importOpml.error as { response?: { data?: { detail?: { message?: string } } } })?.response?.data?.detail
        ?.message ?? "Import failed.")
    : (importOpml.data?.error ?? null);

  const runImport = async () => {
    if (!file || !preview) return;
    try {
      await importOpml.mutateAsync(file);
    } catch {
      // shown below
    }
  };

  return (
    <>
      <div className={styles.body}>
        {result ? (
          <div className={styles.choices}>
            <p className={styles.note}>
              Imported {plural(result.feeds_added, "feed", "feeds")}
              {result.feeds_skipped > 0 && ` · ${result.feeds_skipped} already followed`}
              {result.categories_created > 0 &&
                ` · ${plural(result.categories_created, "folder", "folders")} created`}
              .
            </p>
            {!!result.feeds_skipped_invalid && (
              <p className={styles.noteMuted}>
                {plural(result.feeds_skipped_invalid, "outline", "outlines")} skipped: no usable feed URL.
              </p>
            )}
            {!!result.errors?.length && <p className={styles.error}>{result.errors.join(", ")}</p>}
            <p className={styles.noteMuted}>New feeds are queued for their first fetch now.</p>
          </div>
        ) : (
          <>
            <label
              className={`${styles.dropzone} ${dragging ? styles.dropzoneActive : ""}`}
              onDragOver={(e) => {
                e.preventDefault();
                setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragging(false);
                void pick(e.dataTransfer.files?.[0]);
              }}
            >
              <input
                type="file"
                accept=".opml,.xml,application/xml,text/xml"
                className={styles.fileInput}
                data-testid="opml-file-input"
                onChange={(e) => {
                  const picked = e.target.files?.[0];
                  // Clear so re-picking the same file after an error still fires.
                  e.target.value = "";
                  void pick(picked);
                }}
              />
              <span className={styles.dropzoneTitle}>{file ? file.name : "Drop an OPML file here"}</span>
              <span className={styles.dropzoneHint}>
                {file
                  ? "Click to choose a different file"
                  : "or click to browse. Accepts exports from Feedly, Inoreader, NewsBlur and other readers."}
              </span>
            </label>
            {preview && (
              <p className={styles.noteMuted}>
                {plural(preview.feeds, "feed", "feeds")}
                {preview.categories.length > 0 &&
                  ` in ${plural(preview.categories.length, "folder", "folders")} (${preview.categories
                    .slice(0, 4)
                    .join(", ")}${preview.categories.length > 4 ? ", …" : ""})`}
                . Feeds you already follow are skipped.
                {preview.invalid > 0 &&
                  ` ${plural(preview.invalid, "entry", "entries")} without a usable URL will be ignored.`}
              </p>
            )}
            {fileError && <p className={styles.error}>{fileError}</p>}
            {importError && <p className={styles.error}>{importError}</p>}
          </>
        )}
      </div>
      <div className={styles.footer}>
        {!result && (
          <button type="button" className={styles.back} onClick={onBack}>
            Back
          </button>
        )}
        {result ? (
          <button type="button" className={styles.cta} onClick={onDone}>
            Done
          </button>
        ) : (
          <button
            type="button"
            className={styles.cta}
            disabled={!preview || importOpml.isPending}
            onClick={() => void runImport()}
          >
            {importOpml.isPending
              ? "Importing…"
              : preview
                ? `Import ${plural(preview.feeds, "feed", "feeds")}`
                : "Import"}
          </button>
        )}
      </div>
    </>
  );
}
