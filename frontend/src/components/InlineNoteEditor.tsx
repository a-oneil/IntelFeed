/**
 * InlineNoteEditor — the single note editor used everywhere (sidebar, entry
 * panel, entity profiles). Edits markdown source with a live rendered preview,
 * matching how notes are stored and read. Backend-agnostic: the parent supplies
 * the initial values and an onSubmit callback, so the same editor drives both
 * `Note` (entry/sidebar) and `EntityNote` (profile) content.
 *
 * Rendered inline inside a NoteCard. The preview reuses <NoteBody> so it matches
 * the saved read view exactly (entity scanning is disabled while typing).
 */
import { useRef, useState } from "react";
import { NoteBody } from "./NoteBody";
import styles from "./InlineNoteEditor.module.css";

export interface InlineNoteSubmit {
  title: string;
  markdown: string;
  isPinned: boolean;
}

interface InlineNoteEditorProps {
  initialTitle?: string;
  initialMarkdown?: string;
  initialPinned?: boolean;
  showTitle?: boolean;
  showPin?: boolean;
  submitLabel?: string;
  saving?: boolean;
  error?: string | null;
  autoFocus?: boolean;
  onSubmit: (data: InlineNoteSubmit) => void;
  onCancel: () => void;
}

type ViewMode = "write" | "split" | "preview";

export function InlineNoteEditor({
  initialTitle = "",
  initialMarkdown = "",
  initialPinned = false,
  showTitle = true,
  showPin = false,
  submitLabel = "Save",
  saving = false,
  error = null,
  autoFocus = true,
  onSubmit,
  onCancel,
}: InlineNoteEditorProps) {
  const [title, setTitle] = useState(initialTitle);
  const [markdown, setMarkdown] = useState(initialMarkdown);
  const [isPinned, setIsPinned] = useState(initialPinned);
  const [viewMode, setViewMode] = useState<ViewMode>("split");
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const submit = () => {
    if (saving) return;
    onSubmit({ title: title.trim(), markdown, isPinned });
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
      e.preventDefault();
      submit();
    }
    if (e.key === "Escape") {
      e.preventDefault();
      onCancel();
    }
  };

  /** Wrap the current selection with `before`/`after` markers. */
  const wrap = (before: string, after: string = before) => {
    const ta = textareaRef.current;
    if (!ta) return;
    const start = ta.selectionStart;
    const end = ta.selectionEnd;
    const selected = markdown.slice(start, end) || "text";
    const next = markdown.slice(0, start) + before + selected + after + markdown.slice(end);
    setMarkdown(next);
    requestAnimationFrame(() => {
      ta.focus();
      ta.selectionStart = start + before.length;
      ta.selectionEnd = start + before.length + selected.length;
    });
  };

  /** Prefix the start of each selected line (e.g. `## `, `- `). */
  const prefixLines = (prefix: string) => {
    const ta = textareaRef.current;
    if (!ta) return;
    const start = ta.selectionStart;
    const end = ta.selectionEnd;
    const lineStart = markdown.lastIndexOf("\n", start - 1) + 1;
    const block = markdown.slice(lineStart, end);
    const prefixed = block
      .split("\n")
      .map((l) => (l.startsWith(prefix) ? l : prefix + l))
      .join("\n");
    const next = markdown.slice(0, lineStart) + prefixed + markdown.slice(end);
    setMarkdown(next);
    requestAnimationFrame(() => {
      ta.focus();
      ta.selectionStart = lineStart;
      ta.selectionEnd = lineStart + prefixed.length;
    });
  };

  const addLink = () => {
    const url = prompt("Enter URL:");
    if (url) wrap("[", `](${url})`);
  };

  return (
    <div className={styles.editor} onKeyDown={handleKeyDown}>
      <div className={styles.topbar}>
        {showTitle && (
          <input
            type="text"
            className={styles.titleInput}
            placeholder="Title (optional)"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            autoFocus={autoFocus}
          />
        )}
        {showPin && (
          <label className={styles.pinLabel}>
            <input type="checkbox" checked={isPinned} onChange={(e) => setIsPinned(e.target.checked)} />
            Pin
          </label>
        )}
        <div className={styles.viewModeGroup}>
          {(["write", "split", "preview"] as const).map((mode) => (
            <button
              key={mode}
              type="button"
              className={`${styles.viewModeBtn} ${viewMode === mode ? styles.active : ""}`}
              onClick={() => setViewMode(mode)}
            >
              {mode === "write" ? "Write" : mode === "split" ? "Split" : "Preview"}
            </button>
          ))}
        </div>
      </div>

      {viewMode !== "preview" && (
        <div className={styles.mdToolbar}>
          <button className={styles.mdBtn} onClick={() => wrap("**")} title="Bold">
            B
          </button>
          <button className={styles.mdBtn} style={{ fontStyle: "italic" }} onClick={() => wrap("*")} title="Italic">
            I
          </button>
          <span className={styles.mdSep} />
          <button className={styles.mdBtn} onClick={() => prefixLines("## ")} title="Heading">
            H
          </button>
          <button className={styles.mdBtn} onClick={() => prefixLines("- ")} title="Bullet list">
            &#8226; List
          </button>
          <button className={styles.mdBtn} onClick={() => prefixLines("> ")} title="Quote">
            &ldquo; Quote
          </button>
          <span className={styles.mdSep} />
          <button className={styles.mdBtn} onClick={() => wrap("`")} title="Inline code">
            &lt;/&gt;
          </button>
          <button className={styles.mdBtn} onClick={() => wrap("\n```\n", "\n```\n")} title="Code block">
            Code
          </button>
          <button className={styles.mdBtn} onClick={addLink} title="Link">
            Link
          </button>
        </div>
      )}

      {error && <div className={styles.errorBar}>{error}</div>}

      <div className={`${styles.body} ${styles[`view_${viewMode}`]}`}>
        {viewMode !== "preview" && (
          <div className={styles.pane}>
            <textarea
              ref={textareaRef}
              className={styles.textarea}
              placeholder="Write your note in markdown…"
              value={markdown}
              onChange={(e) => setMarkdown(e.target.value)}
              autoFocus={autoFocus && !showTitle}
            />
          </div>
        )}
        {viewMode !== "write" && (
          <div className={`${styles.pane} ${styles.previewPane}`}>
            {markdown.trim() ? (
              <NoteBody content={markdown} format="markdown" scanEntities={false} />
            ) : (
              <div className={styles.previewEmpty}>Nothing to preview yet.</div>
            )}
          </div>
        )}
      </div>

      <div className={styles.actions}>
        <button className={styles.save} onClick={submit} disabled={saving}>
          {saving ? "Saving…" : submitLabel}
        </button>
        <button className={styles.cancel} onClick={onCancel}>
          Cancel
        </button>
        <span className={styles.hint}>⌘↵ / Ctrl+↵ to save · Esc to cancel</span>
      </div>
    </div>
  );
}
