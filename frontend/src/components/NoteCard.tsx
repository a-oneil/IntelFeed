/**
 * NoteCard — the one note card used across the sidebar, entry panel and
 * entity profiles. Read state renders the note's saved content as formatted
 * markdown (via <NoteBody>) with an optional title, author/time and hover
 * actions. Clicking Edit flips the card into the shared markdown editor.
 *
 * Backend-agnostic: callers pass the display fields plus an `onSave` that
 * persists to whichever store the note lives in (Note or EntityNote).
 */
import { useEffect, useRef, useState } from "react";
import { InlineNoteEditor, type InlineNoteSubmit } from "./InlineNoteEditor";
import { NoteBody } from "./NoteBody";
import { isRichHtml, toMarkdownSource } from "@/utils/noteContent";
import { exportMarkdownNote } from "@/hooks/useExport";
import styles from "./NoteCard.module.css";

interface NoteCardProps {
  title?: string | null;
  /** Raw stored content shown in the read view. */
  content: string;
  /** How to render `content`; defaults to auto-detecting HTML vs markdown. */
  bodyFormat?: "auto" | "html" | "markdown";
  /** Markdown source loaded into the editor (defaults to `content`). */
  editorMarkdown?: string;
  /** Entity whose profile is shown — never links a note to its own entity. */
  excludeEntityId?: string;
  author?: string | null;
  /** Pre-formatted timestamp string (e.g. "2h ago"). */
  time?: string;
  isPinned?: boolean;
  showTitle?: boolean;
  showPin?: boolean;
  editable?: boolean;
  /** Extra meta shown inline — e.g. a "linked entry" button. */
  linkedLabel?: string;
  onOpenLinked?: () => void;
  onSave: (data: InlineNoteSubmit) => Promise<unknown> | void;
  onDelete?: () => void;
  onExport?: () => void;
  submitLabel?: string;
  /** Render straight into the editor (create flow). */
  startInEdit?: boolean;
  onExitCreate?: () => void;
}

export function NoteCard({
  title,
  content,
  bodyFormat = "auto",
  editorMarkdown,
  excludeEntityId,
  author,
  time,
  isPinned = false,
  showTitle = true,
  showPin = false,
  editable = true,
  linkedLabel,
  onOpenLinked,
  onSave,
  onDelete,
  onExport,
  submitLabel = "Save",
  startInEdit = false,
  onExitCreate,
}: NoteCardProps) {
  const [editing, setEditing] = useState(startInEdit);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Collapse long notes to a fixed height with a "Show more" toggle.
  const bodyRef = useRef<HTMLDivElement>(null);
  const [expanded, setExpanded] = useState(false);
  const [clampable, setClampable] = useState(false);
  useEffect(() => {
    const el = bodyRef.current;
    if (editing || !el) return;
    const measure = () => setClampable(el.scrollHeight > 260);
    measure();
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [content, editing]);

  const handleSubmit = async (data: InlineNoteSubmit) => {
    setSaving(true);
    setError(null);
    try {
      await onSave(data);
      if (startInEdit) onExitCreate?.();
      else setEditing(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save note");
    } finally {
      setSaving(false);
    }
  };

  const handleCancel = () => {
    if (startInEdit) onExitCreate?.();
    else setEditing(false);
  };

  // Clean markdown source, reused by both the editor and export.
  const rawSource = editorMarkdown ?? content;
  const markdownSource = isRichHtml(rawSource) ? rawSource : toMarkdownSource(rawSource);
  const handleExport = onExport ?? (() => exportMarkdownNote(title || "Note", markdownSource));

  if (editing) {
    return (
      <InlineNoteEditor
        initialTitle={title || ""}
        initialMarkdown={markdownSource}
        initialPinned={isPinned}
        showTitle={showTitle}
        showPin={showPin}
        submitLabel={submitLabel}
        saving={saving}
        error={error}
        onSubmit={handleSubmit}
        onCancel={handleCancel}
      />
    );
  }

  return (
    <div className={styles.card}>
      <div className={styles.top}>
        {isPinned && (
          <span className={styles.pinIcon} title="Pinned">
            &#128204;
          </span>
        )}
        {showTitle && title && <span className={styles.title}>{title}</span>}
        <div className={styles.meta}>
          {author && <span className={styles.author}>{author}</span>}
          {author && time && <span className={styles.metaSep}>·</span>}
          {time && <span className={styles.time}>{time}</span>}
        </div>
        <div className={styles.actions}>
          {editable && (
            <button className={styles.iconBtn} onClick={() => setEditing(true)}>
              &#9998; Edit
            </button>
          )}
          <button className={styles.iconBtn} onClick={handleExport} title="Export as markdown">
            Export
          </button>
          {onDelete && (
            <button className={`${styles.iconBtn} ${styles.danger}`} onClick={onDelete} title="Delete note">
              Delete
            </button>
          )}
        </div>
      </div>

      {linkedLabel && (
        <div className={styles.meta} style={{ marginBottom: 8 }}>
          {onOpenLinked ? (
            <button className={styles.linked} onClick={onOpenLinked}>
              {linkedLabel}
            </button>
          ) : (
            <span className={styles.linked}>{linkedLabel}</span>
          )}
        </div>
      )}

      <div className={`${styles.bodyClamp} ${clampable && !expanded ? styles.clamped : ""}`}>
        <div ref={bodyRef}>
          <NoteBody content={content} format={bodyFormat} excludeEntityId={excludeEntityId} />
        </div>
      </div>
      {clampable && (
        <button className={styles.expandBtn} onClick={() => setExpanded((v) => !v)}>
          {expanded ? "Show less" : "Show more"}
        </button>
      )}
    </div>
  );
}
