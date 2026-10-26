import { useState, useRef, useEffect } from "react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { remarkSoftBreaks } from "@/utils/remarkSoftBreaks";
import { EntityLinkedMarkdown } from "./EntityLinkedMarkdown";
import { useIsVisitor } from "@/stores/authStore";
import styles from "./InlineEditField.module.css";

interface InlineEditFieldProps {
  value: string;
  /** Shown when not editing, if it differs from the stored `value` (e.g. a
   * pretty label for an enum). Editing always operates on `value`. */
  displayValue?: string;
  onSave: (newValue: string) => Promise<void> | void;
  multiline?: boolean;
  placeholder?: string;
  /** Render value as markdown when not editing */
  renderMarkdown?: boolean;
  /** When rendering markdown, highlight + link known intelligence entities. */
  linkEntities?: boolean;
  /** Entity whose profile is shown — excluded from self-linking. */
  excludeEntityId?: string;
}

export function InlineEditField({ value, displayValue, onSave, multiline, placeholder, renderMarkdown, linkEntities, excludeEntityId }: InlineEditFieldProps) {
  const [editing, setEditingState] = useState(false);
  // Public read-only mode: every inline field in the app displays, none edits.
  const isVisitor = useIsVisitor();
  const setEditing = (on: boolean) => setEditingState(on && !isVisitor);
  const [draft, setDraft] = useState(value);
  const [saving, setSaving] = useState(false);
  const inputRef = useRef<HTMLInputElement | HTMLTextAreaElement>(null);

  useEffect(() => {
    if (editing && inputRef.current) {
      inputRef.current.focus();
      inputRef.current.select();
    }
  }, [editing]);

  useEffect(() => {
    setDraft(value);
  }, [value]);

  const handleSave = async () => {
    const trimmed = draft.trim();
    if (trimmed === value) {
      setEditing(false);
      return;
    }
    setSaving(true);
    try {
      await onSave(trimmed);
      setEditing(false);
    } finally {
      setSaving(false);
    }
  };

  const handleCancel = () => {
    setDraft(value);
    setEditing(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      handleCancel();
    } else if (e.key === "Enter" && !multiline) {
      e.preventDefault();
      handleSave();
    } else if (e.key === "Enter" && e.metaKey && multiline) {
      e.preventDefault();
      handleSave();
    }
  };

  if (editing) {
    const className = `${multiline ? styles.textarea : styles.input} ${saving ? styles.saving : ""}`;
    if (multiline) {
      return (
        <textarea
          ref={inputRef as React.RefObject<HTMLTextAreaElement>}
          className={className}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onBlur={handleSave}
          onKeyDown={handleKeyDown}
          placeholder={placeholder}
        />
      );
    }
    return (
      <input
        ref={inputRef as React.RefObject<HTMLInputElement>}
        className={className}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={handleSave}
        onKeyDown={handleKeyDown}
        placeholder={placeholder}
      />
    );
  }

  if (renderMarkdown && value) {
    return (
      <div className={styles.markdownDisplay} onClick={() => setEditing(true)} title={isVisitor ? undefined : "Click to edit"}>
        {linkEntities ? (
          <EntityLinkedMarkdown text={value} excludeEntityId={excludeEntityId} enabled={!editing} />
        ) : (
          <Markdown remarkPlugins={[remarkGfm, remarkSoftBreaks]}>{value}</Markdown>
        )}
        <svg className={styles.pencil} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
          <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
        </svg>
      </div>
    );
  }

  return (
    <span className={styles.display} onClick={() => setEditing(true)} title={isVisitor ? undefined : "Click to edit"}>
      {displayValue || value || <span style={{ color: "var(--text-muted)" }}>{placeholder || "Click to edit"}</span>}
      <svg className={styles.pencil} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
        <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
      </svg>
    </span>
  );
}
