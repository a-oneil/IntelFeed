import { useState, useRef, useEffect } from "react";
import styles from "./InlineEditAliases.module.css";

interface InlineEditAliasesProps {
  aliases: string[];
  onSave: (aliases: string[]) => Promise<void> | void;
}

export function InlineEditAliases({ aliases, onSave }: InlineEditAliasesProps) {
  const [adding, setAdding] = useState(false);
  const [draft, setDraft] = useState("");
  const [saving, setSaving] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (adding && inputRef.current) {
      inputRef.current.focus();
    }
  }, [adding]);

  const handleAdd = async () => {
    const trimmed = draft.trim();
    if (!trimmed || aliases.includes(trimmed)) {
      setAdding(false);
      setDraft("");
      return;
    }
    setSaving(true);
    try {
      await onSave([...aliases, trimmed]);
      setDraft("");
      setAdding(false);
    } finally {
      setSaving(false);
    }
  };

  const handleRemove = async (alias: string) => {
    setSaving(true);
    try {
      await onSave(aliases.filter((a) => a !== alias));
    } finally {
      setSaving(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      handleAdd();
    } else if (e.key === "Escape") {
      setAdding(false);
      setDraft("");
    }
  };

  return (
    <div className={`${styles.container} ${saving ? styles.saving : ""}`}>
      {aliases.map((alias) => (
        <span key={alias} className={styles.alias}>
          {alias}
          <button
            className={styles.removeBtn}
            onClick={() => handleRemove(alias)}
            title={`Remove "${alias}"`}
          >
            ×
          </button>
        </span>
      ))}
      {adding ? (
        <input
          ref={inputRef}
          className={styles.input}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onBlur={handleAdd}
          onKeyDown={handleKeyDown}
          placeholder="New alias..."
        />
      ) : (
        <button className={styles.addBtn} onClick={() => setAdding(true)}>
          + Add alias
        </button>
      )}
    </div>
  );
}
