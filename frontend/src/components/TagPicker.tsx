/**
 * TagPicker — a multi-select of tag names with autocomplete over existing tags
 * plus inline create-new. Emits a plain string[] of tag names, so it drops into
 * anywhere tags are configured by name (e.g. automation add/remove-tags actions).
 */
import { useMemo, useRef, useState } from "react";
import { useTags } from "@/hooks/useTags";
import styles from "./TagPicker.module.css";

interface TagPickerProps {
  value: string[];
  onChange: (names: string[]) => void;
  placeholder?: string;
}

export function TagPicker({ value, onChange, placeholder = "Add or create tag…" }: TagPickerProps) {
  const { data: tags = [] } = useTags();
  const [input, setInput] = useState("");
  const [open, setOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const colorFor = (name: string) => tags.find((t) => t.name === name)?.color ?? "#6b7280";

  const q = input.trim().toLowerCase();
  const suggestions = useMemo(
    () =>
      tags
        .filter((t) => !value.includes(t.name) && (!q || t.name.toLowerCase().includes(q)))
        .slice(0, 8),
    [tags, value, q],
  );
  const exactExists =
    !!q && (tags.some((t) => t.name.toLowerCase() === q) || value.some((v) => v.toLowerCase() === q));

  const add = (name: string) => {
    const n = name.trim();
    setInput("");
    if (!n || value.includes(n)) return;
    onChange([...value, n]);
  };
  const remove = (name: string) => onChange(value.filter((v) => v !== name));

  return (
    <div className={styles.wrap}>
      <div className={styles.control} onClick={() => inputRef.current?.focus()}>
        {value.map((name) => (
          <span key={name} className={styles.chip}>
            <span className={styles.dot} style={{ background: colorFor(name) }} />
            {name}
            <button
              type="button"
              className={styles.x}
              onClick={(e) => {
                e.stopPropagation();
                remove(name);
              }}
              aria-label={`remove ${name}`}
            >
              ×
            </button>
          </span>
        ))}
        <input
          ref={inputRef}
          className={styles.input}
          value={input}
          placeholder={value.length ? "" : placeholder}
          onChange={(e) => {
            setInput(e.target.value);
            setOpen(true);
          }}
          onFocus={() => setOpen(true)}
          onBlur={() => setTimeout(() => setOpen(false), 120)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              add(suggestions[0]?.name ?? input);
            } else if (e.key === "Backspace" && !input && value.length) {
              remove(value[value.length - 1]);
            }
          }}
          spellCheck={false}
        />
      </div>

      {open && (suggestions.length > 0 || (q && !exactExists)) && (
        <div className={styles.menu}>
          {suggestions.map((t) => (
            <button
              key={t.id}
              type="button"
              className={styles.item}
              onMouseDown={(e) => {
                e.preventDefault();
                add(t.name);
              }}
            >
              <span className={styles.dot} style={{ background: t.color }} />
              {t.name}
              <span className={styles.itemCount}>{t.entry_count.toLocaleString()}</span>
            </button>
          ))}
          {q && !exactExists && (
            <button
              type="button"
              className={`${styles.item} ${styles.create}`}
              onMouseDown={(e) => {
                e.preventDefault();
                add(input);
              }}
            >
              + Create “{input.trim()}”
            </button>
          )}
        </div>
      )}
    </div>
  );
}
