/**
 * TagPicker — a multi-select of tags with autocomplete over existing tags plus
 * inline create-new, for anywhere tags are configured by name (e.g. automation
 * add/remove-tags actions).
 *
 * With `presentation`, a tag that doesn't exist yet also gets a colour, a
 * "show as chip" switch and a tooltip, so a rule author sets the chip's look
 * the moment they invent it. Existing tags are never restyled from here — the
 * tag's own record is the source of truth.
 */
import { useMemo, useRef, useState } from "react";
import { useTags } from "@/hooks/useTags";
import { Chip } from "@/components/primitives/Chip";
import {
  DEFAULT_TAG_COLOR,
  normalizeTagSpec,
  tagSpecName,
  type NewTagSpec,
  type TagSpec,
} from "@/utils/tagSpecs";
import styles from "./TagPicker.module.css";

/** Quick picks for a new chip; the colour input covers everything else. */
const SWATCHES = ["#DC2626", "#EA580C", "#CA8A04", "#16A34A", "#0891B2", "#2563EB", "#7C3AED", "#DB2777"];

interface TagPickerProps {
  value: TagSpec[];
  onChange: (specs: TagSpec[]) => void;
  placeholder?: string;
  /** Offer colour / chip / tooltip for tags that will be created. */
  presentation?: boolean;
}

function NewTagEditor({ spec, onChange }: { spec: NewTagSpec; onChange: (spec: NewTagSpec) => void }) {
  const color = spec.color || DEFAULT_TAG_COLOR;
  return (
    <div className={styles.newTag}>
      <div className={styles.newTagHead}>
        {spec.chip ? (
          <Chip tone="solid" tint={color} size="sm" className={styles.preview} title={spec.description || spec.name}>
            {spec.name}
          </Chip>
        ) : (
          <span className={styles.chip}>
            <span className={styles.dot} style={{ background: color }} />
            {spec.name}
          </span>
        )}
        <span className={styles.newBadge}>new tag</span>
        <label className={styles.chipToggle}>
          <input
            type="checkbox"
            checked={!!spec.chip}
            onChange={(e) => onChange({ ...spec, chip: e.target.checked })}
          />
          Show as chip
        </label>
      </div>
      <div className={styles.swatches} role="radiogroup" aria-label={`Colour for ${spec.name}`}>
        {SWATCHES.map((c) => (
          <button
            key={c}
            type="button"
            role="radio"
            aria-checked={color.toLowerCase() === c.toLowerCase()}
            aria-label={c}
            className={styles.swatch}
            style={{ background: c }}
            onClick={() => onChange({ ...spec, color: c })}
          />
        ))}
        <input
          type="color"
          className={styles.colorInput}
          value={color}
          onChange={(e) => onChange({ ...spec, color: e.target.value })}
          aria-label={`Custom colour for ${spec.name}`}
        />
      </div>
      <input
        type="text"
        className={styles.description}
        maxLength={255}
        placeholder="Tooltip — what this chip means (optional)"
        value={spec.description ?? ""}
        onChange={(e) => onChange({ ...spec, description: e.target.value })}
      />
    </div>
  );
}

export function TagPicker({ value, onChange, placeholder = "Add or create tag…", presentation = false }: TagPickerProps) {
  const { data: tags = [], isSuccess } = useTags();
  const [input, setInput] = useState("");
  const [open, setOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const names = value.map(tagSpecName);
  const existing = (name: string) => tags.find((t) => t.name === name);
  const colorFor = (spec: TagSpec) =>
    existing(tagSpecName(spec))?.color ?? (typeof spec === "string" ? undefined : spec.color) ?? DEFAULT_TAG_COLOR;

  const q = input.trim().toLowerCase();
  const suggestions = useMemo(
    () =>
      tags
        .filter((t) => !names.includes(t.name) && (!q || t.name.toLowerCase().includes(q)))
        .slice(0, 8),
    [tags, names, q],
  );
  const exactExists =
    !!q && (tags.some((t) => t.name.toLowerCase() === q) || names.some((v) => v.toLowerCase() === q));

  const add = (name: string) => {
    const n = name.trim();
    setInput("");
    if (!n || names.includes(n)) return;
    onChange([...value, n]);
  };
  const remove = (name: string) => onChange(value.filter((v) => tagSpecName(v) !== name));
  const update = (index: number, spec: NewTagSpec) =>
    onChange(value.map((v, i) => (i === index ? normalizeTagSpec(spec) : v)));

  // Only once the tag list has loaded can "doesn't exist yet" be trusted.
  const pending = presentation && isSuccess ? value.filter((v) => !existing(tagSpecName(v))) : [];

  return (
    <div className={styles.wrap}>
      <div className={styles.control} onClick={() => inputRef.current?.focus()}>
        {value.map((spec) => {
          const name = tagSpecName(spec);
          return (
            <span key={name} className={styles.chip}>
              <span className={styles.dot} style={{ background: colorFor(spec) }} />
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
          );
        })}
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
              remove(names[names.length - 1]);
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
              {t.display_as_chip && <span className={styles.chipMark}>chip</span>}
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

      {pending.length > 0 && (
        <div className={styles.newTags}>
          {pending.map((spec) => {
            const name = tagSpecName(spec);
            return (
              <NewTagEditor
                key={name}
                spec={typeof spec === "string" ? { name } : spec}
                onChange={(next) => update(value.indexOf(spec), next)}
              />
            );
          })}
          <span className={styles.newTagsHint}>
            Set when the rule first creates the tag. Chips show in the badge row, only to you.
          </span>
        </div>
      )}
    </div>
  );
}
