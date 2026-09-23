import { useEffect, useRef, useState } from "react";
import type { WidgetConfigField } from "./registry";
import styles from "./WidgetSettingsPopover.module.css";

interface Props {
  fields: WidgetConfigField[];
  config: Record<string, unknown>;
  onSave: (patch: Record<string, unknown>) => void;
  onClose: () => void;
}

export default function WidgetSettingsPopover({ fields, config, onSave, onClose }: Props) {
  const [draft, setDraft] = useState<Record<string, unknown>>(() => {
    const initial: Record<string, unknown> = {};
    for (const f of fields) initial[f.key] = config[f.key];
    return initial;
  });
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function onDocClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("mousedown", onDocClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDocClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [onClose]);

  function setField(key: string, value: unknown) {
    setDraft((d) => ({ ...d, [key]: value }));
  }

  function handleSave() {
    const patch: Record<string, unknown> = {};
    for (const f of fields) {
      const value = draft[f.key];
      if (value === undefined || value === "") continue;
      if (f.type === "number") {
        const n = Number(value);
        if (Number.isNaN(n)) continue;
        patch[f.key] = Math.min(f.max ?? n, Math.max(f.min ?? n, Math.round(n)));
      } else {
        patch[f.key] = value;
      }
    }
    onSave(patch);
  }

  return (
    <div className={styles.popover} ref={ref} role="dialog" aria-label="Widget settings">
      {fields.map((field) => (
        <div key={field.key} className={styles.field}>
          <label className={styles.label} htmlFor={`wcfg-${field.key}`}>
            {field.label}
          </label>
          {field.type === "number" && (
            <input
              id={`wcfg-${field.key}`}
              className={styles.input}
              type="number"
              min={field.min}
              max={field.max}
              value={(draft[field.key] as number) ?? ""}
              placeholder="default"
              onChange={(e) => setField(field.key, e.target.value)}
            />
          )}
          {field.type === "select" && (
            <select
              id={`wcfg-${field.key}`}
              className={styles.input}
              value={(draft[field.key] as string) ?? ""}
              onChange={(e) => setField(field.key, e.target.value)}
            >
              {(field.options ?? []).map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          )}
          {field.type === "boolean" && (
            <label className={styles.checkboxRow}>
              <input
                id={`wcfg-${field.key}`}
                type="checkbox"
                checked={Boolean(draft[field.key])}
                onChange={(e) => setField(field.key, e.target.checked)}
              />
              <span>enabled</span>
            </label>
          )}
        </div>
      ))}
      <div className={styles.actions}>
        <button className={styles.cancelBtn} onClick={onClose}>
          Cancel
        </button>
        <button className={styles.saveBtn} onClick={handleSave}>
          Save
        </button>
      </div>
      <p className={styles.hint}>Time range follows the dashboard selector.</p>
    </div>
  );
}
