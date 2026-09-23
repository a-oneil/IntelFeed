import { useEffect, useMemo, useRef, useState } from "react";

import { useSystemSettings } from "@/hooks/useSystemSettings";

import { destLabel, searchEngineSettings, type EngineDest } from "./engineSettingsIndex";
import s from "./EngineSettingsSearch.module.css";

/** "Where do I change X?" for the Engine console. Its settings are spread
 *  across stage panels, table views and browse screens by design — this finds
 *  one by name and opens the surface that owns it, flashing the row. */
export function EngineSettingsSearch({
  onPick,
  className,
}: {
  onPick: (dest: EngineDest, settingKey: string) => void;
  /** Extra class on the field wrapper — lets a toolbar flex it. */
  className?: string;
}) {
  const { data } = useSystemSettings();
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const wrapRef = useRef<HTMLDivElement>(null);

  const hits = useMemo(() => searchEngineSettings(q, data?.settings, data?.groups), [q, data]);

  useEffect(() => setActive(0), [q]);

  // Click-away — the dropdown outlives blur so a click on a row still lands.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!wrapRef.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  const pick = (i: number) => {
    const hit = hits[i];
    if (!hit) return;
    onPick(hit.dest, hit.key);
    setOpen(false);
    setQ("");
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Escape") {
      setOpen(false);
      return;
    }
    if (!hits.length) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((i) => (i + 1) % hits.length);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((i) => (i - 1 + hits.length) % hits.length);
    } else if (e.key === "Enter") {
      e.preventDefault();
      pick(active);
    }
  };

  return (
    <div className={className ? `${s.wrap} ${className}` : s.wrap} ref={wrapRef}>
      <input
        className={s.input}
        type="search"
        placeholder="Find a setting…"
        aria-label="Find an engine setting"
        value={q}
        onChange={(e) => {
          setQ(e.target.value);
          setOpen(true);
        }}
        onFocus={() => setOpen(true)}
        onKeyDown={onKeyDown}
      />
      {open && q.trim().length >= 2 && (
        <div className={s.menu} role="listbox">
          {hits.length === 0 && <div className={s.empty}>No engine setting matches “{q.trim()}”.</div>}
          {hits.map((hit, i) => (
            <button
              key={`${hit.dest.kind}:${hit.key || hit.label}`}
              type="button"
              role="option"
              aria-selected={i === active}
              className={`${s.row} ${i === active ? s.rowOn : ""}`}
              onMouseEnter={() => setActive(i)}
              onClick={() => pick(i)}
            >
              <span className={s.rowTop}>
                <span className={s.rowLabel}>{hit.label}</span>
                <span className={s.rowDest}>{destLabel(hit.dest)}</span>
              </span>
              {hit.hint && <span className={s.rowHint}>{hit.hint}</span>}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
