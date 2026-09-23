import { useState, useRef, useEffect } from "react";
import styles from "./TimeRangeSelector.module.css";

export type TimeRange = "24h" | "7d" | "30d" | "90d" | "1y" | "all" | "custom";

interface TimeRangeSelectorProps {
  value: TimeRange;
  onChange: (range: TimeRange, customStart?: string, customEnd?: string) => void;
  customStart?: string;
  customEnd?: string;
  align?: "left" | "right";
}

const PRESETS: { value: TimeRange; label: string }[] = [
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
  { value: "90d", label: "Last 90 days" },
  { value: "1y", label: "Last year" },
  { value: "all", label: "All time" },
  { value: "custom", label: "Custom range" },
];

const LABEL_MAP: Record<TimeRange, string> = {
  "24h": "24h",
  "7d": "7d",
  "30d": "30d",
  "90d": "90d",
  "1y": "1y",
  all: "All time",
  custom: "Custom",
};

export function TimeRangeSelector({ value, onChange, customStart, customEnd, align = "right" }: TimeRangeSelectorProps) {
  const [open, setOpen] = useState(false);
  const [start, setStart] = useState(customStart || "");
  const [end, setEnd] = useState(customEnd || "");
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const handlePreset = (preset: TimeRange) => {
    if (preset === "custom") return;
    onChange(preset);
    setOpen(false);
  };

  const handleCustomApply = () => {
    if (start && end) {
      onChange("custom", start, end);
      setOpen(false);
    }
  };

  const label = value === "custom" && customStart && customEnd
    ? `${customStart} - ${customEnd}`
    : LABEL_MAP[value];

  return (
    <div className={styles.wrapper} ref={ref}>
      <button className={styles.trigger} onClick={() => setOpen(!open)}>
        {label}
        <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5">
          <path d="M2 4l3 3 3-3" />
        </svg>
      </button>
      {open && (
        <div className={`${styles.dropdown} ${align === "left" ? styles.dropdownLeft : ""}`}>
          {PRESETS.map((p) => (
            <button
              key={p.value}
              className={`${styles.option} ${p.value === value ? styles.optionActive : ""}`}
              onClick={() => p.value !== "custom" ? handlePreset(p.value) : undefined}
            >
              {p.label}
            </button>
          ))}
          <div className={styles.customRange}>
            <input type="date" value={start} onChange={(e) => setStart(e.target.value)} className={styles.dateInput} />
            <span className={styles.dateSep}>to</span>
            <input type="date" value={end} onChange={(e) => setEnd(e.target.value)} className={styles.dateInput} />
            <button className={styles.applyBtn} onClick={handleCustomApply} disabled={!start || !end}>
              Apply
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
