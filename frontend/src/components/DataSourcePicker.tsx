import { useState, useRef, useEffect } from "react";
import { useDataSourceTaxonomy } from "@/hooks/useDetectionRules";
import { Chip } from "./primitives";
import styles from "./DataSourcePicker.module.css";

interface DataSourcePickerProps {
  value: string[];
  onChange: (value: string[]) => void;
}

export default function DataSourcePicker({
  value,
  onChange,
}: DataSourcePickerProps) {
  const { data: taxonomy } = useDataSourceTaxonomy();
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const toggle = (ds: string) => {
    if (value.includes(ds)) {
      onChange(value.filter((v) => v !== ds));
    } else {
      onChange([...value, ds]);
    }
  };

  const remove = (ds: string) => {
    onChange(value.filter((v) => v !== ds));
  };

  const filtered = taxonomy
    ? Object.entries(taxonomy).reduce<Record<string, string[]>>(
        (acc, [cat, sources]) => {
          const matching = sources.filter((s) =>
            s.toLowerCase().includes(search.toLowerCase())
          );
          if (matching.length > 0) acc[cat] = matching;
          return acc;
        },
        {}
      )
    : {};

  return (
    <div className={styles.container} ref={ref}>
      <div className={styles.chips}>
        {value.map((ds) => (
          <Chip key={ds} className={styles.chip}>
            {ds.replace(/_/g, " ")}
            <button
              className={styles.chipRemove}
              onClick={() => remove(ds)}
              type="button"
            >
              ×
            </button>
          </Chip>
        ))}
        <button
          className={styles.addBtn}
          onClick={() => setOpen(!open)}
          type="button"
        >
          + Add
        </button>
      </div>

      {open && (
        <div className={styles.dropdown}>
          <input
            className={styles.search}
            placeholder="Search data sources..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            autoFocus
          />
          <div className={styles.groups}>
            {Object.entries(filtered).map(([category, sources]) => (
              <div key={category} className={styles.group}>
                <div className={styles.groupLabel}>{category}</div>
                {sources.map((ds) => (
                  <button
                    key={ds}
                    className={`${styles.option} ${value.includes(ds) ? styles.selected : ""}`}
                    onClick={() => toggle(ds)}
                    type="button"
                  >
                    <span className={styles.checkbox}>
                      {value.includes(ds) ? "✓" : ""}
                    </span>
                    {ds.replace(/_/g, " ")}
                  </button>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
