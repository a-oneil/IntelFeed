import { useMemo, useState } from "react";
import type { DashboardWidget } from "@/api/types";
import WidgetRenderer, { type TimeRange } from "./WidgetRenderer";
import styles from "./WidgetPicker.module.css";
import { WIDGET_REGISTRY, type WidgetDefinition } from "./registry";

interface Props {
  onAdd: (type: string, title: string, width: number, height: number) => void;
  onClose: () => void;
  /** Dashboard range, so the preview shows the data the widget will actually get. */
  timeRange?: TimeRange;
  timeRangeStart?: string;
  timeRangeEnd?: string;
}

/** Grid geometry from DashboardPage, so the preview matches the real footprint. */
const ROW_HEIGHT = 80;
const ROW_MARGIN = 12;

/** A throwaway widget record so the preview can reuse the real renderer. */
function previewWidget(def: WidgetDefinition): DashboardWidget {
  return {
    id: `preview-${def.type}`,
    dashboard_id: "preview",
    widget_type: def.type,
    title: def.label,
    config: {},
    position_x: 0,
    position_y: 0,
    width: def.defaultW,
    height: def.defaultH,
  };
}

export default function WidgetPicker({
  onAdd,
  onClose,
  timeRange,
  timeRangeStart,
  timeRangeEnd,
}: Props) {
  // Sort by label so the picker order remains stable regardless of registry
  // declaration order. Retired types are filtered out here but still render on
  // dashboards that already persist them.
  const widgets = useMemo(
    () =>
      WIDGET_REGISTRY.filter((w) => !w.hidden).sort((a, b) =>
        a.label.localeCompare(b.label, undefined, { sensitivity: "base" }),
      ),
    [],
  );

  const [query, setQuery] = useState("");
  const [selectedType, setSelectedType] = useState<string>(widgets[0]?.type ?? "");

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return widgets;
    return widgets.filter(
      (w) => w.label.toLowerCase().includes(q) || w.description.toLowerCase().includes(q),
    );
  }, [widgets, query]);

  const selected =
    filtered.find((w) => w.type === selectedType) ?? filtered[0] ?? null;

  return (
    <div className={styles.overlay} onClick={onClose}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
        <div className={styles.modalHeader}>
          <h2>Add Widget</h2>
          <button onClick={onClose} className={styles.closeBtn} aria-label="Close">
            x
          </button>
        </div>

        <div className={styles.body}>
          <div className={styles.listPane}>
            <input
              className={styles.search}
              placeholder="Search widgets…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              autoFocus
            />
            <div className={styles.list} role="listbox" aria-label="Available widgets">
              {filtered.map((wt) => (
                <button
                  key={wt.type}
                  role="option"
                  aria-selected={selected?.type === wt.type}
                  className={`${styles.listItem} ${
                    selected?.type === wt.type ? styles.listItemActive : ""
                  }`}
                  onClick={() => setSelectedType(wt.type)}
                  onDoubleClick={() => onAdd(wt.type, wt.label, wt.defaultW, wt.defaultH)}
                >
                  <span className={styles.itemLabel}>{wt.label}</span>
                  <span className={styles.itemDesc}>{wt.description}</span>
                </button>
              ))}
              {filtered.length === 0 && (
                <p className={styles.emptyList}>No widgets match “{query}”.</p>
              )}
            </div>
          </div>

          <div className={styles.previewPane}>
            {selected ? (
              <>
                <div className={styles.previewHead}>
                  <div>
                    <h3 className={styles.previewTitle}>{selected.label}</h3>
                    <p className={styles.previewDesc}>{selected.description}</p>
                  </div>
                  <span className={styles.sizeChip}>
                    {selected.defaultW} × {selected.defaultH}
                  </span>
                </div>

                {/* Live preview: the real component, real data, current range,
                    at the height it will occupy on the grid. */}
                <div
                  className={styles.previewCard}
                  style={{
                    height:
                      selected.defaultH * ROW_HEIGHT + (selected.defaultH - 1) * ROW_MARGIN,
                  }}
                >
                  <div className={styles.previewCardHead}>
                    <span className={styles.previewCardTitle}>{selected.label}</span>
                  </div>
                  <div className={styles.previewCardBody}>
                    <WidgetRenderer
                      key={selected.type}
                      widget={previewWidget(selected)}
                      timeRange={timeRange}
                      timeRangeStart={timeRangeStart}
                      timeRangeEnd={timeRangeEnd}
                    />
                  </div>
                </div>

                <div className={styles.previewActions}>
                  <span className={styles.previewHint}>Showing your live data</span>
                  <button
                    className={styles.addBtn}
                    onClick={() =>
                      onAdd(selected.type, selected.label, selected.defaultW, selected.defaultH)
                    }
                  >
                    Add to dashboard
                  </button>
                </div>
              </>
            ) : (
              <p className={styles.emptyList}>Select a widget to preview it.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
