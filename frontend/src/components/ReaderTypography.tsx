import { useState, useRef, useEffect, useLayoutEffect, type CSSProperties } from "react";
import { createPortal } from "react-dom";
import { useUIStore, type ReaderFontSize, type ReaderLineHeight, type ReaderMaxWidth } from "@/stores/uiStore";
import styles from "./ReaderTypography.module.css";

const FONT_SIZES: { value: ReaderFontSize; label: string }[] = [
  { value: 13, label: "13" },
  { value: 14, label: "14" },
  { value: 15, label: "15" },
  { value: 16, label: "16" },
  { value: 18, label: "18" },
  { value: 20, label: "20" },
];

const LINE_HEIGHTS: { value: ReaderLineHeight; label: string }[] = [
  { value: 1.4, label: "Tight" },
  { value: 1.6, label: "Normal" },
  { value: 1.7, label: "Relaxed" },
  { value: 1.8, label: "Loose" },
  { value: 2.0, label: "Double" },
];

const MAX_WIDTHS: { value: ReaderMaxWidth; label: string }[] = [
  { value: 600, label: "Narrow" },
  { value: 720, label: "Medium" },
  { value: 860, label: "Wide" },
  { value: 1000, label: "Extra wide" },
  { value: 0, label: "Full" },
];

export function ReaderTypography() {
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const [panelStyle, setPanelStyle] = useState<CSSProperties>({});
  const fontSize = useUIStore((s) => s.readerFontSize);
  const lineHeight = useUIStore((s) => s.readerLineHeight);
  const maxWidth = useUIStore((s) => s.readerMaxWidth);
  const highlightEntities = useUIStore((s) => s.readerHighlightEntities);
  const setFontSize = useUIStore((s) => s.setReaderFontSize);
  const setLineHeight = useUIStore((s) => s.setReaderLineHeight);
  const setMaxWidth = useUIStore((s) => s.setReaderMaxWidth);
  const setHighlightEntities = useUIStore((s) => s.setReaderHighlightEntities);

  useLayoutEffect(() => {
    if (!open || !triggerRef.current) return;
    const isMobile = window.matchMedia("(max-width: 767px)").matches;
    if (isMobile) {
      setPanelStyle({});
      return;
    }
    const update = () => {
      if (!triggerRef.current) return;
      const rect = triggerRef.current.getBoundingClientRect();
      setPanelStyle({
        position: "fixed",
        top: rect.bottom + 4,
        right: window.innerWidth - rect.right,
      });
    };
    update();
    window.addEventListener("resize", update);
    window.addEventListener("scroll", update, true);
    return () => {
      window.removeEventListener("resize", update);
      window.removeEventListener("scroll", update, true);
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    function handleClickOutside(e: MouseEvent) {
      const target = e.target as Node;
      if (containerRef.current?.contains(target)) return;
      if (panelRef.current?.contains(target)) return;
      setOpen(false);
    }
    function handleEscape(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", handleClickOutside);
    document.addEventListener("keydown", handleEscape);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleEscape);
    };
  }, [open]);

  return (
    <div className={styles.container} ref={containerRef}>
      <button
        ref={triggerRef}
        className={`${styles.trigger} ${open ? styles.triggerOpen : ""}`}
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        aria-haspopup="true"
        aria-label="Typography settings"
        title="Reader typography"
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="4 7 4 4 20 4 20 7" />
          <line x1="9" y1="20" x2="15" y2="20" />
          <line x1="12" y1="4" x2="12" y2="20" />
        </svg>
      </button>

      {open && createPortal(
        <div ref={panelRef} className={styles.panel} style={panelStyle}>
          <div className={styles.group}>
            <label className={styles.label}>Font size</label>
            <div className={styles.options}>
              {FONT_SIZES.map((s) => (
                <button
                  key={s.value}
                  className={`${styles.option} ${fontSize === s.value ? styles.optionActive : ""}`}
                  onClick={() => setFontSize(s.value)}
                >
                  {s.label}
                </button>
              ))}
            </div>
          </div>

          <div className={styles.group}>
            <label className={styles.label}>Line spacing</label>
            <div className={styles.options}>
              {LINE_HEIGHTS.map((h) => (
                <button
                  key={h.value}
                  className={`${styles.option} ${lineHeight === h.value ? styles.optionActive : ""}`}
                  onClick={() => setLineHeight(h.value)}
                >
                  {h.label}
                </button>
              ))}
            </div>
          </div>

          <div className={styles.group}>
            <label className={styles.label}>Content width</label>
            <div className={styles.options}>
              {MAX_WIDTHS.map((w) => (
                <button
                  key={w.value}
                  className={`${styles.option} ${maxWidth === w.value ? styles.optionActive : ""}`}
                  onClick={() => setMaxWidth(w.value)}
                >
                  {w.label}
                </button>
              ))}
            </div>
          </div>

          <div className={styles.group}>
            <label className={styles.label}>Highlight entities</label>
            <div className={styles.options}>
              <button
                className={`${styles.option} ${highlightEntities ? styles.optionActive : ""}`}
                onClick={() => setHighlightEntities(true)}
              >
                On
              </button>
              <button
                className={`${styles.option} ${!highlightEntities ? styles.optionActive : ""}`}
                onClick={() => setHighlightEntities(false)}
              >
                Off
              </button>
            </div>
          </div>

          <button
            className={styles.reset}
            onClick={() => {
              setFontSize(15);
              setLineHeight(1.7);
              setMaxWidth(1000);
              setHighlightEntities(true);
            }}
          >
            Reset defaults
          </button>
        </div>,
        document.body,
      )}
    </div>
  );
}
