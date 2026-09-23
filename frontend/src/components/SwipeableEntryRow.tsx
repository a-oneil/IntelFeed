import { useRef, useCallback, type ReactNode } from "react";
import styles from "./SwipeableEntryRow.module.css";

const ACTION_WIDTH = 64;
const NUM_ACTIONS = 3;
const TOTAL_WIDTH = ACTION_WIDTH * NUM_ACTIONS;
const THRESHOLD = 40;

interface Props {
  children: ReactNode;
  onStar: () => void;
  onBookmark: () => void;
  onMarkRead: () => void;
}

export function SwipeableEntryRow({ children, onStar, onBookmark, onMarkRead }: Props) {
  const contentRef = useRef<HTMLDivElement>(null);
  const startX = useRef(0);
  const currentX = useRef(0);
  const isOpen = useRef(false);
  const isSwiping = useRef(false);

  const setTransform = (x: number, animate = false) => {
    const el = contentRef.current;
    if (!el) return;
    el.style.transition = animate ? "transform 0.2s ease" : "none";
    el.style.transform = `translateX(${x}px)`;
  };

  const handleTouchStart = useCallback((e: React.TouchEvent) => {
    startX.current = e.touches[0].clientX;
    currentX.current = isOpen.current ? -TOTAL_WIDTH : 0;
    isSwiping.current = false;
  }, []);

  const handleTouchMove = useCallback((e: React.TouchEvent) => {
    const dx = e.touches[0].clientX - startX.current;
    if (!isSwiping.current && Math.abs(dx) < 10) return;
    isSwiping.current = true;

    const base = isOpen.current ? -TOTAL_WIDTH : 0;
    const raw = base + dx;
    // Clamp between -TOTAL_WIDTH and 0 (no swipe right past origin)
    const clamped = Math.max(-TOTAL_WIDTH, Math.min(0, raw));
    setTransform(clamped);
  }, []);

  const handleTouchEnd = useCallback(() => {
    if (!isSwiping.current) return;
    const el = contentRef.current;
    if (!el) return;

    const current = new DOMMatrix(getComputedStyle(el).transform).m41;
    if (current < -THRESHOLD && !isOpen.current) {
      // Open
      setTransform(-TOTAL_WIDTH, true);
      isOpen.current = true;
    } else if (current > -TOTAL_WIDTH + THRESHOLD && isOpen.current) {
      // Close
      setTransform(0, true);
      isOpen.current = false;
    } else {
      // Snap back
      setTransform(isOpen.current ? -TOTAL_WIDTH : 0, true);
    }
    isSwiping.current = false;
  }, []);

  const close = useCallback(() => {
    setTransform(0, true);
    isOpen.current = false;
  }, []);

  return (
    <div className={styles.wrapper}>
      <div className={styles.actions}>
        <button
          className={`${styles.actionBtn} ${styles.starBtn}`}
          onClick={() => { onStar(); close(); }}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
          </svg>
          Star
        </button>
        <button
          className={`${styles.actionBtn} ${styles.bookmarkBtn}`}
          onClick={() => { onBookmark(); close(); }}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z" />
          </svg>
          Save
        </button>
        <button
          className={`${styles.actionBtn} ${styles.readBtn}`}
          onClick={() => { onMarkRead(); close(); }}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="20 6 9 17 4 12" />
          </svg>
          Read
        </button>
      </div>
      <div
        ref={contentRef}
        className={styles.content}
        onTouchStart={handleTouchStart}
        onTouchMove={handleTouchMove}
        onTouchEnd={handleTouchEnd}
      >
        {children}
      </div>
    </div>
  );
}
