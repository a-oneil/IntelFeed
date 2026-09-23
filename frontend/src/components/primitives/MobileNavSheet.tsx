import { useEffect, useState, type ReactNode } from "react";
import styles from "./MobileNavSheet.module.css";

interface Props {
  /** Heading for the sheet, e.g. "Settings" or "Workbench". */
  title: string;
  /** The section you are on, shown on the closed trigger. */
  current: string;
  /** The nav itself. Any click inside closes the sheet. */
  children: ReactNode;
}

/**
 * The mobile form of a secondary sidebar.
 *
 * Settings and the workbench both carry a nav that is a column on desktop. On a
 * phone, laying it out inline costs the whole viewport before any content —
 * Settings rendered three horizontal strips plus group headings and a footer,
 * roughly a full screen of chrome to reach one panel. Collapsing it to a single
 * row that names where you are, and opening the full nav as a slide-over, gives
 * back the screen and matches the Filters sheet on /search, so all three inner
 * navs behave the same way on touch.
 *
 * Any click inside the sheet closes it: every child here is a destination, so
 * requiring a separate dismiss after choosing one is a wasted tap. The one
 * exception is a form control — both navs put a filter box at the top, and
 * closing the sheet the moment you tapped it made the filter unusable.
 */
export function MobileNavSheet({ title, current, children }: Props) {
  const [open, setOpen] = useState(false);

  // The sheet is a full-height overlay; letting the page behind it scroll is
  // the classic mobile-sheet bug.
  useEffect(() => {
    if (!open) return;
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previous;
    };
  }, [open]);

  // Escape closes it, for the tablet-with-keyboard case.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  // Everything in the body is a destination except the filter box a nav may put
  // at its top — typing there must not dismiss the sheet.
  const onBodyClick = (e: React.MouseEvent<HTMLDivElement>) => {
    if ((e.target as HTMLElement).closest("input, textarea, select, label")) return;
    setOpen(false);
  };

  return (
    <>
      <button
        type="button"
        className={styles.trigger}
        onClick={() => setOpen(true)}
        aria-expanded={open}
        aria-label={`${title} sections. Currently ${current}.`}
      >
        <svg className={styles.triggerIcon} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
          <line x1="3" y1="6" x2="21" y2="6" />
          <line x1="3" y1="12" x2="21" y2="12" />
          <line x1="3" y1="18" x2="21" y2="18" />
        </svg>
        <span className={styles.triggerLabel}>{current}</span>
      </button>

      {open && <div className={styles.backdrop} onClick={() => setOpen(false)} />}

      <aside className={`${styles.sheet} ${open ? styles.sheetOpen : ""}`} aria-hidden={!open}>
        <div className={styles.head}>
          <span className={styles.headTitle}>{title}</span>
          <button type="button" className={styles.done} onClick={() => setOpen(false)}>
            Done
          </button>
        </div>
        {/* Bubbled clicks close the sheet — see the note above. */}
        <div className={styles.body} onClick={onBodyClick}>
          {children}
        </div>
      </aside>
    </>
  );
}
