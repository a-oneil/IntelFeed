import { useEffect, useState, useCallback } from "react";
import styles from "./ReaderTOC.module.css";

const MIN_CHARS = 8000;
const MIN_HEADINGS = 4;

interface TOCEntry {
  id: string;
  text: string;
  level: number;
}

function slugify(text: string, seen: Set<string>): string {
  const base = "toc-" + text.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "").slice(0, 60) || "section";
  let slug = base;
  let i = 2;
  while (seen.has(slug)) slug = `${base}-${i++}`;
  seen.add(slug);
  return slug;
}

/**
 * Sticky "Contents" card for long-form articles. Only renders once the
 * article body has enough headings to be worth a jump-list — most entries
 * are short news items and would just get visual noise otherwise.
 */
export function ReaderTOC({
  containerRef,
  contentLength,
}: {
  containerRef: React.RefObject<HTMLDivElement | null>;
  contentLength: number;
}) {
  const [entries, setEntries] = useState<TOCEntry[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [collapsed, setCollapsed] = useState(false);

  const eligible = contentLength >= MIN_CHARS;

  useEffect(() => {
    if (!eligible) {
      setEntries([]);
      return;
    }
    const container = containerRef.current;
    if (!container) return;

    // Article HTML is injected via SafeHTML after this effect's first run —
    // poll briefly for headings to appear, then observe for later swaps
    // (translation toggle, entry navigation re-rendering the same DOM node).
    let cancelled = false;
    let observer: MutationObserver | null = null;

    const scan = () => {
      if (cancelled) return;
      const headingEls = Array.from(container.querySelectorAll<HTMLElement>("h1, h2, h3"));
      if (headingEls.length < MIN_HEADINGS) {
        setEntries([]);
        return;
      }
      const seen = new Set<string>();
      const next: TOCEntry[] = headingEls.map((el) => {
        if (!el.id) el.id = slugify(el.textContent || "", seen);
        else seen.add(el.id);
        return { id: el.id, text: el.textContent || "", level: Number(el.tagName[1]) };
      });
      setEntries(next);
    };

    scan();
    observer = new MutationObserver(() => scan());
    observer.observe(container, { childList: true, subtree: true });

    return () => {
      cancelled = true;
      observer?.disconnect();
    };
  }, [containerRef, eligible]);

  // Scrollspy: highlight whichever heading is nearest the top of the viewport.
  useEffect(() => {
    if (entries.length === 0) return;
    const els = entries.map((e) => document.getElementById(e.id)).filter(Boolean) as HTMLElement[];
    if (els.length === 0) return;

    const io = new IntersectionObserver(
      (observed) => {
        const visible = observed.filter((o) => o.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible[0]) setActiveId(visible[0].target.id);
      },
      { rootMargin: "-64px 0px -70% 0px" },
    );
    els.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, [entries]);

  const handleJump = useCallback((id: string) => {
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);

  if (!eligible || entries.length === 0) return null;

  return (
    <div className={styles.toc}>
      <button className={styles.tocHeader} onClick={() => setCollapsed((c) => !c)}>
        <span>Contents</span>
        <span className={styles.tocCount}>{entries.length}</span>
        <span className={`${styles.tocChevron} ${collapsed ? styles.tocChevronCollapsed : ""}`}>▾</span>
      </button>
      {!collapsed && (
        <ul className={styles.tocList}>
          {entries.map((e) => (
            <li key={e.id} className={styles.tocItem} style={{ paddingLeft: `${(e.level - 1) * 12}px` }}>
              <button
                className={`${styles.tocLink} ${activeId === e.id ? styles.tocLinkActive : ""}`}
                onClick={() => handleJump(e.id)}
              >
                {e.text}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
