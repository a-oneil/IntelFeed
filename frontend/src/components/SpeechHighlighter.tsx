import { useEffect, useRef, useState } from "react";
import { usePlayerStore } from "@/stores/playerStore";
import styles from "./SpeechHighlighter.module.css";

const BLOCK_SELECTOR = "p, h1, h2, h3, h4, h5, h6, li, blockquote, td, pre";

interface SpeechHighlighterProps {
  entryId: string;
  /** Has the title been prepended as paragraph 0? */
  hasTitle: boolean;
  headerRef: React.RefObject<HTMLElement | null>;
  contentRef: React.RefObject<HTMLDivElement | null>;
}

/**
 * Walk text nodes inside an element and find the node + local offset
 * for a given character offset within the element's full textContent.
 */
function findTextPosition(
  el: Element,
  charIndex: number,
): { node: Text; offset: number } | null {
  const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
  let remaining = charIndex;
  let node: Text | null;
  while ((node = walker.nextNode() as Text | null)) {
    const len = node.textContent?.length ?? 0;
    if (remaining < len) {
      return { node, offset: remaining };
    }
    remaining -= len;
  }
  return null;
}

export function SpeechHighlighter({
  entryId,
  hasTitle,
  headerRef,
  contentRef,
}: SpeechHighlighterProps) {
  const speechTrack = usePlayerStore((s) => s.speechTrack);
  const speechIndex = usePlayerStore((s) => s.speechIndex);
  const speechWordStart = usePlayerStore((s) => s.speechWordStart);
  const speechWordLength = usePlayerStore((s) => s.speechWordLength);
  const mode = usePlayerStore((s) => s.mode);
  const isPlaying = usePlayerStore((s) => s.isPlaying);

  const [rect, setRect] = useState<DOMRect | null>(null);
  const scrollContainerRef = useRef<Element | null>(null);
  const [scrollOffset, setScrollOffset] = useState({ top: 0, left: 0 });

  const isActive =
    mode === "speech" &&
    isPlaying &&
    speechTrack?.entryId === entryId &&
    speechWordStart >= 0 &&
    speechWordLength > 0;

  // Find the scroll container (the article pane)
  useEffect(() => {
    const content = contentRef.current;
    if (!content) return;
    // Walk up to find the scrollable ancestor
    let el: Element | null = content.parentElement;
    while (el) {
      const overflow = getComputedStyle(el).overflowY;
      if (overflow === "auto" || overflow === "scroll") {
        scrollContainerRef.current = el;
        return;
      }
      el = el.parentElement;
    }
    scrollContainerRef.current = document.documentElement;
  }, [contentRef]);

  // Track scroll to update highlight position
  useEffect(() => {
    const container = scrollContainerRef.current;
    if (!container || !isActive) return;
    const onScroll = () => {
      setScrollOffset({ top: container.scrollTop, left: container.scrollLeft });
    };
    container.addEventListener("scroll", onScroll, { passive: true });
    return () => container.removeEventListener("scroll", onScroll);
  }, [isActive]);

  // Compute highlight rect
  useEffect(() => {
    if (!isActive) {
      setRect(null);
      return;
    }

    const container = contentRef.current;
    if (!container) {
      setRect(null);
      return;
    }

    // Map speechIndex to a DOM element
    // Index 0 = title (in headerRef), indices 1+ = content blocks
    let targetEl: Element | null = null;

    if (hasTitle && speechIndex === 0) {
      // Title is in the header h1
      const h1 = headerRef.current?.querySelector("h1");
      targetEl = h1 || null;
    } else {
      const contentIndex = hasTitle ? speechIndex - 1 : speechIndex;
      const blocks = container.querySelectorAll(BLOCK_SELECTOR);
      // Walk blocks, skipping empties, to match how getArticleParagraphs works
      let nonEmptyCount = 0;
      for (let i = 0; i < blocks.length; i++) {
        const text = (blocks[i].textContent || "").trim();
        if (text) {
          if (nonEmptyCount === contentIndex) {
            targetEl = blocks[i];
            break;
          }
          nonEmptyCount++;
        }
      }
    }

    if (!targetEl) {
      setRect(null);
      return;
    }

    const pos = findTextPosition(targetEl, speechWordStart);
    if (!pos) {
      setRect(null);
      return;
    }

    const range = document.createRange();
    try {
      const endOffset = Math.min(
        pos.offset + speechWordLength,
        pos.node.textContent?.length ?? pos.offset,
      );
      range.setStart(pos.node, pos.offset);
      range.setEnd(pos.node, endOffset);
    } catch {
      setRect(null);
      return;
    }

    const wordRect = range.getBoundingClientRect();
    setRect(wordRect);

    // Auto-scroll the word into view
    const scrollContainer = scrollContainerRef.current;
    if (scrollContainer && scrollContainer !== document.documentElement) {
      const containerRect = scrollContainer.getBoundingClientRect();
      const relativeTop = wordRect.top - containerRect.top;
      const relativeBottom = wordRect.bottom - containerRect.top;
      const visibleHeight = scrollContainer.clientHeight;

      if (relativeBottom > visibleHeight - 40) {
        scrollContainer.scrollTop += relativeBottom - visibleHeight + 80;
      } else if (relativeTop < 40) {
        scrollContainer.scrollTop += relativeTop - 80;
      }
    }
  }, [
    isActive,
    speechIndex,
    speechWordStart,
    speechWordLength,
    hasTitle,
    contentRef,
    headerRef,
    scrollOffset, // re-run when scroll changes to keep position accurate
  ]);

  if (!isActive || !rect) return null;

  return (
    <div
      className={styles.highlight}
      style={{
        position: "fixed",
        top: rect.top,
        left: rect.left,
        width: rect.width,
        height: rect.height,
      }}
    />
  );
}
