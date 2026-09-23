import { useState, useEffect, useCallback, useRef } from "react";
import styles from "./FindInArticle.module.css";

interface FindInArticleProps {
  containerRef: React.RefObject<HTMLDivElement | null>;
  onClose: () => void;
}

const HIGHLIGHT_CLASS = "find-in-article-highlight";
const ACTIVE_CLASS = "find-in-article-active";

export function FindInArticle({ containerRef, onClose }: FindInArticleProps) {
  const [query, setQuery] = useState("");
  const [matchCount, setMatchCount] = useState(0);
  const [currentMatch, setCurrentMatch] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const highlightsRef = useRef<HTMLElement[]>([]);

  // Focus input on mount
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  // Clear highlights on unmount
  useEffect(() => {
    return () => clearHighlights();
  }, []);

  const clearHighlights = useCallback(() => {
    const container = containerRef.current;
    if (!container) return;

    const marks = container.querySelectorAll(`mark.${HIGHLIGHT_CLASS}`);
    marks.forEach((mark) => {
      const parent = mark.parentNode;
      if (parent) {
        parent.replaceChild(document.createTextNode(mark.textContent || ""), mark);
        parent.normalize();
      }
    });
    highlightsRef.current = [];
  }, [containerRef]);

  const doSearch = useCallback(
    (searchQuery: string) => {
      clearHighlights();

      if (!searchQuery.trim() || !containerRef.current) {
        setMatchCount(0);
        setCurrentMatch(0);
        return;
      }

      const container = containerRef.current;
      const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT, null);
      const textNodes: Text[] = [];

      let node: Text | null;
      while ((node = walker.nextNode() as Text | null)) {
        // Skip nodes inside <script>, <style>, or existing highlights
        const parent = node.parentElement;
        if (parent && (parent.tagName === "SCRIPT" || parent.tagName === "STYLE" || parent.classList?.contains(HIGHLIGHT_CLASS))) {
          continue;
        }
        textNodes.push(node);
      }

      const lowerQuery = searchQuery.toLowerCase();
      const newHighlights: HTMLElement[] = [];

      for (const textNode of textNodes) {
        const text = textNode.textContent || "";
        const lowerText = text.toLowerCase();
        let startIndex = 0;
        const indices: number[] = [];

        while (startIndex < lowerText.length) {
          const idx = lowerText.indexOf(lowerQuery, startIndex);
          if (idx === -1) break;
          indices.push(idx);
          startIndex = idx + lowerQuery.length;
        }

        if (indices.length === 0) continue;

        // Split text node and wrap matches in <mark>
        const fragment = document.createDocumentFragment();
        let lastEnd = 0;

        for (const idx of indices) {
          if (idx > lastEnd) {
            fragment.appendChild(document.createTextNode(text.slice(lastEnd, idx)));
          }

          const mark = document.createElement("mark");
          mark.className = HIGHLIGHT_CLASS;
          mark.textContent = text.slice(idx, idx + searchQuery.length);
          fragment.appendChild(mark);
          newHighlights.push(mark);

          lastEnd = idx + searchQuery.length;
        }

        if (lastEnd < text.length) {
          fragment.appendChild(document.createTextNode(text.slice(lastEnd)));
        }

        textNode.parentNode?.replaceChild(fragment, textNode);
      }

      highlightsRef.current = newHighlights;
      setMatchCount(newHighlights.length);

      if (newHighlights.length > 0) {
        setCurrentMatch(1);
        scrollToMatch(newHighlights[0]);
      } else {
        setCurrentMatch(0);
      }
    },
    [containerRef, clearHighlights],
  );

  const scrollToMatch = (el: HTMLElement) => {
    highlightsRef.current.forEach((h) => h.classList.remove(ACTIVE_CLASS));
    el.classList.add(ACTIVE_CLASS);
    el.scrollIntoView({ behavior: "smooth", block: "center" });
  };

  const goToMatch = useCallback(
    (direction: "next" | "prev") => {
      if (matchCount === 0) return;
      let next = direction === "next" ? currentMatch + 1 : currentMatch - 1;
      if (next > matchCount) next = 1;
      if (next < 1) next = matchCount;
      setCurrentMatch(next);
      scrollToMatch(highlightsRef.current[next - 1]);
    },
    [currentMatch, matchCount],
  );

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      clearHighlights();
      onClose();
    } else if (e.key === "Enter") {
      goToMatch(e.shiftKey ? "prev" : "next");
    }
  };

  useEffect(() => {
    const timeout = setTimeout(() => doSearch(query), 150);
    return () => clearTimeout(timeout);
  }, [query, doSearch]);

  return (
    <div className={styles.findBar}>
      <input
        ref={inputRef}
        className={styles.findInput}
        type="text"
        placeholder="Find in article..."
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        onKeyDown={handleKeyDown}
      />
      {query && (
        <span className={styles.matchCount}>
          {matchCount === 0 ? "No matches" : `${currentMatch} / ${matchCount}`}
        </span>
      )}
      <button
        className={styles.findNavBtn}
        onClick={() => goToMatch("prev")}
        disabled={matchCount === 0}
        title="Previous (Shift+Enter)"
      >
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="18 15 12 9 6 15" />
        </svg>
      </button>
      <button
        className={styles.findNavBtn}
        onClick={() => goToMatch("next")}
        disabled={matchCount === 0}
        title="Next (Enter)"
      >
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="6 9 12 15 18 9" />
        </svg>
      </button>
      <button
        className={styles.findCloseBtn}
        onClick={() => {
          clearHighlights();
          onClose();
        }}
        title="Close (Esc)"
      >
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
          <line x1="18" y1="6" x2="6" y2="18" />
          <line x1="6" y1="6" x2="18" y2="18" />
        </svg>
      </button>
    </div>
  );
}
