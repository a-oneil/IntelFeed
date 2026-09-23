import { useState } from "react";
import { useNavigate } from "react-router-dom";
import type { GlossaryMatch } from "@/api/types";
import styles from "./GlossaryPanel.module.css";

const NIST_CSF_COLORS: Record<string, string> = {
  govern: "#6366f1",
  identify: "#3b82f6",
  protect: "#22c55e",
  detect: "#f59e0b",
  respond: "#ef4444",
  recover: "#8b5cf6",
};

const NIST_CSF_ORDER = ["govern", "identify", "protect", "detect", "respond", "recover"];

interface Props {
  matches: GlossaryMatch[];
  isLoading: boolean;
  onSearchArticles?: (term: GlossaryMatch["term"]) => void;
}

export function GlossaryPanel({ matches, isLoading, onSearchArticles }: Props) {
  if (isLoading) return <div className={styles.empty}>Scanning article...</div>;
  if (matches.length === 0)
    return <div className={styles.empty}>No glossary terms found in this article.</div>;

  // Group by category
  const grouped = new Map<string, GlossaryMatch[]>();
  for (const m of matches) {
    const cat = m.term.category;
    if (!grouped.has(cat)) grouped.set(cat, []);
    grouped.get(cat)!.push(m);
  }

  // Sort categories: NIST CSF first in order, then custom alphabetically
  const sortedCategories = [...grouped.keys()].sort((a, b) => {
    const aIdx = NIST_CSF_ORDER.indexOf(a);
    const bIdx = NIST_CSF_ORDER.indexOf(b);
    if (aIdx !== -1 && bIdx !== -1) return aIdx - bIdx;
    if (aIdx !== -1) return -1;
    if (bIdx !== -1) return 1;
    return a.localeCompare(b);
  });

  return (
    <div className={styles.container}>
      <div className={styles.summary}>
        {matches.length} term{matches.length !== 1 ? "s" : ""} detected
      </div>
      {sortedCategories.map((cat) => (
        <div key={cat} className={styles.categoryGroup}>
          <div className={styles.categoryHeader}>
            <span
              className={styles.categoryDot}
              style={{ backgroundColor: NIST_CSF_COLORS[cat] || "#6b7280" }}
            />
            <span className={styles.categoryName}>
              {cat.charAt(0).toUpperCase() + cat.slice(1)}
            </span>
            <span className={styles.categoryCount}>({grouped.get(cat)!.length})</span>
          </div>
          {grouped.get(cat)!.map((m) => (
            <TermCard key={m.term.id} match={m} onSearchArticles={onSearchArticles} />
          ))}
        </div>
      ))}
    </div>
  );
}

function TermCard({
  match,
  onSearchArticles,
}: {
  match: GlossaryMatch;
  onSearchArticles?: (term: GlossaryMatch["term"]) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const navigate = useNavigate();

  const handleSearch = (e: React.MouseEvent) => {
    e.stopPropagation();
    onSearchArticles?.(match.term);
  };

  const handleViewInGlossary = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigate(`/glossary?search=${encodeURIComponent(match.term.name)}`);
  };

  return (
    <div className={styles.termCard} onClick={() => setExpanded(!expanded)}>
      <div className={styles.termHeader}>
        <span className={styles.termName}>{match.term.name}</span>
        <button
          className={styles.searchBtn}
          onClick={handleSearch}
          title="Search articles with this term"
        >
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
        </button>
        <button
          className={styles.searchBtn}
          onClick={handleViewInGlossary}
          title="View on glossary page"
        >
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
            <polyline points="15 3 21 3 21 9" />
            <line x1="10" y1="14" x2="21" y2="3" />
          </svg>
        </button>
        <span className={styles.matchCount}>{match.match_count}x</span>
      </div>
      <p className={styles.termDesc}>{match.term.description}</p>
      {expanded && match.term.long_description && (
        <p className={styles.termLongDesc}>{match.term.long_description}</p>
      )}
      {expanded && match.term.technologies.length > 0 && (
        <div className={styles.techList}>
          {match.term.technologies.map((t) => (
            <span key={t.name} className={styles.techBadge}>
              {t.url ? (
                <a
                  href={t.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={(e) => e.stopPropagation()}
                >
                  {t.name}
                </a>
              ) : (
                t.name
              )}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
