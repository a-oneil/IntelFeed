import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useAuthStore } from "@/stores/authStore";
import { useIntelStore } from "@/stores/intelStore";
import { useUIStore } from "@/stores/uiStore";
import { getEntityColor, getEntityLabel } from "@/utils/entityTheme";
import { getRouteLabel } from "@/utils/routeLabels";
import type { EntitySearchResult } from "@/api/types";
import {
  QUICK_ACTIONS,
  ACTION_CATEGORY_LABELS,
  ACTION_CATEGORY_ORDER,
  fuzzyScore,
  type ActionCategory,
  type QuickAction,
} from "@/components/search/commands";
import styles from "./CommandPalette.module.css";

/**
 * ⌘K — the app's command launcher.
 *
 * Commands only: it fuzzy-matches the static vocabulary in
 * `components/search/commands.ts` and never queries the server. Looking things
 * *up* (entities, entries, feeds) belongs to the /search route, which the
 * palette's own "Search" command opens.
 */

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
}

// --- Recently visited tracking ---

const RECENT_KEY = "intelfeed-recent-pages";
const MAX_RECENT = 8;

interface RecentPage {
  path: string;
  label: string;
  timestamp: number;
}

function loadRecentPages(): RecentPage[] {
  try {
    const raw = localStorage.getItem(RECENT_KEY);
    if (!raw) return [];
    return JSON.parse(raw) as RecentPage[];
  } catch {
    return [];
  }
}

function saveRecentPage(path: string) {
  if (path.startsWith("/shared/")) return; // Public share pages aren't "yours"
  const label = getRouteLabel(path);
  if (!label) return; // Don't track unknown pages (login, etc.)

  const recent = loadRecentPages();
  // Remove duplicate if exists
  const filtered = recent.filter((r) => r.path !== path);
  // Prepend new visit
  filtered.unshift({ path, label, timestamp: Date.now() });
  // Trim to max
  localStorage.setItem(RECENT_KEY, JSON.stringify(filtered.slice(0, MAX_RECENT)));
}

// --- Navigation history ---

function entityRouteFromPivotType(type: string, id: string): string {
  switch (type) {
    case "threat_actor": return `/workbench/threat_actor/${id}`;
    case "malware": return `/workbench/malware/${id}`;
    case "cve": return `/workbench/cve/${id}`;
    case "ttp": return `/workbench/ttp/${id}`;
    case "country": return `/workbench/country/${id}`;
    case "tool": return `/workbench/tool/${id}`;
    case "mitigation": return `/workbench/mitigation/${id}`;
    case "cwe": return `/workbench/cwe/${id}`;
    case "vendor": return `/workbench/vendor/${id}`;
    case "product": return `/workbench/product/${id}`;
    default: return `/workbench/explore`;
  }
}

// --- Component ---

export function CommandPalette({ open, onClose }: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  const location = useLocation();

  const isAdmin = useAuthStore((s) => s.user?.role === "admin");
  const recentPivots = useIntelStore((s) => s.recentPivots);
  const setActiveSection = useIntelStore((s) => s.setActiveSection);
  const openCopilot = useUIStore((s) => s.openCopilot);
  const openAddFeed = useUIStore((s) => s.openAddFeed);
  const openIngest = useUIStore((s) => s.openIngest);
  const openShortcutsHelp = useUIStore((s) => s.openShortcutsHelp);

  // Track page visits for "recently visited"
  useEffect(() => {
    saveRecentPage(location.pathname + location.search);
  }, [location.pathname, location.search]);

  // Focus input when opened
  useEffect(() => {
    if (open) {
      setQuery("");
      setSelectedIndex(0);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);


  const recentPages = useMemo(() => loadRecentPages(), [open]); // eslint-disable-line react-hooks/exhaustive-deps

  const actions = useMemo(
    () => QUICK_ACTIONS.filter((a) => isAdmin || !a.adminOnly),
    [isAdmin],
  );

  const runAction = useCallback(
    (action: QuickAction) => {
      switch (action.special) {
        case "open-copilot":
          openCopilot();
          onClose();
          return;
        case "open-add-feed":
          openAddFeed();
          onClose();
          return;
        case "open-ingest":
          openIngest();
          onClose();
          return;
        case "show-shortcuts":
          openShortcutsHelp();
          onClose();
          return;
      }
      if (action.workbenchSection) {
        setActiveSection(action.workbenchSection);
      }
      navigate(action.path);
      onClose();
    },
    [navigate, onClose, openAddFeed, openCopilot, openIngest, openShortcutsHelp, setActiveSection],
  );

  // Build flat result list for keyboard nav
  type ResultItem = {
    type: "recent" | "recent-entity" | "action";
    category?: ActionCategory;
    label: string;
    sublabel?: string;
    color?: string;
    shortcut?: string;
    onSelect: () => void;
  };

  const results: ResultItem[] = [];

  if (query.length > 0) {
    // --- Filter mode: the typed text narrows the command vocabulary ---
    const scored = actions
      .map((action) => ({ action, score: fuzzyScore(query, action.label, action.keywords) }))
      .filter(({ score }) => score > 0)
      .sort(
        (a, b) =>
          b.score - a.score ||
          ACTION_CATEGORY_ORDER.indexOf(a.action.category) -
            ACTION_CATEGORY_ORDER.indexOf(b.action.category),
      );

    for (const { action } of scored) {
      results.push({
        type: "action",
        category: action.category,
        label: action.label,
        shortcut: action.shortcut,
        onSelect: () => runAction(action),
      });
    }
  } else {
    // --- Empty query: recent entities, recently visited, then all commands ---

    // Recent entities from intel store (up to 5), skip entries with UUID-only labels
    const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    const validPivots = recentPivots.filter((p) => !uuidPattern.test(p.label));
    for (const pivot of validPivots.slice(0, 5)) {
      results.push({
        type: "recent-entity",
        label: pivot.label,
        sublabel: getEntityLabel(pivot.type as EntitySearchResult["type"]) || pivot.type.replace("_", " "),
        color: getEntityColor(pivot.type as EntitySearchResult["type"]),
        onSelect: () => {
          navigate(entityRouteFromPivotType(pivot.type, pivot.id));
          onClose();
        },
      });
    }

    // Recently visited pages
    for (const page of recentPages.slice(0, 4)) {
      results.push({
        type: "recent",
        label: page.label,
        sublabel: timeAgo(page.timestamp),
        onSelect: () => {
          navigate(page.path);
          onClose();
        },
      });
    }

    // Show commands grouped by category
    for (const cat of ACTION_CATEGORY_ORDER) {
      for (const action of actions.filter((a) => a.category === cat)) {
        results.push({
          type: "action",
          category: cat,
          label: action.label,
          shortcut: action.shortcut,
          onSelect: () => runAction(action),
        });
      }
    }
  }

  // Clamp selected index
  const clampedIndex = Math.min(selectedIndex, Math.max(results.length - 1, 0));

  const selectResult = useCallback(
    (index: number) => {
      results[index]?.onSelect();
    },
    [results]
  );

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setSelectedIndex((i) => Math.min(i + 1, results.length - 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setSelectedIndex((i) => Math.max(i - 1, 0));
      } else if (e.key === "Enter") {
        e.preventDefault();
        selectResult(clampedIndex);
      } else if (e.key === "Escape") {
        onClose();
      }
    },
    [results.length, clampedIndex, selectResult, onClose]
  );

  // Scroll selected item into view
  useEffect(() => {
    const list = listRef.current;
    if (!list) return;
    const items = list.querySelectorAll(`.${styles.resultItem}`);
    const item = items[clampedIndex] as HTMLElement;
    if (item) {
      item.scrollIntoView({ block: "nearest" });
    }
  }, [clampedIndex]);

  if (!open) return null;

  // Group results by section for headers
  let lastSection = "";

  function getSectionKey(item: ResultItem): string {
    if (item.type === "recent-entity") return "recent-entity";
    if (item.type === "recent") return "recent";
    if (item.type === "action" && item.category) return `action-${item.category}`;
    return "action";
  }

  function getSectionLabel(item: ResultItem): string {
    if (item.type === "recent-entity") return "RECENT ENTITIES";
    if (item.type === "recent") return "RECENTLY VISITED";
    if (item.type === "action" && item.category) return ACTION_CATEGORY_LABELS[item.category];
    return "COMMANDS";
  }

  // Track the flat index for keyboard selection across section headers
  let flatIndex = 0;

  return (
    <div className={styles.overlay} onClick={onClose}>
      <div
        id="command-palette-dialog"
        className={styles.palette}
        role="dialog"
        aria-label="Command palette"
        onClick={(e) => e.stopPropagation()}
      >
        <div className={styles.inputRow}>
          <svg
            className={styles.searchIcon}
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <input
            ref={inputRef}
            type="text"
            className={styles.input}
            placeholder="Search commands..."
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
            onKeyDown={handleKeyDown}
          />
          <kbd className={styles.kbd}>esc</kbd>
        </div>

        <div className={styles.results} ref={listRef}>
          {results.length === 0 && query.length > 0 && (
            <div className={styles.noResults}>
              No command matches — try the Search page for entities and articles
            </div>
          )}

          {results.map((item, _i) => {
            const sectionKey = getSectionKey(item);
            let sectionHeader: string | null = null;
            if (sectionKey !== lastSection) {
              lastSection = sectionKey;
              sectionHeader = getSectionLabel(item);
            }

            const idx = flatIndex++;

            return (
              <div key={idx}>
                {sectionHeader && (
                  <div className={styles.sectionHeader}>{sectionHeader}</div>
                )}
                <button
                  className={`${styles.resultItem} ${idx === clampedIndex ? styles.selected : ""}`}
                  onClick={() => selectResult(idx)}
                  onMouseEnter={() => setSelectedIndex(idx)}
                >
                  {item.color && (
                    <span
                      className={styles.dot}
                      style={{ backgroundColor: item.color }}
                    />
                  )}
                  {item.type === "recent-entity" && !item.color && (
                    <span className={styles.recentIcon}>↩</span>
                  )}
                  {item.type === "recent" && (
                    <span className={styles.recentIcon}>⏱</span>
                  )}
                  {item.type === "action" && item.category === "create" && (
                    <span className={`${styles.actionIcon} ${styles.createIcon}`}>✚</span>
                  )}
                  {item.type === "action" && item.category === "navigate" && (
                    <span className={styles.actionIcon}>→</span>
                  )}
                  {item.type === "action" && item.category === "browse" && (
                    <span className={styles.actionIcon}>◆</span>
                  )}
                  {item.type === "action" && item.category === "manage" && (
                    <span className={styles.actionIcon}>⚙</span>
                  )}
                  {item.type === "action" && item.category === "run" && (
                    <span className={`${styles.actionIcon} ${styles.runIcon}`}>▶</span>
                  )}
                  <span className={styles.resultLabel}>{item.label}</span>
                  {item.sublabel && (
                    <span className={styles.resultSublabel}>{item.sublabel}</span>
                  )}
                  {item.shortcut && (
                    <kbd className={styles.resultShortcut}>{item.shortcut}</kbd>
                  )}
                </button>
              </div>
            );
          })}
        </div>

        <div className={styles.footer}>
          <span>
            <kbd className={styles.kbdSmall}>&uarr;&darr;</kbd> navigate
          </span>
          <span>
            <kbd className={styles.kbdSmall}>&crarr;</kbd> select
          </span>
          <span>
            <kbd className={styles.kbdSmall}>esc</kbd> close
          </span>
        </div>
      </div>
    </div>
  );
}

// --- Helpers ---

function timeAgo(timestamp: number): string {
  const diff = Date.now() - timestamp;
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
