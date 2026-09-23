import { useState, useEffect, useRef, useCallback } from "react";
import { createPortal } from "react-dom";
import { useNavigate } from "react-router-dom";
import { useUIStore } from "@/stores/uiStore";
import { useAITasks, useRunAIOnText } from "@/hooks/useAI";
import { useEnrichmentSources, useEnrichValue } from "@/hooks/useEnrichment";
import { useCreateSavedSearch } from "@/hooks/useSearch";
import { getPivotLinks } from "@/utils/pivotLinks";
import styles from "./SelectionContextMenu.module.css";

interface SelectionContextMenuProps {
  containerRef: React.RefObject<HTMLElement | null> | React.RefObject<HTMLElement | null>[];
  /** Entry the selection lives in, when there is one. Omitted for entry-less
   *  contexts like the daily summary — the chat pivot and Link-to-entity action
   *  (both of which need an entry) are hidden in that case. */
  entryId?: string;
  onCreateEntity: (text: string) => void;
  onCreateNote: (selectedText: string) => void;
  onAddAlias: (text: string) => void;
  /** Links the selection to an entity *on this entry*. Omit in entry-less
   *  contexts — the menu item is then hidden. */
  onLinkEntity?: (text: string) => void;
}

interface MenuState {
  left: number;
  top: number;
  showBelow: boolean;
  text: string;
}

type Submenu = "ai_task" | "enrich" | "pivot" | null;

const MENU_WIDTH = 224;
const MENU_HEIGHT = 380;
const PADDING = 8;
const GAP = 6;

export function SelectionContextMenu({
  containerRef,
  entryId,
  onCreateEntity,
  onCreateNote,
  onAddAlias,
  onLinkEntity,
}: SelectionContextMenuProps) {
  const [menu, setMenu] = useState<MenuState | null>(null);
  const [submenu, setSubmenu] = useState<Submenu>(null);
  const [enrichResult, setEnrichResult] = useState<string | null>(null);
  const [aiResult, setAiResult] = useState<string | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  const setHeaderSearchQuery = useUIStore((s) => s.setHeaderSearchQuery);

  const { data: aiTasks } = useAITasks();
  const { data: enrichSources } = useEnrichmentSources();
  const runAIOnText = useRunAIOnText();
  const enrichValue = useEnrichValue();
  const createSavedSearch = useCreateSavedSearch();

  const dismiss = useCallback(() => {
    setMenu(null);
    setSubmenu(null);
    setEnrichResult(null);
    setAiResult(null);
  }, []);

  const handleMouseUp = useCallback((e: MouseEvent) => {
    // Clicking inside the menu (e.g. submenu toggles) collapses the selection —
    // ignore those events so the menu doesn't immediately dismiss itself.
    if (menuRef.current && menuRef.current.contains(e.target as Node)) return;

    setTimeout(() => {
      const selection = window.getSelection();
      if (!selection || selection.isCollapsed || selection.rangeCount === 0) {
        setMenu(null);
        return;
      }
      const text = selection.toString().trim();
      if (text.length < 2) {
        setMenu(null);
        return;
      }

      const containers = Array.isArray(containerRef)
        ? containerRef.map((r) => r.current).filter(Boolean)
        : [containerRef.current].filter(Boolean);
      if (containers.length === 0) return;
      const range = selection.getRangeAt(0);
      const anchor = range.commonAncestorContainer;
      if (!containers.some((c) => c!.contains(anchor))) {
        setMenu(null);
        return;
      }

      const rect = range.getBoundingClientRect();
      const centerX = rect.left + rect.width / 2;
      let left = centerX - MENU_WIDTH / 2;
      left = Math.max(PADDING, Math.min(window.innerWidth - MENU_WIDTH - PADDING, left));

      let top = rect.top - MENU_HEIGHT - GAP;
      let showBelow = false;
      if (top < PADDING) {
        top = rect.bottom + GAP;
        showBelow = true;
      }
      if (showBelow && top + MENU_HEIGHT > window.innerHeight - PADDING) {
        top = window.innerHeight - MENU_HEIGHT - PADDING;
      }

      setMenu({ left, top, showBelow, text });
      setSubmenu(null);
      setEnrichResult(null);
      setAiResult(null);
    }, 10);
  }, [containerRef]);

  useEffect(() => {
    document.addEventListener("mouseup", handleMouseUp);
    return () => document.removeEventListener("mouseup", handleMouseUp);
  }, [handleMouseUp]);

  useEffect(() => {
    if (!menu) return;
    const handleKey = (e: KeyboardEvent) => { if (e.key === "Escape") dismiss(); };
    const handleMouseDown = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) dismiss();
    };
    document.addEventListener("keydown", handleKey);
    document.addEventListener("mousedown", handleMouseDown);
    return () => {
      document.removeEventListener("keydown", handleKey);
      document.removeEventListener("mousedown", handleMouseDown);
    };
  }, [menu, dismiss]);

  if (!menu) return null;

  const preview = menu.text.length > 50 ? menu.text.slice(0, 50) + "…" : menu.text;
  const enabledSources = enrichSources?.filter((s) => s.is_enabled) ?? [];
  const pivotLinks = getPivotLinks("", menu.text);

  const handleCreateEntity = () => {
    onCreateEntity(menu.text);
    dismiss();
  };

  const handleAddAlias = () => {
    onAddAlias(menu.text);
    dismiss();
  };

  const handleLinkEntity = () => {
    onLinkEntity?.(menu.text);
    dismiss();
  };

  const handleRunAITask = async (taskName: string) => {
    setAiResult("Running…");
    setSubmenu(null);
    try {
      const res = await runAIOnText.mutateAsync({ taskName, text: menu.text });
      const resultStr = typeof res.result === "string"
        ? res.result
        : JSON.stringify(res.result, null, 2);
      setAiResult(resultStr);
    } catch {
      setAiResult("Failed — check that this task has an AI provider assigned.");
    }
  };

  const handleEnrichSource = async (sourceType: string) => {
    setEnrichResult("Enriching…");
    setSubmenu(null);
    try {
      const res = await enrichValue.mutateAsync({
        value: menu.text,
        sourceTypes: [sourceType],
        entryId,
      });
      const r = res.results[0];
      if (r?.status === "success" && r.parsed_data) {
        setEnrichResult(JSON.stringify(r.parsed_data, null, 2));
      } else if (r?.error) {
        setEnrichResult(`Error: ${r.error}`);
      } else {
        setEnrichResult(`Status: ${r?.status ?? "unknown"}`);
      }
    } catch {
      setEnrichResult("Enrichment failed. Check API key configuration.");
    }
  };

  const handleCreateSavedSearch = async () => {
    try {
      await createSavedSearch.mutateAsync({ name: menu.text, query: menu.text });
    } catch {
      // silently fail — user can create from search panel if needed
    }
    dismiss();
  };

  const handleRunSearch = () => {
    setHeaderSearchQuery(menu.text);
    navigate("/search");
    dismiss();
  };

  const handleGoogleSearch = () => {
    window.open(`https://www.google.com/search?q=${encodeURIComponent(menu.text)}`, "_blank", "noopener,noreferrer");
    dismiss();
  };

  const handleOpenInChat = () => {
    const params = new URLSearchParams({ message: menu.text });
    if (entryId) params.set("entry", entryId);
    navigate(`/chat?${params.toString()}`);
    dismiss();
  };

  const handleCreateNote = () => {
    onCreateNote(menu.text);
    dismiss();
  };

  const toggleSubmenu = (s: Submenu) => setSubmenu((v) => (v === s ? null : s));

  // Portal to <body>: the menu is `position: fixed` positioned from viewport
  // coordinates, but in the AI summary it renders inside the virtualized entry
  // list whose rows carry `transform: translateY(...)`. A transformed ancestor
  // makes `fixed` resolve against that ancestor, so the menu ends up clipped /
  // hidden. Escaping to <body> restores true viewport positioning (and is a
  // no-op in the non-transformed reader).
  return createPortal(
    <div
      ref={menuRef}
      className={`${styles.menu} ${menu.showBelow ? styles.menuBelow : styles.menuAbove}`}
      style={{ left: menu.left, top: menu.top }}
      onMouseDown={(e) => e.stopPropagation()}
    >
      <div className={styles.preview}>&ldquo;{preview}&rdquo;</div>

      {/* Inline result display */}
      {(aiResult || enrichResult) && (
        <div className={styles.result}>
          <pre className={styles.resultPre}>{aiResult ?? enrichResult}</pre>
          <button className={styles.resultClose} onClick={() => { setAiResult(null); setEnrichResult(null); }}>
            &#x2715;
          </button>
        </div>
      )}

      {!aiResult && !enrichResult && (
        <>
          <button className={styles.item} onClick={handleCreateEntity}>
            <span className={styles.icon}>&#x2B;</span>
            Create entity
          </button>

          <button className={styles.item} onClick={handleAddAlias}>
            <span className={styles.icon}>&#x29BF;</span>
            Add alias to profile
          </button>

          {onLinkEntity && (
            <button className={styles.item} onClick={handleLinkEntity}>
              <span className={styles.icon}>&#x21CC;</span>
              Link to entity
            </button>
          )}

          {/* AI Task submenu */}
          <button
            className={`${styles.item} ${submenu === "ai_task" ? styles.itemActive : ""}`}
            onClick={() => toggleSubmenu("ai_task")}
          >
            <span className={styles.icon}>&#x2605;</span>
            Run AI task
            <span className={`${styles.chevron} ${submenu === "ai_task" ? styles.chevronOpen : ""}`}>&#x25BE;</span>
          </button>

          {submenu === "ai_task" && (
            <div className={styles.submenu}>
              {!aiTasks || aiTasks.length === 0 ? (
                <div className={styles.submenuEmpty}>No tasks configured</div>
              ) : (
                aiTasks.map((task) => (
                  <button
                    key={task.id}
                    className={styles.submenuBtn}
                    onClick={() => handleRunAITask(task.name)}
                    disabled={runAIOnText.isPending}
                    title={task.description || task.display_name}
                  >
                    <span className={styles.submenuDot} />
                    {task.display_name}
                  </button>
                ))
              )}
            </div>
          )}

          {/* Enrich submenu */}
          <button
            className={`${styles.item} ${submenu === "enrich" ? styles.itemActive : ""}`}
            onClick={() => toggleSubmenu("enrich")}
          >
            <span className={styles.icon}>&#x2316;</span>
            Enrich
            <span className={`${styles.chevron} ${submenu === "enrich" ? styles.chevronOpen : ""}`}>&#x25BE;</span>
          </button>

          {submenu === "enrich" && (
            <div className={styles.submenu}>
              {enabledSources.length === 0 ? (
                <div className={styles.submenuEmpty}>No enrichment sources enabled</div>
              ) : (
                <>
                  {enabledSources.map((src) => (
                    <button
                      key={src.id}
                      className={styles.submenuBtn}
                      onClick={() => handleEnrichSource(src.source_type)}
                      disabled={enrichValue.isPending}
                    >
                      <span className={styles.submenuDot} />
                      {src.display_name}
                    </button>
                  ))}
                </>
              )}
            </div>
          )}

          {/* Pivot to submenu */}
          <button
            className={`${styles.item} ${submenu === "pivot" ? styles.itemActive : ""}`}
            onClick={() => toggleSubmenu("pivot")}
          >
            <span className={styles.icon}>&#x21D7;</span>
            Pivot to
            <span className={`${styles.chevron} ${submenu === "pivot" ? styles.chevronOpen : ""}`}>&#x25BE;</span>
          </button>

          {submenu === "pivot" && (
            <div className={styles.submenu}>
              {pivotLinks.map((link) => (
                <a
                  key={link.platform}
                  className={styles.submenuItem}
                  href={link.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={dismiss}
                >
                  <span className={styles.submenuDot} />
                  {link.platform}
                  <span className={styles.extIcon}>&#x2197;</span>
                </a>
              ))}
              {pivotLinks.length > 0 && <div className={styles.submenuDivider} />}
              <a
                className={styles.submenuItem}
                href={`https://github.com/search?q=${encodeURIComponent(menu.text)}&type=code`}
                target="_blank"
                rel="noopener noreferrer"
                onClick={dismiss}
              >
                <span className={styles.submenuDot} />
                GitHub
                <span className={styles.extIcon}>&#x2197;</span>
              </a>
              <a
                className={styles.submenuItem}
                href={`https://duckduckgo.com/?q=${encodeURIComponent(menu.text)}`}
                target="_blank"
                rel="noopener noreferrer"
                onClick={dismiss}
              >
                <span className={styles.submenuDot} />
                DuckDuckGo
                <span className={styles.extIcon}>&#x2197;</span>
              </a>
            </div>
          )}

          <button className={styles.item} onClick={handleGoogleSearch}>
            <span className={styles.icon}>G</span>
            Google search
          </button>

          <button className={styles.item} onClick={handleOpenInChat}>
            <span className={styles.icon}>&#x25B6;</span>
            Open in chat
          </button>

          <button className={styles.item} onClick={handleRunSearch}>
            <span className={styles.icon}>&#x2315;</span>
            Run search
          </button>

          <button
            className={styles.item}
            onClick={handleCreateSavedSearch}
            disabled={createSavedSearch.isPending}
          >
            <span className={styles.icon}>&#x2665;</span>
            Save search
          </button>

          <button className={styles.item} onClick={handleCreateNote}>
            <span className={styles.icon}>&#x270E;</span>
            Create note
          </button>
        </>
      )}
    </div>,
    document.body,
  );
}
