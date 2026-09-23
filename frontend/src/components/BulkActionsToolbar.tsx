import {
  memo,
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type CSSProperties,
} from "react";
import { createPortal } from "react-dom";
import { toast } from "sonner";
import { useBulkAction } from "@/hooks/useEntries";
import { useTags, useBulkTag, useBulkUntag } from "@/hooks/useTags";
import { useBulkExtract } from "@/hooks/useIntelligence";
import { useUIStore } from "@/stores/uiStore";
import { BulkSummaryModal } from "./BulkSummaryModal";
import api from "@/api/client";
import styles from "./BulkActionsToolbar.module.css";

interface BulkActionsToolbarProps {
  selectedIds: Set<string>;
  totalCount: number;
  onSelectAll: () => void;
  onClearSelection: () => void;
}

export const BulkActionsToolbar = memo(function BulkActionsToolbar({
  selectedIds,
  totalCount,
  onSelectAll,
  onClearSelection,
}: BulkActionsToolbarProps) {
  const bulkAction = useBulkAction();
  const bulkTag = useBulkTag();
  const bulkUntag = useBulkUntag();
  const bulkExtract = useBulkExtract();
  const { data: tags } = useTags();

  const [showTagDropdown, setShowTagDropdown] = useState(false);
  const [tagMode, setTagMode] = useState<"add" | "remove">("add");
  const [tagSearch, setTagSearch] = useState("");
  const [showExtractMenu, setShowExtractMenu] = useState(false);
  const [showSummary, setShowSummary] = useState(false);
  const tagRef = useRef<HTMLDivElement>(null);
  const extractRef = useRef<HTMLDivElement>(null);
  const tagPanelRef = useRef<HTMLDivElement>(null);
  const extractPanelRef = useRef<HTMLDivElement>(null);
  const tagSearchRef = useRef<HTMLInputElement>(null);
  const [tagPanelStyle, setTagPanelStyle] = useState<CSSProperties>({});
  const [extractPanelStyle, setExtractPanelStyle] = useState<CSSProperties>({});

  const count = selectedIds.size;
  const ids = Array.from(selectedIds);
  const allSelected = count === totalCount && totalCount > 0;
  const someSelected = count > 0 && count < totalCount;

  // Close dropdowns on outside click (panels are portaled, so check them too)
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      const target = e.target as Node;
      if (
        !tagRef.current?.contains(target) &&
        !tagPanelRef.current?.contains(target)
      ) {
        setShowTagDropdown(false);
      }
      if (
        !extractRef.current?.contains(target) &&
        !extractPanelRef.current?.contains(target)
      ) {
        setShowExtractMenu(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  // The toolbar is a horizontal scroll strip, so dropdown panels render in a
  // portal with fixed positioning pinned to their trigger button.
  useLayoutEffect(() => {
    if (!showTagDropdown && !showExtractMenu) return;
    const update = () => {
      const pin = (
        anchor: HTMLDivElement | null,
        set: (s: CSSProperties) => void
      ) => {
        if (!anchor) return;
        const rect = anchor.getBoundingClientRect();
        set({
          position: "fixed",
          top: rect.bottom + 4,
          right: Math.max(8, window.innerWidth - rect.right),
        });
      };
      if (showTagDropdown) pin(tagRef.current, setTagPanelStyle);
      if (showExtractMenu) pin(extractRef.current, setExtractPanelStyle);
    };
    update();
    window.addEventListener("resize", update);
    window.addEventListener("scroll", update, true);
    return () => {
      window.removeEventListener("resize", update);
      window.removeEventListener("scroll", update, true);
    };
  }, [showTagDropdown, showExtractMenu]);

  // Focus search when tag dropdown opens
  useEffect(() => {
    if (showTagDropdown) {
      setTimeout(() => tagSearchRef.current?.focus(), 50);
    } else {
      setTagSearch("");
    }
  }, [showTagDropdown]);

  const handleAction = useCallback(
    (action: string, label: string) => {
      bulkAction.mutate(
        { entry_ids: ids, action },
        {
          onSuccess: () => {
            toast.success(`${label} — ${count} entries`);
            onClearSelection();
          },
          onError: () => toast.error(`Failed to ${label.toLowerCase()}`),
        }
      );
    },
    [ids, count, bulkAction, onClearSelection]
  );

  const handleTag = useCallback(
    (tagId: string, tagName: string) => {
      const mutation = tagMode === "add" ? bulkTag : bulkUntag;
      mutation.mutate(
        { entryIds: ids, tagIds: [tagId] },
        {
          onSuccess: () => {
            toast.success(
              tagMode === "add"
                ? `Tagged ${count} entries with "${tagName}"`
                : `Removed "${tagName}" from ${count} entries`,
            );
            setShowTagDropdown(false);
          },
          onError: () =>
            toast.error(tagMode === "add" ? "Failed to tag entries" : "Failed to remove tag"),
        }
      );
    },
    [ids, count, bulkTag, bulkUntag, tagMode]
  );

  const handleExtract = useCallback(
    (extractTypes: string[], label: string) => {
      bulkExtract.mutate(
        { entry_ids: ids, extract_types: extractTypes, use_ai: false },
        {
          onSuccess: (data) => {
            toast.success(`${label} queued for ${data.entry_count} entries`);
            setShowExtractMenu(false);
          },
          onError: () => toast.error("Failed to start extraction"),
        }
      );
    },
    [ids, bulkExtract]
  );

  const handleExport = useCallback(async () => {
    try {
      const response = await api.post(
        "/export/bulk",
        { entry_ids: ids },
        { responseType: "blob" }
      );
      const blob = new Blob([response.data], { type: "application/zip" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "intelfeed-export.zip";
      a.click();
      URL.revokeObjectURL(url);
      toast.success(`Exported ${count} entries`);
    } catch {
      toast.error("Failed to export entries");
    }
  }, [ids, count]);

  const handleExportBundle = useCallback(async () => {
    try {
      const response = await api.post(
        "/export/research-bundle",
        { entry_ids: ids, name: `IntelFeed Research Bundle (${count} entries)` },
        { responseType: "blob" }
      );
      const blob = new Blob([response.data], { type: "application/zip" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "intelfeed-research-bundle.zip";
      a.click();
      URL.revokeObjectURL(url);
      toast.success(`Exported research bundle — ${count} entries`);
    } catch {
      toast.error("Failed to export research bundle");
    }
  }, [ids, count]);

  const handleReport = useCallback(() => {
    useUIStore.getState().openSendToReport({
      entryIds: ids,
      label: `${ids.length} selected articles`,
      wizardState: { sourceType: "entries", entryIds: ids },
    });
  }, [ids]);

  const filteredTags = (tags ?? []).filter((t) =>
    t.name.toLowerCase().includes(tagSearch.toLowerCase())
  );

  return (
    <div className={styles.toolbar}>
      <div className={styles.left}>
        <input
          type="checkbox"
          className={styles.selectAllCheckbox}
          checked={allSelected}
          ref={(el) => {
            if (el) el.indeterminate = someSelected;
          }}
          onChange={onSelectAll}
        />
        <span className={styles.selectedCount}>{count} selected</span>
      </div>

      <div className={styles.right}>
        {/* State actions */}
        <button
          className={styles.btn}
          onClick={() => handleAction("read", "Marked read")}
          title="Mark selected as read"
        >
          Mark Read
        </button>
        <button
          className={styles.btn}
          onClick={() => handleAction("unread", "Marked unread")}
          title="Mark selected as unread"
        >
          Mark Unread
        </button>
        <button
          className={styles.btn}
          onClick={() => handleAction("star", "Starred")}
          title="Star selected"
        >
          Star
        </button>
        <button
          className={styles.btn}
          onClick={() => handleAction("bookmark", "Bookmarked")}
          title="Bookmark selected"
        >
          Bookmark
        </button>

        <span className={styles.divider} />

        {/* Tag */}
        <div className={styles.tagDropdownWrapper} ref={tagRef}>
          <button
            className={`${styles.btn} ${styles.btnAccent}`}
            onClick={() => setShowTagDropdown((v) => !v)}
            title="Tag selected entries"
          >
            Tag
          </button>
          {showTagDropdown && createPortal(
            <div
              ref={tagPanelRef}
              className={styles.tagDropdown}
              style={tagPanelStyle}
            >
              <div className={styles.tagModeToggle}>
                <button
                  className={tagMode === "add" ? styles.tagModeActive : styles.tagModeBtn}
                  onClick={() => setTagMode("add")}
                >
                  Add
                </button>
                <button
                  className={tagMode === "remove" ? styles.tagModeActive : styles.tagModeBtn}
                  onClick={() => setTagMode("remove")}
                >
                  Remove
                </button>
              </div>
              <input
                ref={tagSearchRef}
                className={styles.tagSearchInput}
                placeholder={tagMode === "add" ? "Add tag…" : "Remove tag…"}
                value={tagSearch}
                onChange={(e) => setTagSearch(e.target.value)}
              />
              <div className={styles.tagList}>
                {filteredTags.length === 0 ? (
                  <div className={styles.tagEmpty}>
                    {tags?.length === 0
                      ? "No tags created yet"
                      : "No matching tags"}
                  </div>
                ) : (
                  filteredTags.map((tag) => (
                    <button
                      key={tag.id}
                      className={styles.tagItem}
                      onClick={() => handleTag(tag.id, tag.name)}
                    >
                      <span
                        className={styles.tagDot}
                        style={{ background: tag.color || "var(--text-muted)" }}
                      />
                      {tag.name}
                    </button>
                  ))
                )}
              </div>
            </div>,
            document.body,
          )}
        </div>

        {/* Extract Intelligence */}
        <div className={styles.tagDropdownWrapper} ref={extractRef}>
          <button
            className={`${styles.btn} ${styles.btnAccent}`}
            onClick={() => setShowExtractMenu((v) => !v)}
            title="Extract intelligence from selected entries"
          >
            Extract Intel
          </button>
          {showExtractMenu && createPortal(
            <div
              ref={extractPanelRef}
              className={styles.extractDropdown}
              style={extractPanelStyle}
            >
              <button
                className={styles.extractItem}
                onClick={() =>
                  handleExtract(
                    ["ttps", "cves", "actors", "malware"],
                    "Full extraction"
                  )
                }
              >
                Full Extraction
              </button>
              <button
                className={styles.extractItem}
                onClick={() => handleExtract(["ttps"], "TTP extraction")}
              >
                TTPs Only
              </button>
              <button
                className={styles.extractItem}
                onClick={() => handleExtract(["cves"], "CVE extraction")}
              >
                CVEs Only
              </button>
              <button
                className={styles.extractItem}
                onClick={() =>
                  handleExtract(["actors", "malware"], "Actor/Malware extraction")
                }
              >
                Actors & Malware
              </button>
            </div>,
            document.body,
          )}
        </div>

        <span className={styles.divider} />

        {/* Export, Summarize & Report */}
        <button
          className={styles.btn}
          onClick={handleExport}
          title="Export selected entries as markdown ZIP"
        >
          Export
        </button>
        <button
          className={styles.btn}
          onClick={handleExportBundle}
          title="Export a research bundle: entry markdown + entity appendix + IOC CSV + ATT&CK layer"
        >
          Export Bundle
        </button>
        <button
          className={`${styles.btn} ${styles.btnAccent}`}
          onClick={() => setShowSummary(true)}
          title="AI summarize selected entries"
        >
          Summarize
        </button>
        <button
          className={`${styles.btn} ${styles.btnAccent}`}
          onClick={() =>
            // Pin the selection in the global copilot (article contents are
            // injected server-side, capped) and let the analyst ask.
            useUIStore.getState().openCopilotWith({
              context: { entry_ids: ids, label: `${ids.length} selected articles` },
              lockContext: true,
            })
          }
          title="Ask the copilot about selected entries"
        >
          Ask Copilot
        </button>
        <button
          className={styles.btn}
          onClick={handleReport}
          title="Add selected entries to a report draft or start a new report"
        >
          Report
        </button>

        <span className={styles.divider} />

        {/* Danger + Cancel */}
        <button
          className={`${styles.btn} ${styles.btnDanger}`}
          onClick={() => handleAction("hide", "Hidden")}
          title="Hide selected entries"
        >
          Hide
        </button>
        <button
          className={styles.cancelBtn}
          onClick={onClearSelection}
          title="Clear selection (Esc)"
        >
          Cancel
        </button>
      </div>

      {showSummary && (
        <BulkSummaryModal
          entryIds={ids}
          onClose={() => setShowSummary(false)}
        />
      )}

    </div>
  );
});
