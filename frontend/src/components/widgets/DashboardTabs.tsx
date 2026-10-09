import { useEffect, useRef, useState } from "react";
import type { Dashboard } from "@/api/types";
import styles from "./DashboardTabs.module.css";
import { confirmDialog } from "@/utils/dialog";

interface Props {
  /** Board summaries, already ordered. Names have the storage prefix stripped. */
  boards: Array<Pick<Dashboard, "id" | "name">>;
  activeId: string | null;
  onSelect: (id: string) => void;
  onCreate: (name: string) => void;
  onRename: (id: string, name: string) => void;
  onDelete: (id: string) => void;
  /** Full board id list in the new order, after a drag lands. */
  onReorder: (ids: string[]) => void;
  /** Layout lock — while locked, tabs can't be renamed, reordered, or deleted. */
  locked?: boolean;
}

export default function DashboardTabs({
  boards,
  activeId,
  onSelect,
  onCreate,
  onRename,
  onDelete,
  onReorder,
  locked = false,
}: Props) {
  const [creating, setCreating] = useState(false);
  const [draftName, setDraftName] = useState("");
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameDraft, setRenameDraft] = useState("");
  const [dragId, setDragId] = useState<string | null>(null);
  const [dropId, setDropId] = useState<string | null>(null);
  const createRef = useRef<HTMLInputElement>(null);
  const renameRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (creating) createRef.current?.focus();
  }, [creating]);
  useEffect(() => {
    if (renamingId) renameRef.current?.select();
  }, [renamingId]);

  function submitCreate() {
    const name = draftName.trim();
    if (name) onCreate(name);
    setDraftName("");
    setCreating(false);
  }

  function submitRename() {
    if (!renamingId) return;
    const name = renameDraft.trim();
    if (name) onRename(renamingId, name);
    setRenamingId(null);
  }

  function startRename(id: string, name: string) {
    if (locked) return;
    setRenamingId(id);
    setRenameDraft(name);
  }

  function handleDrop(targetId: string) {
    if (!locked && dragId && dragId !== targetId) {
      const ids = boards.map((b) => b.id);
      const from = ids.indexOf(dragId);
      const to = ids.indexOf(targetId);
      ids.splice(from, 1);
      // Dragging rightward lands after the target; leftward lands before it.
      ids.splice(ids.indexOf(targetId) + (from < to ? 1 : 0), 0, dragId);
      onReorder(ids);
    }
    setDragId(null);
    setDropId(null);
  }

  /** Keyboard reorder — drag-and-drop alone is unreachable without a pointer. */
  function moveBy(id: string, delta: number) {
    if (locked) return;
    const ids = boards.map((b) => b.id);
    const from = ids.indexOf(id);
    const to = from + delta;
    if (from < 0 || to < 0 || to >= ids.length) return;
    ids.splice(to, 0, ids.splice(from, 1)[0]);
    onReorder(ids);
  }

  return (
    <div className={styles.row}>
      <div className={styles.tabs} role="tablist" aria-label="Dashboards">
        {boards.map((board) => {
          const active = board.id === activeId;
          if (renamingId === board.id && !locked) {
            return (
              <input
                key={board.id}
                ref={renameRef}
                className={styles.renameInput}
                value={renameDraft}
                onChange={(e) => setRenameDraft(e.target.value)}
                onBlur={submitRename}
                onKeyDown={(e) => {
                  if (e.key === "Enter") submitRename();
                  if (e.key === "Escape") setRenamingId(null);
                }}
              />
            );
          }
          return (
            <div
              key={board.id}
              className={`${styles.tab} ${active ? styles.tabActive : ""} ${
                dragId === board.id ? styles.tabDragging : ""
              } ${dropId === board.id && dragId !== board.id ? styles.tabDropTarget : ""}`}
              role="tab"
              aria-selected={active}
              tabIndex={0}
              draggable={!locked && boards.length > 1}
              onClick={() => onSelect(board.id)}
              onDoubleClick={() => startRename(board.id, board.name)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  onSelect(board.id);
                }
                if (e.key === "F2") {
                  e.preventDefault();
                  startRename(board.id, board.name);
                }
                // Alt+arrows reorder without a pointer.
                if (e.altKey && (e.key === "ArrowLeft" || e.key === "ArrowRight")) {
                  e.preventDefault();
                  moveBy(board.id, e.key === "ArrowLeft" ? -1 : 1);
                }
              }}
              onDragStart={(e) => {
                setDragId(board.id);
                e.dataTransfer.effectAllowed = "move";
                e.dataTransfer.setData("text/plain", board.id);
              }}
              onDragOver={(e) => {
                if (!dragId) return;
                e.preventDefault();
                e.dataTransfer.dropEffect = "move";
                setDropId(board.id);
              }}
              onDragLeave={() => {
                if (dropId === board.id) setDropId(null);
              }}
              onDrop={(e) => {
                e.preventDefault();
                handleDrop(board.id);
              }}
              onDragEnd={() => {
                setDragId(null);
                setDropId(null);
              }}
              title={
                locked
                  ? "Unlock the layout to rename, reorder, or delete"
                  : boards.length > 1
                    ? "Drag to reorder · double-click to rename"
                    : "Double-click to rename"
              }
            >
              <span className={styles.tabName}>{board.name}</span>
              {!locked && (
                <button
                  className={styles.tabAction}
                  title="Rename dashboard"
                  aria-label={`Rename ${board.name}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    startRename(board.id, board.name);
                  }}
                >
                  ✎
                </button>
              )}
              {!locked && boards.length > 1 && (
                <button
                  className={`${styles.tabAction} ${styles.tabDelete}`}
                  title="Delete dashboard"
                  aria-label={`Delete ${board.name}`}
                  onClick={async (e) => {
                    e.stopPropagation();
                    if (
                      await confirmDialog({
                        title: "Delete dashboard",
                        message: `Delete dashboard "${board.name}" and its widgets?`,
                        confirmLabel: "Delete",
                        destructive: true,
                      })
                    ) {
                      onDelete(board.id);
                    }
                  }}
                >
                  ×
                </button>
              )}
            </div>
          );
        })}
      </div>

      {creating ? (
        <input
          ref={createRef}
          className={styles.renameInput}
          placeholder="Name…"
          value={draftName}
          onChange={(e) => setDraftName(e.target.value)}
          onBlur={submitCreate}
          onKeyDown={(e) => {
            if (e.key === "Enter") submitCreate();
            if (e.key === "Escape") {
              setDraftName("");
              setCreating(false);
            }
          }}
        />
      ) : (
        <button className={styles.newTab} title="New dashboard" onClick={() => setCreating(true)}>
          +
        </button>
      )}
    </div>
  );
}
