import { useMemo, useState } from "react";
import { toast } from "sonner";
import {
  useTags,
  useCreateTag,
  useUpdateTag,
  useDeleteTag,
  useMergeTags,
} from "@/hooks/useTags";
import { AxiosError } from "axios";
import styles from "./TagManager.module.css";
import { AsyncStateLoading } from "@/components/AsyncState";
import { useOpenSavedSearch } from "@/hooks/useOpenSavedSearch";

const PALETTE = [
  "#6b7280", "#f85149", "#f78166", "#d29922", "#3fb950",
  "#58a6ff", "#a855f7", "#ec4899", "#14b8a6", "#eab308",
];

function errMessage(e: unknown, fallback: string): string {
  if (e instanceof AxiosError) {
    return e.response?.data?.message || e.response?.data?.detail || fallback;
  }
  return fallback;
}

export function TagManager() {
  const { data: tags = [], isLoading } = useTags();
  const createTag = useCreateTag();
  const updateTag = useUpdateTag();
  const deleteTag = useDeleteTag();
  const mergeTags = useMergeTags();
  const openSavedSearch = useOpenSavedSearch();

  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<"count" | "name">("count");
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameVal, setRenameVal] = useState("");
  const [recolorId, setRecolorId] = useState<string | null>(null);
  const [describingId, setDescribingId] = useState<string | null>(null);
  const [describeVal, setDescribeVal] = useState("");
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  const [showNew, setShowNew] = useState(false);
  const [newName, setNewName] = useState("");
  const [newColor, setNewColor] = useState(PALETTE[0]);
  const [newChip, setNewChip] = useState(false);

  const [merging, setMerging] = useState(false);
  const [mergeTarget, setMergeTarget] = useState<string>("");
  const [confirmBulkDelete, setConfirmBulkDelete] = useState(false);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = tags.filter((t) => t.name.toLowerCase().includes(q));
    return [...list].sort((a, b) =>
      sort === "count" ? b.entry_count - a.entry_count : a.name.localeCompare(b.name),
    );
  }, [tags, query, sort]);

  const maxCount = Math.max(1, ...tags.map((t) => t.entry_count));
  const selectedTags = tags.filter((t) => selected.has(t.id));

  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  const clearSelection = () => {
    setSelected(new Set());
    setMerging(false);
    setConfirmBulkDelete(false);
  };

  const startRename = (id: string, current: string) => {
    setRecolorId(null);
    setConfirmDeleteId(null);
    setRenamingId(id);
    setRenameVal(current);
  };

  const saveRename = (id: string) => {
    const name = renameVal.trim();
    setRenamingId(null);
    if (!name) return;
    const current = tags.find((t) => t.id === id);
    if (!current || current.name === name) return;
    updateTag.mutate(
      { tagId: id, data: { name } },
      {
        onSuccess: () => toast.success(`Renamed to "${name}"`),
        onError: (e) => toast.error(errMessage(e, "Couldn't rename tag")),
      },
    );
  };

  const toggleChip = (id: string, name: string, chip: boolean) => {
    updateTag.mutate(
      { tagId: id, data: { display_as_chip: chip } },
      {
        onSuccess: () =>
          toast.success(chip ? `"${name}" now shows as a chip` : `"${name}" is a plain tag again`),
        onError: (e) => toast.error(errMessage(e, "Couldn't update tag")),
      },
    );
  };

  const startDescribe = (id: string, current: string | null) => {
    setRenamingId(null);
    setRecolorId(null);
    setConfirmDeleteId(null);
    setDescribingId(id);
    setDescribeVal(current ?? "");
  };

  const saveDescribe = (id: string) => {
    const description = describeVal.trim();
    setDescribingId(null);
    const current = tags.find((t) => t.id === id);
    if (!current || (current.description ?? "") === description) return;
    // An empty string clears the tooltip server-side.
    updateTag.mutate(
      { tagId: id, data: { description } },
      { onError: (e) => toast.error(errMessage(e, "Couldn't save tooltip")) },
    );
  };

  const recolor = (id: string, color: string) => {
    setRecolorId(null);
    updateTag.mutate({ tagId: id, data: { color } });
  };

  const doDelete = (id: string, name: string) => {
    setConfirmDeleteId(null);
    deleteTag.mutate(id, {
      onSuccess: () => {
        toast.success(`Deleted "${name}"`);
        setSelected((prev) => {
          const next = new Set(prev);
          next.delete(id);
          return next;
        });
      },
      onError: (e) => toast.error(errMessage(e, "Couldn't delete tag")),
    });
  };

  const doCreate = async () => {
    const name = newName.trim();
    if (!name) return;
    try {
      await createTag.mutateAsync({ name, color: newColor, display_as_chip: newChip });
      toast.success(`Created "${name}"`);
      setNewName("");
      setNewColor(PALETTE[0]);
      setNewChip(false);
      setShowNew(false);
    } catch (e) {
      toast.error(errMessage(e, "Couldn't create tag"));
    }
  };

  const doMerge = () => {
    if (!mergeTarget) return;
    const sourceIds = selectedTags.map((t) => t.id).filter((id) => id !== mergeTarget);
    if (!sourceIds.length) return;
    const targetName = tags.find((t) => t.id === mergeTarget)?.name ?? "tag";
    mergeTags.mutate(
      { sourceIds, targetId: mergeTarget },
      {
        onSuccess: () => {
          toast.success(`Merged ${sourceIds.length} tag${sourceIds.length > 1 ? "s" : ""} into "${targetName}"`);
          clearSelection();
        },
        onError: (e) => toast.error(errMessage(e, "Couldn't merge tags")),
      },
    );
  };

  const doBulkDelete = () => {
    const ids = [...selected];
    ids.forEach((id) => {
      const name = tags.find((t) => t.id === id)?.name ?? "";
      deleteTag.mutate(id, {
        onError: (e) => toast.error(errMessage(e, `Couldn't delete "${name}"`)),
      });
    });
    toast.success(`Deleting ${ids.length} tag${ids.length > 1 ? "s" : ""}`);
    clearSelection();
  };

  const viewTag = (name: string) => {
    openSavedSearch({
      id: `tag-${name}`,
      name: `tag:${name}`,
      display_name: null,
      query: "",
      filters: { tags: [name] },
      unread_count: 0,
      total_count: 0,
      created_at: new Date().toISOString(),
    });
  };

  return (
    <div className={styles.card}>
      <div className={styles.cardTitle}>
        <span>All tags</span>
        <span className={styles.tally}>
          {tags.length} tag{tags.length !== 1 ? "s" : ""}
        </span>
      </div>

      <div className={styles.toolbar}>
        <div className={styles.search}>
          <span className={styles.searchIcon}>⌕</span>
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter tags…"
            spellCheck={false}
          />
        </div>
        <button
          className={styles.btn}
          onClick={() => setSort((s) => (s === "count" ? "name" : "count"))}
        >
          Sort: {sort === "count" ? "count" : "name"}
        </button>
        <button className={`${styles.btn} ${styles.primary}`} onClick={() => setShowNew((v) => !v)}>
          + New tag
        </button>
      </div>

      {showNew && (
        <div className={styles.newRow}>
          <div className={styles.swatchPicker}>
            {PALETTE.map((c) => (
              <button
                key={c}
                className={`${styles.sw} ${newColor === c ? styles.swSel : ""}`}
                style={{ background: c }}
                onClick={() => setNewColor(c)}
                aria-label={`color ${c}`}
              />
            ))}
          </div>
          <input
            className={styles.newInput}
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") doCreate();
              if (e.key === "Escape") setShowNew(false);
            }}
            placeholder="New tag name…"
            autoFocus
            spellCheck={false}
          />
          <label className={styles.chipToggle} title="Show in the entry's badge row instead of the meta line">
            <input type="checkbox" checked={newChip} onChange={(e) => setNewChip(e.target.checked)} />
            Chip
          </label>
          <button className={`${styles.btn} ${styles.primary}`} onClick={doCreate} disabled={!newName.trim()}>
            Create
          </button>
          <button className={styles.btn} onClick={() => setShowNew(false)}>Cancel</button>
        </div>
      )}

      {selected.size > 0 && (
        <div className={styles.bulkBar}>
          <span className={styles.bulkN}>{selected.size} selected</span>
          <button className={styles.linkBtn} onClick={clearSelection}>Clear</button>
          <span className={styles.spacer} />
          {selected.size >= 2 && !merging && (
            <button
              className={styles.btn}
              onClick={() => {
                setMerging(true);
                setMergeTarget(selectedTags[0]?.id ?? "");
              }}
            >
              Merge…
            </button>
          )}
          {!confirmBulkDelete ? (
            <button className={`${styles.btn} ${styles.danger}`} onClick={() => setConfirmBulkDelete(true)}>
              Delete
            </button>
          ) : (
            <>
              <span className={styles.confirmText}>Delete {selected.size}?</span>
              <button className={`${styles.btn} ${styles.danger}`} onClick={doBulkDelete}>Confirm</button>
              <button className={styles.btn} onClick={() => setConfirmBulkDelete(false)}>Cancel</button>
            </>
          )}
        </div>
      )}

      {merging && (
        <div className={styles.mergePanel}>
          <span className={styles.mergeLabel}>Merge {selected.size} tags into</span>
          <select
            className={styles.mergeSelect}
            value={mergeTarget}
            onChange={(e) => setMergeTarget(e.target.value)}
          >
            {selectedTags.map((t) => (
              <option key={t.id} value={t.id}>{t.name}</option>
            ))}
          </select>
          <button className={`${styles.btn} ${styles.primary}`} onClick={doMerge} disabled={mergeTags.isPending}>
            {mergeTags.isPending ? "Merging…" : "Merge"}
          </button>
          <button className={styles.btn} onClick={() => setMerging(false)}>Cancel</button>
          <span className={styles.mergeNote}>
            Re-tags all their articles and deletes the others.
          </span>
        </div>
      )}

      {isLoading ? (
        <AsyncStateLoading label="Loading tags…" compact />
      ) : filtered.length === 0 ? (
        <div className={styles.empty}>{query ? "No tags match." : "No tags yet."}</div>
      ) : (
        <div className={styles.table}>
          <div className={`${styles.row} ${styles.head}`}>
            <span />
            <span>Tag</span>
            <span>Articles</span>
            <span className={styles.actionsCol}>Actions</span>
          </div>

          {filtered.map((t) => {
            const isSel = selected.has(t.id);
            return (
              <div key={t.id} className={`${styles.row} ${isSel ? styles.rowSel : ""}`}>
                <button
                  className={`${styles.cbx} ${isSel ? styles.cbxOn : ""}`}
                  onClick={() => toggle(t.id)}
                  aria-label={isSel ? "deselect" : "select"}
                >
                  {isSel ? "✓" : ""}
                </button>

                <div className={styles.tagCell}>
                  <div className={styles.swatchWrap}>
                    <button
                      className={styles.swatch}
                      style={{ background: t.color }}
                      onClick={() => setRecolorId(recolorId === t.id ? null : t.id)}
                      title="Recolor"
                    />
                    {recolorId === t.id && (
                      <div className={styles.colorPop}>
                        {PALETTE.map((c) => (
                          <button
                            key={c}
                            className={`${styles.sw} ${t.color.toLowerCase() === c ? styles.swSel : ""}`}
                            style={{ background: c }}
                            onClick={() => recolor(t.id, c)}
                            aria-label={`color ${c}`}
                          />
                        ))}
                      </div>
                    )}
                  </div>

                  {renamingId === t.id ? (
                    <input
                      className={styles.renameInput}
                      value={renameVal}
                      onChange={(e) => setRenameVal(e.target.value)}
                      onBlur={() => saveRename(t.id)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") saveRename(t.id);
                        if (e.key === "Escape") setRenamingId(null);
                      }}
                      autoFocus
                      spellCheck={false}
                    />
                  ) : (
                    <button className={styles.tagName} onClick={() => startRename(t.id, t.name)} title="Rename">
                      {t.name}
                    </button>
                  )}
                  {t.display_as_chip && <span className={styles.chipMark}>chip</span>}
                  {describingId === t.id ? (
                    <input
                      className={styles.renameInput}
                      value={describeVal}
                      maxLength={255}
                      placeholder="Tooltip shown on the chip…"
                      onChange={(e) => setDescribeVal(e.target.value)}
                      onBlur={() => saveDescribe(t.id)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") saveDescribe(t.id);
                        if (e.key === "Escape") setDescribingId(null);
                      }}
                      autoFocus
                    />
                  ) : (
                    t.description && (
                      <span className={styles.tagDescription} title={t.description}>
                        {t.description}
                      </span>
                    )
                  )}
                </div>

                <span className={styles.count}>
                  <span
                    className={styles.bar}
                    style={{ width: `${Math.round((t.entry_count / maxCount) * 60)}px` }}
                  />
                  {t.entry_count.toLocaleString()}
                </span>

                <div className={styles.rowActions}>
                  {confirmDeleteId === t.id ? (
                    <>
                      <span className={styles.confirmText}>Delete?</span>
                      <button className={`${styles.ract} ${styles.del}`} onClick={() => doDelete(t.id, t.name)}>Confirm</button>
                      <button className={styles.ract} onClick={() => setConfirmDeleteId(null)}>Cancel</button>
                    </>
                  ) : (
                    <>
                      <button className={styles.ract} onClick={() => viewTag(t.name)} disabled={t.entry_count === 0}>View</button>
                      <button
                        className={styles.ract}
                        onClick={() => toggleChip(t.id, t.name, !t.display_as_chip)}
                        aria-pressed={t.display_as_chip}
                        title={t.display_as_chip ? "Show as a plain tag in the meta line" : "Show as a chip in the entry's badge row"}
                      >
                        {t.display_as_chip ? "Unchip" : "Chip"}
                      </button>
                      <button className={styles.ract} onClick={() => startDescribe(t.id, t.description)}>Tooltip</button>
                      <button className={styles.ract} onClick={() => startRename(t.id, t.name)}>Rename</button>
                      <button className={`${styles.ract} ${styles.del}`} onClick={() => setConfirmDeleteId(t.id)}>Delete</button>
                    </>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
