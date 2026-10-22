import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";

import { EntityMergeIntoModal } from "@/components/EntityMergeIntoModal";
import {
  ALIAS_TYPES,
  CONVERTIBLE_TYPES,
  CONVERT_TARGETS,
  MERGEABLE_TYPES,
  NAMEABLE_TYPES,
  TYPE_LABELS,
  useConfirmExtraction,
  useConvertExtractionEntity,
  useDeleteExtractionEntities,
  useExtractionEntities,
  useExtractionStats,
  useInvalidateExtraction,
  useMergeExtractionEntities,
  useUpdateExtractionEntity,
  type ExtractionEntity,
  type ExtractionParams,
  type ExtractionType,
} from "@/hooks/useExtraction";

import styles from "./ExtractionTab.module.css";
import { confirmDialog, promptDialog } from "@/utils/dialog";

const ALL_TYPES: ExtractionType[] = ["threat_actor", "malware", "cve", "tool", "ttp", "observable"];
const WINDOWS: ExtractionParams["window"][] = ["24h", "7d", "30d", "all"];
const STATUSES: { key: "all" | "review" | "orphan" | "dupe" | "stale"; label: string }[] = [
  { key: "all", label: "All" },
  { key: "review", label: "Review" },
  { key: "orphan", label: "Orphans" },
  { key: "dupe", label: "Dupes" },
  { key: "stale", label: "Stale" },
];

const CONF_BAR: Record<string, { pct: number; cls: string }> = {
  high: { pct: 92, cls: styles.confHigh },
  medium: { pct: 60, cls: styles.confMed },
  low: { pct: 30, cls: styles.confLow },
};

const PAGE_SIZE = 50;
const EMPTY_ITEMS: ExtractionEntity[] = [];

export function ExtractionTab({
  initialStatus = "all",
  embedded = false,
}: {
  initialStatus?: "all" | "review" | "orphan" | "dupe" | "stale";
  /** Render inside the Engine console card: no stat tiles (the console's
   *  healthline + attention chips already carry them). */
  embedded?: boolean;
}) {
  const navigate = useNavigate();
  const [timeWindow, setTimeWindow] = useState<ExtractionParams["window"]>("7d");
  const [status, setStatus] = useState<"all" | "review" | "orphan" | "dupe" | "stale">(initialStatus);
  const [types, setTypes] = useState<Set<ExtractionType>>(new Set());
  const [searchInput, setSearchInput] = useState("");
  const [q, setQ] = useState("");
  const [sortBy, setSortBy] = useState<NonNullable<ExtractionParams["sort_by"]>>("created");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  // Debounce the search box.
  useEffect(() => {
    const h = setTimeout(() => {
      setQ(searchInput.trim());
      setOffset(0);
    }, 300);
    return () => clearTimeout(h);
  }, [searchInput]);

  // Chip selection narrows. No selection means every type is in play, which
  // the API expects as no filter at all.
  const effectiveTypes = useMemo(() => (types.size ? [...types] : undefined), [types]);

  const { data: stats } = useExtractionStats(timeWindow);
  const { data, isLoading, isFetching } = useExtractionEntities({
    types: effectiveTypes,
    status,
    window: timeWindow,
    q: q || undefined,
    sort_by: sortBy,
    sort_order: sortOrder,
    limit: PAGE_SIZE,
    offset,
  });

  const confirmMut = useConfirmExtraction();
  const deleteMut = useDeleteExtractionEntities();
  const mergeMut = useMergeExtractionEntities();
  const updateMut = useUpdateExtractionEntity();
  const convertMut = useConvertExtractionEntity();
  const invalidateExtraction = useInvalidateExtraction();

  // Row whose "Merge into…" modal is open (search + fold into any same-type entity).
  const [mergeRow, setMergeRow] = useState<ExtractionEntity | null>(null);

  const items = data?.items ?? EMPTY_ITEMS;
  const total = data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  const selectedItems = useMemo(() => items.filter((i) => selected.has(i.id)), [items, selected]);

  function resetTo(fn: () => void) {
    fn();
    setOffset(0);
    setSelected(new Set());
  }

  function toggleType(t: ExtractionType) {
    resetTo(() => {
      setTypes((prev) => {
        const next = new Set(prev);
        if (next.has(t)) next.delete(t);
        else next.add(t);
        return next;
      });
    });
  }

  function toggleSort(col: NonNullable<ExtractionParams["sort_by"]>) {
    if (sortBy === col) setSortOrder((o) => (o === "asc" ? "desc" : "asc"));
    else {
      setSortBy(col);
      setSortOrder("desc");
    }
    setOffset(0);
  }

  function toggleSelect(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleSelectAll() {
    setSelected((prev) => (prev.size === items.length && items.length > 0 ? new Set() : new Set(items.map((i) => i.id))));
  }

  function pivot(e: ExtractionEntity) {
    navigate(`/workbench/${e.entity_type}/${e.id}`);
  }

  async function doDelete(rows: ExtractionEntity[]) {
    if (!rows.length) return;
    // Ledger rows have no name to deny — they tombstone in place (or hard-
    // delete on request). Named entities delete + join the do-not-recreate
    // list. A mixed selection gets both sentences, not the wrong one.
    const obsRows = rows.filter((r) => r.entity_type === "observable");
    const entityRows = rows.filter((r) => r.entity_type !== "observable");
    const one = rows.length === 1 ? rows[0] : null;
    const parts: string[] = [];
    if (entityRows.length)
      parts.push(
        `${entityRows.length === 1 && one ? `"${one.name}" is deleted` : `${entityRows.length} entities are deleted`} ` +
          `with all links, and the name${entityRows.length === 1 ? " goes" : "s go"} on the do-not-recreate list. ` +
          `This cannot be undone.`,
      );
    // Observables: tombstone by default; hard-delete (re-capturable) behind a
    // second confirm so the choice actually reaches the wire.
    let denyObservables = true;
    if (obsRows.length) {
      parts.push(
        `${obsRows.length === 1 && rows.length === 1 ? `The ledger keeps "${obsRows[0].name}"` : `The ledger keeps ${obsRows.length} observable value${obsRows.length === 1 ? "" : "s"}`} ` +
          `as tombstone${obsRows.length === 1 ? "" : "s"}: every capture door and the outbound feeds refuse ` +
          `the value${obsRows.length === 1 ? "" : "s"} from now on; past sightings stay as history.`,
      );
    }
    const label = one ? `"${one.name}"` : `${rows.length} selected`;
    if (
      !(await confirmDialog({
        title: `Remove ${label}`,
        message: parts.join("\n\n"),
        confirmLabel: "Remove",
        destructive: true,
      }))
    )
      return;
    if (obsRows.length) {
      // Two outcomes rather than yes/no, which the native confirm could only
      // express by explaining what OK and Cancel meant. Labelled buttons say it.
      denyObservables = !(await confirmDialog({
        title: "Tombstone or hard-delete?",
        message:
          "Tombstoning keeps the rows and their sightings as history, and every capture door refuses the values from now on. " +
          "A hard delete removes the rows and sightings outright, leaving the values free to be captured again.",
        confirmLabel: "Hard-delete",
        cancelLabel: "Tombstone (recommended)",
        destructive: true,
      }));
    }
    // One call per type — the endpoint denies + deletes as a batch.
    const byType = new Map<ExtractionType, string[]>();
    for (const r of rows) byType.set(r.entity_type, [...(byType.get(r.entity_type) ?? []), r.id]);
    let ok = 0;
    let failed = 0;
    for (const [entityType, ids] of byType) {
      try {
        const res = await deleteMut.mutateAsync({
          entityType,
          ids,
          deny: entityType === "observable" ? denyObservables : undefined,
        });
        ok += res.deleted;
      } catch {
        failed += ids.length;
      }
    }
    const bits: string[] = [];
    if (entityRows.length) bits.push(`${entityRows.length} entit${entityRows.length === 1 ? "y" : "ies"} deleted + denylisted`);
    if (obsRows.length) bits.push(`${obsRows.length} observable${obsRows.length === 1 ? "" : "s"} ${denyObservables ? "tombstoned" : "hard-deleted"}`);
    if (failed) toast.warning(`${bits.join(", ")} — ${failed} failed`);
    else if (ok) toast.success(bits.join(", "));
    else toast.error("Nothing was removed");
    setSelected(new Set());
  }

  async function doConfirm(rows: ExtractionEntity[]) {
    const byType = new Map<ExtractionType, string[]>();
    for (const r of rows.filter((r) => r.needs_review)) {
      byType.set(r.entity_type, [...(byType.get(r.entity_type) ?? []), r.id]);
    }
    if (!byType.size) return;
    let n = 0;
    for (const [entityType, ids] of byType) {
      const res = await confirmMut.mutateAsync({ entityType, ids });
      n += res.confirmed;
    }
    toast.success(`Confirmed ${n} entit${n === 1 ? "y" : "ies"}`);
    setSelected(new Set());
  }

  const mergeReady =
    selectedItems.length >= 2 &&
    selectedItems.every((i) => i.entity_type === selectedItems[0].entity_type) &&
    MERGEABLE_TYPES.has(selectedItems[0].entity_type);

  async function doMerge() {
    if (!mergeReady) return;
    const entityType = selectedItems[0].entity_type;
    // Keep the row with the most linked entries; merge the rest into it.
    const sorted = [...selectedItems].sort((a, b) => b.article_count - a.article_count);
    const keeper = sorted[0];
    const mergeIds = sorted.slice(1).map((i) => i.id);
    if (
      !(await confirmDialog({
        title: "Merge entities",
        message: `Merge ${mergeIds.length} into "${keeper.name}"? Aliases and entry links fold into the keeper.`,
        confirmLabel: "Merge",
        destructive: true,
      }))
    )
      return;
    await mergeMut.mutateAsync({ entityType, keeperId: keeper.id, mergeIds });
    toast.success(`Merged ${mergeIds.length} into "${keeper.name}"`);
    setSelected(new Set());
  }

  async function doRename(e: ExtractionEntity) {
    const next = await promptDialog({
      title: "Rename entity",
      message: `Rename "${e.name}" to:`,
      defaultValue: e.name,
      confirmLabel: "Rename",
    });
    if (!next || next === e.name) return;
    try {
      await updateMut.mutateAsync({ entityType: e.entity_type, id: e.id, name: next });
      toast.success(`Renamed to "${next}"`);
    } catch (err) {
      toast.error(errMsg(err, "Rename failed"));
    }
  }

  async function doAddAlias(e: ExtractionEntity) {
    const alias = await promptDialog({
      title: "Add alias",
      message: `Add an alias to "${e.name}":`,
      confirmLabel: "Add alias",
    });
    if (!alias) return;
    const existing = e.aliases ?? [];
    if (existing.some((a) => a.toLowerCase() === alias.toLowerCase())) {
      toast.info(`"${alias}" is already an alias`);
      return;
    }
    try {
      await updateMut.mutateAsync({ entityType: e.entity_type, id: e.id, aliases: [...existing, alias] });
      toast.success(`Added alias "${alias}"`);
    } catch (err) {
      toast.error(errMsg(err, "Failed to add alias"));
    }
  }

  async function doConvert(e: ExtractionEntity, target: (typeof CONVERT_TARGETS)[number]) {
    let targetIdentifier: string | undefined;
    if (target.needsIdentifier) {
      const answer = await promptDialog({
        title: target.needsIdentifier === "cve" ? "CVE ID" : "ATT&CK technique ID",
        message:
          target.needsIdentifier === "cve"
            ? "Enter the CVE ID for the new record (e.g. CVE-2024-1234):"
            : "Enter the ATT&CK technique ID for the new record (e.g. T1059 or T1059.001):",
        placeholder: target.needsIdentifier === "cve" ? "CVE-2024-1234" : "T1059.001",
      });
      if (!answer) return;
      targetIdentifier = answer;
    }
    if (
      !(await confirmDialog({
        title: "Convert entity",
        message: `Convert "${e.name}" to ${target.label}? Entry links and relationships migrate to the new entity.`,
        confirmLabel: "Convert",
        destructive: true,
      }))
    )
      return;
    try {
      await convertMut.mutateAsync({ id: e.id, targetType: target.key, targetIdentifier });
      toast.success(`Converted to ${target.label}`);
      setSelected(new Set());
    } catch (err) {
      toast.error(errMsg(err, "Conversion failed"));
    }
  }

  const allSelected = items.length > 0 && selected.size === items.length;
  const delta = stats ? stats.created_window - stats.created_prev_window : 0;

  return (
    <div className={styles.wrap}>
      {/* stat tiles — standalone only */}
      {!embedded && (
      <div className={styles.stats}>
        <Stat label={`Created · ${timeWindow}`} value={stats?.created_window} accent="accent">
          {stats && timeWindow !== "all" && (
            <span className={delta >= 0 ? styles.up : styles.down}>
              {delta >= 0 ? "▲" : "▼"} {Math.abs(delta)} vs prior
            </span>
          )}
        </Stat>
        <Stat label="Needs review" value={stats?.needs_review} tone="warning">
          <span className={styles.mut}>unconfirmed by AI</span>
        </Stat>
        <Stat label="Orphaned" value={stats?.orphaned}>
          <span className={styles.mut}>0 linked entries</span>
        </Stat>
        <Stat label="Likely duplicates" value={stats?.likely_duplicates} tone="danger">
          <span className={styles.mut}>merge candidates</span>
        </Stat>
        <Stat label="Auto-confirmed" value={stats?.auto_confirmed} tone="success">
          <span className={styles.mut}>
            {stats && stats.total_created ? Math.round((stats.auto_confirmed / stats.total_created) * 100) : 0}% of created
          </span>
        </Stat>
      </div>
      )}

      {/* toolbar */}
      <div className={styles.toolbar}>
        <label className={styles.search}>
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6">
            <circle cx="7" cy="7" r="5" />
            <path d="M11 11l3.5 3.5" />
          </svg>
          <input
            placeholder="Search created entities, aliases…"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
        </label>

        <div className={styles.chips}>
          {ALL_TYPES.map((t) => (
            <button
              key={t}
              className={`${styles.chip} ${types.has(t) ? styles.chipOn : ""}`}
              onClick={() => toggleType(t)}
            >
              <span className={`${styles.sw} ${styles[`sw_${t}`]}`} />
              {TYPE_LABELS[t]}
              <span className={styles.cnt}>{stats?.by_type[t] ?? 0}</span>
            </button>
          ))}
        </div>

        <div className={styles.seg}>
          {STATUSES.map((s) => (
            <button
              key={s.key}
              className={status === s.key ? styles.segOn : ""}
              onClick={() => resetTo(() => setStatus(s.key))}
            >
              {s.label}
            </button>
          ))}
        </div>

        <div className={styles.seg}>
          {WINDOWS.map((w) => (
            <button key={w} className={timeWindow === w ? styles.segOn : ""} onClick={() => resetTo(() => setTimeWindow(w))}>
              {w === "all" ? "All" : w}
            </button>
          ))}
        </div>
      </div>

      {/* bulk bar */}
      {selected.size > 0 && (
        <div className={styles.bulkbar}>
          <span className={styles.bulkN}>{selected.size} selected</span>
          <span className={styles.grow} />
          <button
            className={styles.bulkbtn}
            disabled={!mergeReady || mergeMut.isPending}
            title={mergeReady ? "" : "Select 2+ of the same mergeable type (actor / malware / tool)"}
            onClick={doMerge}
          >
            Merge…
          </button>
          <button
            className={styles.bulkbtn}
            disabled={confirmMut.isPending || !selectedItems.some((i) => i.needs_review)}
            onClick={() => doConfirm(selectedItems)}
          >
            Confirm
          </button>
          <button className={`${styles.bulkbtn} ${styles.danger}`} disabled={deleteMut.isPending} onClick={() => doDelete(selectedItems)}>
            Delete
          </button>
        </div>
      )}

      {/* table */}
      <div className={styles.tablewrap}>
        <div className={styles.tscroll}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th className={styles.checkCol}>
                  <span
                    className={`${styles.cbox} ${allSelected ? styles.cboxOn : ""}`}
                    onClick={toggleSelectAll}
                    role="checkbox"
                    aria-checked={allSelected}
                  />
                </th>
                <SortTh label="Entity" col="name" sortBy={sortBy} sortOrder={sortOrder} onSort={toggleSort} />
                <th>Type</th>
                <SortTh label="Confidence" col="confidence" sortBy={sortBy} sortOrder={sortOrder} onSort={toggleSort} />
                <SortTh label="Entries" col="entries" sortBy={sortBy} sortOrder={sortOrder} onSort={toggleSort} />
                <th className={styles.hideSm}>First source</th>
                <SortTh label="Created" col="created" sortBy={sortBy} sortOrder={sortOrder} onSort={toggleSort} className={styles.hideSm} />
                <th>Status</th>
                <th className={styles.actionsCol}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((e) => (
                <tr key={e.id} className={selected.has(e.id) ? styles.selRow : ""}>
                  <td>
                    <span
                      className={`${styles.cbox} ${selected.has(e.id) ? styles.cboxOn : ""}`}
                      onClick={() => toggleSelect(e.id)}
                      role="checkbox"
                      aria-checked={selected.has(e.id)}
                    />
                  </td>
                  <td>
                    <div className={styles.ename}>
                      <button
                        className={`${styles.namelink} ${e.entity_type === "observable" ? styles.nameMono : ""}`}
                        onClick={() => pivot(e)}
                        title={e.name}
                      >
                        {e.name}
                      </button>
                      {e.duplicate_of && <span className={styles.provchip}>≈ {e.duplicate_of}</span>}
                    </div>
                    <div className={styles.aka}>
                      {e.entity_type === "observable"
                        ? // Backend packs [kind, label] into aliases for ledger
                          // rows — a qualifier, not an alias claim.
                          e.aliases.filter(Boolean).join(" · ")
                        : e.aliases.length
                          ? `aka ${e.aliases.slice(0, 3).join(", ")}`
                          : "no aliases"}
                    </div>
                  </td>
                  <td>
                    <span className={`${styles.etype} ${styles[`t_${e.entity_type}`]}`}>
                      <span className={styles.swatch} />
                      {TYPE_LABELS[e.entity_type]}
                    </span>
                  </td>
                  <td>
                    {e.created_confidence && CONF_BAR[e.created_confidence] ? (
                      <span className={styles.conf}>
                        <span className={styles.cbar}>
                          <span
                            className={CONF_BAR[e.created_confidence].cls}
                            style={{ width: `${CONF_BAR[e.created_confidence].pct}%` }}
                          />
                        </span>
                        <span className={styles.pct}>{e.created_confidence}</span>
                      </span>
                    ) : (
                      <span className={styles.mut}>—</span>
                    )}
                  </td>
                  <td className={styles.num}>{e.article_count}</td>
                  <td className={`${styles.hideSm} ${styles.mut} ${styles.sourceCell}`} title={e.source_entry_title ?? ""}>
                    {e.source_entry_title ?? "—"}
                  </td>
                  <td className={`${styles.hideSm} ${styles.when}`}>{relTime(e.first_seen_at)}</td>
                  <td>
                    <StatusPill status={e.status} duplicateOf={e.duplicate_of} />
                  </td>
                  <td>
                    <div className={styles.rowacts}>
                      <button className={styles.iact} title="Pivot to profile" onClick={() => pivot(e)}>
                        ↗
                      </button>
                      {e.needs_review && (
                        <button className={styles.iact} title="Confirm" onClick={() => doConfirm([e])}>
                          ✓
                        </button>
                      )}
                      <RowActionsMenu
                        entity={e}
                        onMergeInto={() => setMergeRow(e)}
                        onRename={() => doRename(e)}
                        onAddAlias={() => doAddAlias(e)}
                        onConvert={(target) => doConvert(e, target)}
                      />
                      <button
                        className={`${styles.iact} ${styles.iactDanger}`}
                        title={e.entity_type === "observable" ? "Deny — never capture this value again" : "Delete"}
                        onClick={() => doDelete([e])}
                      >
                        ✕
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {!isLoading && items.length === 0 && (
                <tr>
                  <td colSpan={9} className={styles.empty}>
                    No AI-created entities match these filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className={styles.tfoot}>
          <span>
            {total > 0 ? (
              <>
                Showing <b className={styles.num}>{offset + 1}–{Math.min(offset + PAGE_SIZE, total)}</b> of{" "}
                <b className={styles.num}>{total}</b> AI-created entities
                {isFetching && <span className={styles.mut}> · updating…</span>}
              </>
            ) : (
              "—"
            )}
          </span>
          {pageCount > 1 && (
            <div className={styles.pager}>
              <button disabled={currentPage === 1} onClick={() => setOffset(offset - PAGE_SIZE)}>
                ‹
              </button>
              <span className={styles.pageInfo}>
                {currentPage} / {pageCount}
              </span>
              <button disabled={currentPage === pageCount} onClick={() => setOffset(offset + PAGE_SIZE)}>
                ›
              </button>
            </div>
          )}
        </div>
      </div>

      {mergeRow && (
        <EntityMergeIntoModal
          entityType={mergeRow.entity_type}
          keeperId={mergeRow.id}
          keeperName={mergeRow.name}
          onClose={() => setMergeRow(null)}
          onMerged={() => {
            invalidateExtraction();
            setSelected(new Set());
            setMergeRow(null);
          }}
        />
      )}
    </div>
  );
}

function Stat({
  label,
  value,
  tone,
  accent,
  children,
}: {
  label: string;
  value: number | undefined;
  tone?: "warning" | "danger" | "success";
  accent?: "accent";
  children?: React.ReactNode;
}) {
  const toneCls = tone ? styles[`v_${tone}`] : accent ? styles.v_accent : "";
  return (
    <div className={styles.stat}>
      <div className={styles.statK}>{label}</div>
      <div className={`${styles.statV} ${toneCls}`}>{value ?? "—"}</div>
      <div className={styles.statD}>{children}</div>
    </div>
  );
}

function SortTh({
  label,
  col,
  sortBy,
  sortOrder,
  onSort,
  className,
}: {
  label: string;
  col: NonNullable<ExtractionParams["sort_by"]>;
  sortBy: string;
  sortOrder: "asc" | "desc";
  onSort: (c: NonNullable<ExtractionParams["sort_by"]>) => void;
  className?: string;
}) {
  const active = sortBy === col;
  return (
    <th className={`${styles.sortable} ${className ?? ""}`} onClick={() => onSort(col)}>
      {label}
      {active && <span className={styles.arr}>{sortOrder === "asc" ? "▲" : "▼"}</span>}
    </th>
  );
}

function StatusPill({ status, duplicateOf }: { status: ExtractionEntity["status"]; duplicateOf: string | null }) {
  const map = {
    linked: { cls: styles.stLinked, text: "Linked" },
    review: { cls: styles.stReview, text: "Needs review" },
    orphan: { cls: styles.stOrphan, text: "Orphan" },
    dupe: { cls: styles.stDupe, text: duplicateOf ? `Dup of ${duplicateOf}` : "Duplicate" },
    stale: { cls: styles.stOrphan, text: "Stale" },
  }[status];
  return <span className={`${styles.status} ${map.cls}`}>● {map.text}</span>;
}

function errMsg(err: unknown, fallback: string): string {
  const data = (err as { response?: { data?: { error?: { message?: string }; message?: string; detail?: string } } })
    ?.response?.data;
  return data?.error?.message || data?.message || data?.detail || fallback;
}

/**
 * RowActionsMenu — per-row "⋯" overflow that folds the entity-management
 * actions (merge into an existing entity, rename, add alias, convert type)
 * into the table so an analyst never has to leave the Extraction tab to fix a
 * dupe. Rendered as a fixed-position popover so it escapes the table's scroll
 * clipping. Actions are gated by what each entity type supports (CVE/TTP are
 * id-keyed: no rename/alias/merge, convert only).
 */
function RowActionsMenu({
  entity,
  onMergeInto,
  onRename,
  onAddAlias,
  onConvert,
}: {
  entity: ExtractionEntity;
  onMergeInto: () => void;
  onRename: () => void;
  onAddAlias: () => void;
  onConvert: (target: (typeof CONVERT_TARGETS)[number]) => void;
}) {
  const [open, setOpen] = useState(false);
  const [convertOpen, setConvertOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const btnRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const close = () => {
      setOpen(false);
      setConvertOpen(false);
    };
    const onDown = (e: MouseEvent) => {
      if (menuRef.current?.contains(e.target as Node) || btnRef.current?.contains(e.target as Node)) return;
      close();
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && close();
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    // Any scroll shifts the anchor — close rather than track.
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("resize", close);
    };
  }, [open]);

  function toggle() {
    if (!open && btnRef.current) {
      const r = btnRef.current.getBoundingClientRect();
      setPos({ top: r.bottom + 4, left: r.right });
    }
    setConvertOpen(false);
    setOpen((o) => !o);
  }

  const t = entity.entity_type;
  const canMerge = MERGEABLE_TYPES.has(t);
  const canRename = NAMEABLE_TYPES.has(t);
  const canAlias = ALIAS_TYPES.has(t);
  const canConvert = CONVERTIBLE_TYPES.has(t);
  const convertTargets = CONVERT_TARGETS.filter((x) => x.key !== t);
  // Observables support none of these — don't hang an empty popover off the row.
  if (!canMerge && !canRename && !canAlias && !canConvert) return null;

  function run(fn: () => void) {
    setOpen(false);
    setConvertOpen(false);
    fn();
  }

  return (
    <>
      <button ref={btnRef} className={styles.iact} title="Manage entity" onClick={toggle}>
        ⋯
      </button>
      {open && pos && (
        <div
          ref={menuRef}
          className={styles.rowmenu}
          style={{ top: pos.top, left: pos.left }}
          role="menu"
        >
          {canMerge && (
            <button className={styles.menuitem} onClick={() => run(onMergeInto)}>
              Merge into…
            </button>
          )}
          {canRename && (
            <button className={styles.menuitem} onClick={() => run(onRename)}>
              Rename…
            </button>
          )}
          {canAlias && (
            <button className={styles.menuitem} onClick={() => run(onAddAlias)}>
              Add alias…
            </button>
          )}
          {canConvert && (
            <button className={styles.menuitem} onClick={() => setConvertOpen((o) => !o)}>
              Convert type <span className="caret-glyph">{convertOpen ? "▾" : "▸"}</span>
            </button>
          )}
          {convertOpen && (
            <div className={styles.submenu}>
              {convertTargets.map((target) => (
                <button key={target.key} className={styles.menuitem} onClick={() => run(() => onConvert(target))}>
                  {target.label}
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </>
  );
}

function relTime(iso: string): string {
  const then = new Date(iso).getTime();
  const secs = Math.max(0, (Date.now() - then) / 1000);
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  const days = Math.floor(secs / 86400);
  if (days < 30) return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}
