import { Fragment, useEffect, useMemo, useRef, useState } from "react";
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
  useExtractionBulk,
  useExtractionEntities,
  useExtractionStats,
  useInvalidateExtraction,
  useMergeExtractionEntities,
  useNotDuplicate,
  useUpdateExtractionEntity,
  type ExtractionEntity,
  type ExtractionParams,
  type ExtractionType,
} from "@/hooks/useExtraction";

import { EntityEvidencePanel } from "./EvidencePanel";
import styles from "./ExtractionTab.module.css";
import { confirmDialog, promptDialog } from "@/utils/dialog";

const ALL_TYPES: ExtractionType[] = ["threat_actor", "malware", "cve", "tool", "ttp", "observable"];
type EntityStatus = "all" | "review" | "orphan" | "dupe";
export type ReviewEntityStatus = Exclude<EntityStatus, "all">;

/** Review › Entities: the status switch, in the order the lens shows them. */
const REVIEW_STATUSES: { value: ReviewEntityStatus; label: string }[] = [
  { value: "review", label: "Unconfirmed" },
  { value: "dupe", label: "Duplicates" },
  { value: "orphan", label: "Orphans" },
];

const PAGE_SIZE = 50;
const EMPTY_ITEMS: ExtractionEntity[] = [];

export function ExtractionTab({
  status = "all",
  window: timeWindow,
  statusSwitch,
}: {
  /** One status only (Review's Entities lens); Entities lists them all. */
  status?: EntityStatus;
  /** The console's time picker: entities first seen in this window. */
  window: NonNullable<ExtractionParams["window"]>;
  /** Review's Entities lens: the Unconfirmed / Duplicates / Orphans switch, with its counts. */
  statusSwitch?: {
    onChange: (s: ReviewEntityStatus) => void;
    counts: Partial<Record<ReviewEntityStatus, number>>;
  };
}) {
  const navigate = useNavigate();
  const [entityType, setEntityType] = useState<ExtractionType | "">("");
  const [searchInput, setSearchInput] = useState("");
  const [q, setQ] = useState("");
  const [sortBy, setSortBy] = useState<NonNullable<ExtractionParams["sort_by"]>>("created");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  // A new console window starts at the first page.
  useEffect(() => {
    setOffset(0);
    setSelected(new Set());
  }, [timeWindow]);

  // Debounce the search box.
  useEffect(() => {
    const h = setTimeout(() => {
      setQ(searchInput.trim());
      setOffset(0);
    }, 300);
    return () => clearTimeout(h);
  }, [searchInput]);

  // No type picked means every type is in play, which the API expects as no filter at all.
  const effectiveTypes = useMemo(() => (entityType ? [entityType] : undefined), [entityType]);

  const { data: stats } = useExtractionStats(timeWindow, status === "all");
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
  const notDupMut = useNotDuplicate();
  const updateMut = useUpdateExtractionEntity();
  const convertMut = useConvertExtractionEntity();
  const bulkMut = useExtractionBulk();
  const invalidateExtraction = useInvalidateExtraction();

  // Row whose "Merge into…" modal is open (search + fold into any same-type entity).
  const [mergeRow, setMergeRow] = useState<ExtractionEntity | null>(null);
  const [openEvidence, setOpenEvidence] = useState<string | null>(null);

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
        `${obsRows.length === 1 && rows.length === 1 ? `The observables list keeps "${obsRows[0].name}"` : `The observables list keeps ${obsRows.length} observable value${obsRows.length === 1 ? "" : "s"}`} ` +
          `as tombstone${obsRows.length === 1 ? "" : "s"}. The value${obsRows.length === 1 ? " is" : "s are"} not captured ` +
          `or published again. Past sightings stay as history.`,
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
          "Tombstoning keeps the rows and their sightings as history, and the values are never captured again. " +
          "A hard delete removes the rows and sightings, and the values can be captured again.",
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
    if (failed) toast.warning(`${bits.join(", ")}, ${failed} failed`);
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

  async function doMergeIntoSibling(e: ExtractionEntity) {
    if (!e.duplicate_of_id) return;
    if (
      !(await confirmDialog({
        title: "Merge duplicate",
        message: `Merge "${e.name}" into "${e.duplicate_of}"? Its aliases and article links move to "${e.duplicate_of}".`,
        confirmLabel: "Merge",
      }))
    )
      return;
    try {
      await mergeMut.mutateAsync({ entityType: e.entity_type, keeperId: e.duplicate_of_id, mergeIds: [e.id] });
      toast.success(`Merged "${e.name}" into "${e.duplicate_of}"`);
    } catch (err) {
      toast.error(`Merge failed: ${(err as Error).message}`);
    }
  }

  async function doNotDuplicate(e: ExtractionEntity) {
    if (!e.duplicate_of_id) return;
    try {
      await notDupMut.mutateAsync({ entityType: e.entity_type, id: e.id, otherId: e.duplicate_of_id });
      toast.success(`"${e.name}" and "${e.duplicate_of}" will not be flagged again`);
    } catch (err) {
      toast.error(`Failed: ${(err as Error).message}`);
    }
  }

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
        message: `Merge ${mergeIds.length} into "${keeper.name}"? Aliases and entry links move to the kept entity.`,
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

  // The bulk buttons act on what the table shows: the status, the type pick and the search.
  const whatShows = () => {
    const type = entityType ? ` ${TYPE_LABELS[entityType].toLowerCase()}` : "";
    const named = q ? ` matching “${q}”` : "";
    return `${total.toLocaleString()}${type} entit${total === 1 ? "y" : "ies"}${named}`;
  };
  async function doBulk(action: "confirm" | "delete" | "merge" | "not_duplicate") {
    if (status === "all" || total === 0) return;
    const copy = {
      confirm: { title: "Confirm all", message: `Confirm ${whatShows()}? Each is kept as it is and leaves this list.`, label: "Confirm all", destructive: false },
      delete: {
        title: "Delete all",
        message: `Delete ${whatShows()}, with every article link and relationship? Their names go on the do-not-recreate list. This cannot be undone.`,
        label: "Delete all",
        destructive: true,
      },
      merge: {
        title: "Merge all",
        message: `Merge each of ${whatShows()} into the entity it most resembles? Aliases and article links move over. Each merge is its own change in History.`,
        label: "Merge all",
        destructive: true,
      },
      not_duplicate: {
        title: "Not duplicates",
        message: `Mark each of ${whatShows()} as distinct from the entity it resembles? The pairs stop being flagged.`,
        label: "Not duplicates",
        destructive: false,
      },
    }[action];
    if (!(await confirmDialog({ title: copy.title, message: copy.message, confirmLabel: copy.label, destructive: copy.destructive }))) return;
    try {
      const r = await bulkMut.mutateAsync({ action, status, types: effectiveTypes, q: q || undefined, window: timeWindow });
      const verb = { confirm: "Confirmed", delete: "Deleted", merge: "Merged", not_duplicate: "Marked" }[action];
      const parts = [`${verb} ${r.done.toLocaleString()} of ${r.matched.toLocaleString()}`];
      if (r.skipped) parts.push(`${r.skipped.toLocaleString()} skipped`);
      toast.success(parts.join(", "));
      setSelected(new Set());
    } catch (err) {
      toast.error(errMsg(err, `${copy.title} failed`));
    }
  }
  const bulkBusy = bulkMut.isPending;
  const bulkAll =
    status === "review"
      ? [
          { label: "Confirm all", action: "confirm" as const, danger: false, title: "Confirm every entity the table shows" },
          { label: "Delete all", action: "delete" as const, danger: true, title: "Delete every entity the table shows" },
        ]
      : status === "dupe"
        ? [
            { label: "Merge all", action: "merge" as const, danger: false, title: "Merge every entity the table shows into the one it resembles" },
            { label: "Not duplicates", action: "not_duplicate" as const, danger: false, title: "Stop flagging every pair the table shows" },
          ]
        : status === "orphan"
          ? [{ label: "Delete all", action: "delete" as const, danger: true, title: "Delete every entity the table shows" }]
          : [];

  return (
    <div className={styles.wrap}>
      {/* toolbar */}
      <div className={styles.toolbar}>
        {statusSwitch && (
          <span className={styles.seg} aria-label="Entity status">
            {REVIEW_STATUSES.map((s) => (
              <button
                key={s.value}
                className={status === s.value ? styles.segOn : ""}
                onClick={() => resetTo(() => statusSwitch.onChange(s.value))}
              >
                {s.label}
                <span className={styles.segCnt}>{(statusSwitch.counts[s.value] ?? 0).toLocaleString()}</span>
              </button>
            ))}
          </span>
        )}

        <select
          className={styles.filt}
          aria-label="Entity type"
          value={entityType}
          onChange={(e) => resetTo(() => setEntityType(e.target.value as ExtractionType | ""))}
        >
          <option value="">All entity types</option>
          {ALL_TYPES.map((t) => (
            <option key={t} value={t}>
              {TYPE_LABELS[t]}
              {/* The per-type counts cover every status, so only the full list shows them. */}
              {status === "all" && ` (${(stats?.by_type[t] ?? 0).toLocaleString()})`}
            </option>
          ))}
        </select>

        <label className={styles.search}>
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden>
            <circle cx="7" cy="7" r="5" />
            <path d="M11 11l3.5 3.5" />
          </svg>
          <input
            aria-label="Search created entities"
            placeholder="Search created entities, aliases…"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
        </label>

        {bulkAll.length > 0 && (
          <>
            <span className={styles.grow} />
            {bulkAll.map((b) => (
              <button
                key={b.action}
                className={`${styles.bulkbtn} ${b.danger ? styles.danger : ""}`}
                disabled={bulkBusy || total === 0}
                title={b.title}
                onClick={() => doBulk(b.action)}
              >
                {bulkBusy ? "Working…" : b.label}
              </button>
            ))}
          </>
        )}
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
                <SortTh label="Articles" col="entries" sortBy={sortBy} sortOrder={sortOrder} onSort={toggleSort} />
                <th className={styles.hideSm}>First source</th>
                <SortTh label="Created" col="created" sortBy={sortBy} sortOrder={sortOrder} onSort={toggleSort} className={styles.hideSm} />
                {status === "all" && <th>Status</th>}
                <th className={styles.actionsCol} />
              </tr>
            </thead>
            <tbody>
              {items.map((e) => (
                <Fragment key={e.id}>
                  <tr className={selected.has(e.id) ? styles.selRow : ""}>
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
                    <td className={styles.mut}>{e.created_confidence ?? "n/a"}</td>
                    <td className={styles.num}>{e.article_count}</td>
                    <td className={`${styles.hideSm} ${styles.mut} ${styles.sourceCell}`} title={e.source_entry_title ?? ""}>
                      <button
                        className={styles.evToggle}
                        onClick={() => setOpenEvidence((cur) => (cur === e.id ? null : e.id))}
                        title="Show the articles and the paragraphs naming it"
                      >
                        {openEvidence === e.id ? "▾" : "▸"} {e.source_entry_title ?? "articles"}
                      </button>
                    </td>
                    <td className={`${styles.hideSm} ${styles.when}`}>{relTime(e.first_seen_at)}</td>
                    {status === "all" && (
                      <td>
                        <StatusPill status={e.status} duplicateOf={e.duplicate_of} />
                      </td>
                    )}
                    <td>
                      {/* a fixed grid — primary / secondary / ⋯ / ✕ — so the buttons line up down the table */}
                      <div className={styles.rowacts}>
                        {e.status === "dupe" && e.duplicate_of_id ? (
                          <>
                            <button
                              className={`${styles.act} ${styles.actGood}`}
                              title={`Merge ${e.name} into ${e.duplicate_of}. Aliases and article links move over.`}
                              disabled={mergeMut.isPending}
                              onClick={() => doMergeIntoSibling(e)}
                            >
                              Merge
                            </button>
                            <button
                              className={styles.act}
                              title={`${e.name} and ${e.duplicate_of} are distinct. Stop flagging the pair.`}
                              disabled={notDupMut.isPending}
                              onClick={() => doNotDuplicate(e)}
                            >
                              Not a duplicate
                            </button>
                          </>
                        ) : e.needs_review ? (
                          <>
                            <button className={`${styles.act} ${styles.actGood}`} title="Keep it as it is" onClick={() => doConfirm([e])}>
                              Confirm
                            </button>
                            <span />
                          </>
                        ) : (
                          <>
                            <span />
                            <span />
                          </>
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
                          aria-label={e.entity_type === "observable" ? "Deny" : "Delete"}
                          title={e.entity_type === "observable" ? "Deny: never capture this value again" : "Delete"}
                          onClick={() => doDelete([e])}
                        >
                          ✕
                        </button>
                      </div>
                    </td>
                  </tr>
                  {openEvidence === e.id && (
                    <tr>
                      <td colSpan={9}>
                        <EntityEvidencePanel entityType={e.entity_type} entityId={e.id} />
                      </td>
                    </tr>
                  )}
                </Fragment>
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
              "No results"
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
    dupe: { cls: styles.stDupe, text: duplicateOf ? `Duplicate of ${duplicateOf}` : "Duplicate" },
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
  // Observables support none of these — keep the slot so the row's buttons stay aligned.
  if (!canMerge && !canRename && !canAlias && !canConvert) return <span />;

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
