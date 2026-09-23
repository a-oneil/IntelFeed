import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { useIntelStore, type EntityType } from "@/stores/intelStore";
import { useAuthStore } from "@/stores/authStore";
import api from "@/api/client";
import type { EntitySearchResult, PaginatedResponse } from "@/api/types";
import { bulkExportEntityProfiles } from "@/hooks/useExport";
import { useRelationshipSignals, type RelationshipSignals, type RelationshipSignalTop } from "@/hooks/useRelationships";
import { useDeleteEntity, MERGEABLE_ENTITY_TYPES } from "@/hooks/useEntityProfile";
import { useDenyObservable } from "@/hooks/useIntelligence";
import { EntityMergeSelectionModal, type MergeSelectionEntity } from "@/components/EntityMergeSelectionModal";
import { isCreatableEntityType } from "@/components/CreateEntityPanel";
import { EntityRowActionsCell } from "@/components/entityProfile/EntityActionsMenu";
import { useTechniqueCoverage } from "@/hooks/useDetectionRules";
import { useIsMobile } from "@/hooks/useMediaQuery";
import { DataTable, type DataTableColumn, type SortDir } from "@/components/table/DataTable";
import { PageHeader } from "@/components/primitives";
import table from "@/components/table/DataTable.module.css";
import styles from "@/pages/WorkbenchPage.module.css";

// Re-exported so entity column definitions can live next to the sections that
// use them without importing the table module directly.
export type { DataTableColumn as ColumnDef, SortDir };

const relLabel = (t: RelationshipSignalTop) =>
  `${t.direction === "outbound" ? "→" : "←"} ${t.verb.replace(/_/g, " ")} ${t.other_label ?? t.other_type}` +
  (t.confidence === "confirmed" ? " ✓" : "");

function linkedCellTitle(sig: RelationshipSignals): string {
  return sig.top.map(relLabel).join("\n");
}

/** Gaps sort to the top: no rule > library only > covered. */
const COVERAGE_RANK: Record<string, number> = { no_rule: 3, library_only: 2, covered: 1 };
const COVERAGE_LABEL: Record<string, string> = {
  no_rule: "no rule",
  library_only: "library",
  covered: "covered",
};
const COVERAGE_TIP: Record<string, string> = {
  no_rule: "No detection rule references this technique",
  library_only: "Rules exist, but their required data sources aren't in your telemetry inventory",
  covered: "A non-draft rule covers this technique and its data sources are satisfiable",
};

const PAGE_SIZE = 100;

interface EntityTableSectionProps<T> {
  title: string;
  entityType: EntityType;
  columns: DataTableColumn<T>[];
  queryKey: string;
  endpoint: string;
  /** Must name a column the endpoint accepts as `sort_by` */
  defaultSort: { key: string; dir: SortDir };
  emptyTitle: string;
  emptyDesc: string;
  getId: (item: T) => string;
  getLabel?: (item: T) => string;
  /** Extra header controls (e.g. Find Duplicates) */
  filters?: ReactNode;
  extraQueryParams?: Record<string, unknown>;
  noun: string;
  nounPlural?: string;
}

export function EntityTableSection<T>({
  title,
  entityType,
  columns,
  queryKey,
  endpoint,
  defaultSort,
  emptyTitle,
  emptyDesc,
  getId,
  getLabel,
  filters,
  extraQueryParams,
  noun,
  nounPlural,
}: EntityTableSectionProps<T>) {
  const [sort, setSort] = useState<{ key: string; dir: SortDir }>(defaultSort);
  const [serverFilters, setServerFilters] = useState<Record<string, string>>({});
  const selectEntity = useIntelStore((s) => s.selectEntity);
  // Gated: the EntityType union outgrew CreateEntityPanel (observables are
  // promoted from articles, CWEs come from the catalog) — an ungated button
  // silently opened a Threat Actor form for those types.
  const openCreateEntity = useIntelStore((s) => s.openCreateEntity);
  const canCreate = isCreatableEntityType(entityType);
  const isMobile = useIsMobile();
  // Mobile: header actions (export, filters) fold behind a ⋯ menu so the
  // section header stays a single pinned row.
  const [actionsOpen, setActionsOpen] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const scrollRestoredRef = useRef(false);

  // Callers pass these as inline arrows, so pin the identity — they feed
  // memoised columns and the batched relationship-signals request.
  const accessorsRef = useRef({ getId, getLabel });
  accessorsRef.current = { getId, getLabel };
  const rowId = useCallback((item: T) => accessorsRef.current.getId(item), []);

  const scrollKey = `${entityType}:${sort.key}:${sort.dir}:${JSON.stringify(extraQueryParams ?? {})}`;

  const { data, isLoading, isError, error, fetchNextPage, hasNextPage, isFetchingNextPage } = useInfiniteQuery({
    queryKey: [queryKey, sort, serverFilters, extraQueryParams],
    queryFn: async ({ pageParam = 0 }) => {
      const { data } = await api.get<PaginatedResponse<T>>(endpoint, {
        params: {
          limit: PAGE_SIZE,
          offset: pageParam,
          sort_by: sort.key,
          sort_order: sort.dir,
          ...serverFilters,
          ...extraQueryParams,
        },
      });
      return data;
    },
    initialPageParam: 0,
    getNextPageParam: (lastPage) =>
      lastPage.has_more ? lastPage.offset + lastPage.limit : undefined,
  });

  const items = useMemo(() => data?.pages.flatMap((p) => p.items) ?? [], [data]);
  const total = data?.pages[0]?.total ?? 0;
  const ids = useMemo(() => items.map(rowId), [items, rowId]);

  // --- Markdown export (selected rows or all-of-type) ---
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [exportingAll, setExportingAll] = useState(false);
  const [exportingSelected, setExportingSelected] = useState(false);

  const handleExportAll = async () => {
    setExportingAll(true);
    try {
      await bulkExportEntityProfiles({ entityType, all: true });
      toast.success(`Exported ${title} profiles`);
    } catch {
      toast.error("Export failed");
    } finally {
      setExportingAll(false);
    }
  };

  const deleteEntity = useDeleteEntity();
  const [deletingSelected, setDeletingSelected] = useState(false);
  const [tombstoningSelected, setTombstoningSelected] = useState(false);
  const denyObservable = useDenyObservable();
  const [mergeSelectionOpen, setMergeSelectionOpen] = useState(false);

  // Merging folds N profiles into one, so it needs two or more checked rows of a
  // type the merge engine supports — and merge is an admin-only endpoint.
  const isAdmin = useAuthStore((s) => s.user?.role === "admin");
  const canMergeSelection =
    isAdmin &&
    MERGEABLE_ENTITY_TYPES.includes(entityType as (typeof MERGEABLE_ENTITY_TYPES)[number]) &&
    selectedIds.size >= 2;

  // The ledger's tombstone rung sits beside delete for observables; denying is
  // an admin endpoint.
  const canTombstone = isAdmin && entityType === "observable" && selectedIds.size > 0;

  // The checked rows as merge candidates, in table order. Selection only ever
  // holds loaded rows, so every id resolves.
  const selectedForMerge = useMemo<MergeSelectionEntity[]>(
    () =>
      items
        .filter((item) => selectedIds.has(rowId(item)))
        .map((item) => {
          const row = item as { aliases?: string[] | null; article_count?: number | null };
          return {
            id: rowId(item),
            name: accessorsRef.current.getLabel?.(item) ?? rowId(item),
            aliases: row.aliases,
            article_count: row.article_count,
          };
        }),
    [items, selectedIds, rowId]
  );

  // Batched rather than all-at-once so a large selection doesn't open a
  // hundred simultaneous requests.
  const runOnSelection = async (ids: string[], run: (id: string) => Promise<unknown>) => {
    let failed = 0;
    for (let i = 0; i < ids.length; i += 5) {
      const results = await Promise.allSettled(ids.slice(i, i + 5).map(run));
      failed += results.filter((r) => r.status === "rejected").length;
    }
    return failed;
  };

  const reportBulk = (verb: string, ids: string[], failed: number, word: string) => {
    setSelectedIds(new Set());
    if (failed === 0) toast.success(`${verb} ${ids.length} ${word}`);
    else if (failed === ids.length) toast.error(`Couldn't ${verb.toLowerCase()} ${failed} ${word}`);
    else toast.warning(`${verb} ${ids.length - failed} of ${ids.length} — ${failed} failed`);
  };

  // Bulk delete skips the single-row undo window — a confirm is the guard.
  const handleDeleteSelected = async () => {
    const ids = [...selectedIds];
    if (ids.length === 0) return;
    const word = ids.length === 1 ? noun : (nounPlural ?? `${noun}s`);
    const prompt =
      entityType === "observable"
        ? `Delete ${ids.length} ${word}? Their sightings and relationships go with them, and nothing stops a future article from capturing the values again — use "Never capture" for that. This can't be undone.`
        : `Delete ${ids.length} ${word}? Their entry links and relationships go with them. This can't be undone.`;
    if (!confirm(prompt)) return;
    setDeletingSelected(true);
    const failed = await runOnSelection(ids, (id) => deleteEntity(entityType, id));
    setDeletingSelected(false);
    reportBulk("Deleted", ids, failed, word);
  };

  // Observables only: the tombstone rung. Keeps every row but slams the capture
  // doors shut on its value, which a delete deliberately does not do.
  const handleTombstoneSelected = async () => {
    const ids = [...selectedIds];
    if (ids.length === 0) return;
    const word = ids.length === 1 ? noun : (nounPlural ?? `${noun}s`);
    if (
      !confirm(
        `Never capture ${ids.length} ${word}? Every door refuses the values from now on and they leave the outbound feeds; the rows and their sightings are kept as history.`,
      )
    )
      return;
    setTombstoningSelected(true);
    const failed = await runOnSelection(ids, (id) => denyObservable.mutateAsync(id));
    setTombstoningSelected(false);
    reportBulk("Tombstoned", ids, failed, word);
  };

  const handleExportSelected = async () => {
    if (selectedIds.size === 0) return;
    setExportingSelected(true);
    try {
      await bulkExportEntityProfiles({ entityType, entityIds: [...selectedIds] });
      toast.success(`Exported ${selectedIds.size} profile${selectedIds.size === 1 ? "" : "s"}`);
      setSelectedIds(new Set());
    } catch {
      toast.error("Export failed");
    } finally {
      setExportingSelected(false);
    }
  };

  // Batched relationship signals for the "Linked" / "Top link" columns (one
  // request per loaded page of rows, cached a minute).
  const { data: signals } = useRelationshipSignals(entityType, ids);

  // Telemetry-aware rule coverage, batched the same way. Only TTP rows carry
  // technique IDs, so every other table passes an empty list and the query stays
  // disabled — the hook must still be called unconditionally.
  const techniqueIds = useMemo(
    () =>
      entityType === "ttp"
        ? items.map((i) => (i as { technique_id?: string }).technique_id ?? "").filter(Boolean)
        : [],
    [entityType, items]
  );
  const { data: coverage } = useTechniqueCoverage(techniqueIds);
  const coverageOf = useCallback(
    (item: T) => coverage?.techniques?.[(item as { technique_id?: string }).technique_id ?? ""],
    [coverage]
  );

  // These columns are appended rather than declared per entity type: every
  // entity has relationships, and coverage comes from one shared batched hook.
  const allColumns = useMemo<DataTableColumn<T>[]>(
    () => [
      ...columns,
      ...(entityType === "ttp"
        ? ([
            {
              key: "coverage",
              label: "Coverage",
              width: 100,
              minWidth: 80,
              hideable: true,
              sortValue: (item: T) => COVERAGE_RANK[coverageOf(item)?.status ?? ""] ?? 0,
              choices: [
                { value: "all", label: "Any" },
                { value: "no_rule", label: "No rule" },
                { value: "library_only", label: "Library only" },
                { value: "covered", label: "Covered" },
              ],
              choiceMatch: (item: T, v: string) => coverageOf(item)?.status === v,
              render: (item: T) => {
                const info = coverageOf(item);
                if (!info) return <span className={table.zero}>·</span>;
                const cls =
                  info.status === "no_rule"
                    ? table.chipCritical
                    : info.status === "library_only"
                      ? table.chipMedium
                      : table.chipLow;
                const missing = info.missing_data_sources?.length
                  ? `\nMissing: ${info.missing_data_sources.join(", ")}`
                  : "";
                return (
                  <span
                    className={`${table.chip} ${cls}`}
                    title={`${COVERAGE_TIP[info.status] ?? ""}${missing}`}
                  >
                    {COVERAGE_LABEL[info.status] ?? info.status}
                  </span>
                );
              },
            },
            {
              key: "rule_count",
              label: "Rules",
              width: 70,
              minWidth: 56,
              hideable: true,
              defaultHidden: true,
              numValue: (item: T) => coverageOf(item)?.rule_count ?? 0,
              render: (item: T) => {
                const info = coverageOf(item);
                if (!info?.rule_count) return <span className={table.zero}>·</span>;
                return (
                  <span
                    className={`${table.count} ${table.rule}`}
                    title={`${info.rule_count} rule${info.rule_count === 1 ? "" : "s"} reference this technique — ${info.satisfiable_rule_count} satisfiable by your telemetry`}
                  >
                    {info.rule_count}
                    {info.satisfiable_rule_count !== info.rule_count && (
                      <span className={table.muted}> / {info.satisfiable_rule_count}</span>
                    )}
                  </span>
                );
              },
            },
          ] as DataTableColumn<T>[])
        : []),
      {
        key: "linked_count",
        label: "Linked",
        width: 70,
        minWidth: 56,
        hideable: true,
        serverSort: true,
        render: (item: T) => {
          const sig = signals?.[rowId(item)];
          return sig?.count ? (
            <span className={table.count} title={linkedCellTitle(sig)}>{sig.count}</span>
          ) : (
            <span className={table.zero}>·</span>
          );
        },
      },
      {
        key: "top_link",
        label: "Top link",
        width: 200,
        minWidth: 110,
        hideable: true,
        defaultHidden: true,
        textValue: (item: T) => (signals?.[rowId(item)]?.top ?? []).map(relLabel).join(", "),
        render: (item: T) => {
          const sig = signals?.[rowId(item)];
          const top = sig?.top?.[0];
          if (!top) return <span className={table.zero}>·</span>;
          return (
            <span className={`${styles.entityMeta} ${table.ellipsis}`} title={linkedCellTitle(sig!)}>
              {relLabel(top)}
            </span>
          );
        },
      },
      {
        // The profile's ⋯ menu, per row: edit, convert, merge, watch, delete.
        key: "actions",
        label: "",
        width: 40,
        minWidth: 36,
        sticky: "right",
        render: (item: T) => (
          <EntityRowActionsCell
            entityType={entityType}
            entityId={rowId(item)}
            displayName={accessorsRef.current.getLabel?.(item) ?? rowId(item)}
            entity={item as unknown as EntitySearchResult}
          />
        ),
      },
    ],
    [columns, signals, rowId, entityType, coverageOf]
  );

  const onSelectionChange = useCallback((next: string[]) => setSelectedIds(new Set(next)), []);
  const onServerFiltersChange = useCallback((f: Record<string, string>) => setServerFilters(f), []);
  const onRowClick = useCallback(
    (item: T) => {
      const { getId: id, getLabel: label } = accessorsRef.current;
      selectEntity(entityType, id(item), label?.(item));
    },
    [selectEntity, entityType]
  );

  // Save scroll position (throttled via rAF) and restore it once per sort/filter
  // combination, so returning from an entity profile lands where you left off.
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    let rafId: number | null = null;
    const save = () => {
      if (el.scrollTop > 0) useIntelStore.getState().setTableScrollPosition(scrollKey, el.scrollTop);
    };
    const onScroll = () => {
      if (rafId !== null) return;
      rafId = requestAnimationFrame(() => {
        rafId = null;
        save();
      });
    };
    el.addEventListener("scroll", onScroll, { passive: true });
    return () => {
      el.removeEventListener("scroll", onScroll);
      // Flush any pending rAF synchronously before the DOM is torn down so the
      // last good scroll position survives the unmount (e.g. user scrolls then
      // immediately clicks a row).
      if (rafId !== null) {
        cancelAnimationFrame(rafId);
        save();
      }
    };
  }, [scrollKey]);

  useEffect(() => {
    if (scrollRestoredRef.current || isLoading || items.length === 0) return;
    const el = scrollRef.current;
    if (!el) return;
    const saved = useIntelStore.getState().tableScrollPositions[scrollKey] ?? 0;
    if (saved > 0) el.scrollTop = saved;
    scrollRestoredRef.current = true;
  }, [isLoading, items.length, scrollKey]);

  return (
    <>
      {/* No total in the header: DataTable's own bar already reports
          "N loaded · M total" a few pixels below. */}
      <PageHeader
        title={title}
        count={selectedIds.size > 0 ? `${selectedIds.size} selected` : undefined}
        actions={
          isMobile ? (
            <>
              <button
                className={styles.headerActionsBtn}
                onClick={() => setActionsOpen((v) => !v)}
                aria-label={`${title} actions`}
                aria-expanded={actionsOpen}
              >
                ⋯
              </button>
              {actionsOpen && (
                <>
                  <div className={styles.headerActionsBackdrop} onClick={() => setActionsOpen(false)} />
                  <div className={styles.headerActionsMenu}>
                    {selectedIds.size > 0 && (
                      <>
                        <button className={styles.btn} disabled={exportingSelected} onClick={handleExportSelected}>
                          {exportingSelected ? "Exporting…" : `Export selected (${selectedIds.size})`}
                        </button>
                        {canMergeSelection && (
                          <button
                            className={styles.btn}
                            onClick={() => {
                              setActionsOpen(false);
                              setMergeSelectionOpen(true);
                            }}
                          >
                            {`Merge selected (${selectedIds.size})`}
                          </button>
                        )}
                        {canTombstone && (
                          <button
                            className={styles.btn}
                            disabled={tombstoningSelected}
                            onClick={handleTombstoneSelected}
                            title="Tombstone: never capture or export these values again"
                          >
                            {tombstoningSelected ? "Tombstoning…" : `Never capture (${selectedIds.size})`}
                          </button>
                        )}
                        <button
                          className={`${styles.btn} ${styles.btnDanger}`}
                          disabled={deletingSelected}
                          onClick={handleDeleteSelected}
                        >
                          {deletingSelected ? "Deleting…" : `Delete selected (${selectedIds.size})`}
                        </button>
                        <button className={styles.btn} onClick={() => setSelectedIds(new Set())}>
                          Clear selection
                        </button>
                      </>
                    )}
                    <button
                      className={styles.btn}
                      disabled={exportingAll}
                      onClick={handleExportAll}
                      title="Export every profile of this type as Markdown"
                    >
                      {exportingAll ? "Exporting…" : "Export all"}
                    </button>
                    {filters}
                    <button
                      className={`${styles.btn} ${styles.btnPrimary}`}
                      onClick={() => { setActionsOpen(false); openCreateEntity(entityType); }}
                    >
                      + Create Entity
                    </button>
                  </div>
                </>
              )}
            </>
          ) : (
            <>
              {selectedIds.size > 0 && (
                <>
                  <button className={styles.btn} disabled={exportingSelected} onClick={handleExportSelected}>
                    {exportingSelected ? "Exporting…" : "Export selected"}
                  </button>
                  {canMergeSelection && (
                    <button className={styles.btn} onClick={() => setMergeSelectionOpen(true)}>
                      Merge selected
                    </button>
                  )}
                  {canTombstone && (
                    <button
                      className={styles.btn}
                      disabled={tombstoningSelected}
                      onClick={handleTombstoneSelected}
                      title="Tombstone: never capture or export these values again"
                    >
                      {tombstoningSelected ? "Tombstoning…" : "Never capture"}
                    </button>
                  )}
                  <button
                    className={`${styles.btn} ${styles.btnDanger}`}
                    disabled={deletingSelected}
                    onClick={handleDeleteSelected}
                  >
                    {deletingSelected ? "Deleting…" : "Delete selected"}
                  </button>
                  <button className={styles.btn} onClick={() => setSelectedIds(new Set())}>
                    Clear
                  </button>
                </>
              )}
              <button
                className={styles.btn}
                disabled={exportingAll}
                onClick={handleExportAll}
                title="Export every profile of this type as Markdown"
              >
                {exportingAll ? "Exporting…" : "Export all"}
              </button>
              {filters}
              {canCreate && (
                <button
                  className={`${styles.btn} ${styles.btnPrimary}`}
                  onClick={() => openCreateEntity(entityType)}
                  title={`Create a new ${noun ?? "entity"}`}
                >
                  + Create Entity
                </button>
              )}
            </>
          )
        }
      />
      {mergeSelectionOpen && selectedForMerge.length >= 2 && (
        <EntityMergeSelectionModal
          entityType={entityType}
          entities={selectedForMerge}
          onClose={() => setMergeSelectionOpen(false)}
          onMerged={() => setSelectedIds(new Set())}
        />
      )}
      <DataTable<T>
        tableId={`entity:${entityType}`}
        columns={allColumns}
        rows={items}
        getRowId={rowId}
        onRowClick={onRowClick}
        selectable
        selectedIds={selectedIds}
        onSelectionChange={onSelectionChange}
        sort={sort}
        onSortChange={setSort}
        onServerFiltersChange={onServerFiltersChange}
        isLoading={isLoading}
        hasNextPage={hasNextPage}
        isFetchingNextPage={isFetchingNextPage}
        fetchNextPage={fetchNextPage}
        totalCount={total}
        noun={noun}
        nounPlural={nounPlural}
        scrollRef={scrollRef}
        emptyState={
          isError ? (
            // A failed request is not an empty table — saying "No X yet" over
            // a 4xx once masked an unsupported sort key as missing data.
            <div className={styles.emptyState}>
              <div className={styles.emptyTitle}>Couldn't load {nounPlural ?? `${noun}s`}</div>
              <div className={styles.emptyDesc}>
                {(error as { response?: { data?: { error?: { message?: string }; detail?: string } } })?.response
                  ?.data?.error?.message ??
                  (error as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
                  (error instanceof Error ? error.message : "Request failed")}
              </div>
            </div>
          ) : (
            <div className={styles.emptyState}>
              <div className={styles.emptyTitle}>{emptyTitle}</div>
              <div className={styles.emptyDesc}>{emptyDesc}</div>
            </div>
          )
        }
      />
    </>
  );
}
