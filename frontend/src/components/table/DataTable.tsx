import {
  memo,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
  type MutableRefObject,
} from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useUIStore, EMPTY_TABLE_LAYOUT } from "@/stores/uiStore";
import { TableSkeleton } from "@/components/Skeleton";
import { Hint } from "@/components/primitives";
import { DEFAULT_TABLE_LAYOUTS, EMPTY_DEFAULT_LAYOUT } from "./defaultLayouts";
import { scalePx } from "@/utils/uiScale";
import styles from "./DataTable.module.css";

export type SortDir = "asc" | "desc";

export interface DataTableColumn<T> {
  key: string;
  label: string;
  /** Default width in px (overridable by drag-resize, persisted per table) */
  width: number;
  minWidth?: number;
  /** Absorbs spare horizontal width — set on exactly one column per table */
  flex?: boolean;
  /** Whether the Columns menu can hide it */
  hideable?: boolean;
  /** Hidden until the user enables it in the Columns menu */
  defaultHidden?: boolean;
  /** Sorts the full result set on the server; the owner supplies `sort`/`onSortChange` */
  serverSort?: boolean;
  /** Client-side sort key over loaded rows */
  sortValue?: (row: T) => string | number;
  /** Present ⇒ column gets a text filter input */
  textValue?: (row: T) => string;
  /** Send this column's text filter to the server instead of filtering loaded rows */
  serverText?: boolean;
  /** Present ⇒ column gets a ">0" filter toggle and numeric sort */
  numValue?: (row: T) => number;
  /** Present ⇒ column gets a dropdown filter (first entry is the "no filter" option) */
  choices?: { value: string; label: string }[];
  /** Client-side predicate for the selected dropdown value */
  choiceMatch?: (row: T, value: string) => boolean;
  /** Send this column's dropdown value to the server instead of filtering loaded rows */
  serverChoice?: boolean;
  /** Pin the column to the right edge of the scroller (row actions). Sticky
   *  columns are always ordered last and can't be dragged. */
  sticky?: "right";
  /** Key the server filter is reported under (defaults to the column key) */
  serverParam?: string;
  /**
   * Hover card for a column whose header is a label rather than an
   * explanation — where the value came from, what a low number means. When set
   * it replaces the header's native tooltip; two at once is worse than either.
   */
  hint?: { title: string; body: string; aside?: string };
  render: (row: T) => ReactNode;
}

const SELECT_KEY = "__select";
const DEFAULT_ROW_HEIGHT = scalePx(34);
/** Sentinel value of a dropdown filter's "no filter" option. */
const ALL = "all";
const EMPTY_SELECTION: ReadonlySet<string> = new Set<string>();

interface DataTableProps<T> {
  /** Stable id namespacing this table's persisted columns, widths, order, filters, sort */
  tableId: string;
  columns: DataTableColumn<T>[];
  rows: T[];
  getRowId: (row: T) => string;
  rowHeight?: number;
  /** Extra class names per row — use `rowMuted` / `rowDim` from the shared module */
  rowClass?: (row: T) => string | undefined;
  /** Row rendered with the "current selection" highlight */
  activeRowId?: string | null;
  onRowClick?: (row: T) => void;

  selectable?: boolean;
  selectedIds?: Set<string>;
  onSelectionChange?: (ids: string[]) => void;

  /** Current server sort; required for columns declaring `serverSort` */
  sort?: { key: string; dir: SortDir } | null;
  onSortChange?: (sort: { key: string; dir: SortDir }) => void;

  /**
   * Debounced values of every `serverText` / `serverChoice` column, keyed by
   * column key. Wrap in useCallback — an unstable identity re-fires it.
   */
  onServerFiltersChange?: (filters: Record<string, string>) => void;

  isLoading?: boolean;
  hasNextPage?: boolean;
  isFetchingNextPage?: boolean;
  fetchNextPage?: () => void;
  /** Server-reported result-set size, shown next to the loaded count */
  totalCount?: number;
  /** Word for a row, used in the counts line ("142 actors loaded") */
  noun?: string;
  /** Plural of `noun` when adding an "s" is wrong ("entries", "families") */
  nounPlural?: string;
  emptyMessage?: string;
  /** Rendered instead of the plain empty message when nothing is loaded at all */
  emptyState?: ReactNode;
  /** Extra controls in the table bar, left of the Columns menu */
  toolbar?: ReactNode;
  /** Scroll container, exposed so owners can persist/restore scroll position */
  scrollRef?: MutableRefObject<HTMLDivElement | null>;
}

const RowView = memo(function RowView({
  cells,
  gridTemplate,
  className,
  onClick,
  selectCell,
}: {
  cells: ReactNode[];
  gridTemplate: string;
  className: string;
  onClick?: () => void;
  selectCell: ReactNode;
}) {
  return (
    <div className={className} style={{ gridTemplateColumns: gridTemplate }} onClick={onClick}>
      {selectCell}
      {cells}
    </div>
  );
});

export function DataTable<T>({
  tableId,
  columns,
  rows,
  getRowId,
  rowHeight = DEFAULT_ROW_HEIGHT,
  rowClass,
  activeRowId,
  onRowClick,
  selectable = false,
  selectedIds,
  onSelectionChange,
  sort,
  onSortChange,
  onServerFiltersChange,
  isLoading = false,
  hasNextPage = false,
  isFetchingNextPage = false,
  fetchNextPage,
  totalCount,
  noun = "row",
  nounPlural,
  emptyMessage = "Nothing to display",
  emptyState,
  toolbar,
  scrollRef,
}: DataTableProps<T>) {
  const layout = useUIStore((s) => s.tables[tableId]) ?? EMPTY_TABLE_LAYOUT;
  const setColumnVisible = useUIStore((s) => s.setTableColumnVisible);
  const setColumnWidth = useUIStore((s) => s.setTableColumnWidth);
  const setColumnOrder = useUIStore((s) => s.setTableColumnOrder);
  const resetLayout = useUIStore((s) => s.resetTableLayout);
  const setTextFilter = useUIStore((s) => s.setTableTextFilter);
  const setHasFilter = useUIStore((s) => s.setTableHasFilter);
  const setChoiceFilter = useUIStore((s) => s.setTableChoiceFilter);
  const setClientSort = useUIStore((s) => s.setTableClientSort);
  const clearFilters = useUIStore((s) => s.clearTableFilters);

  const { columnVisibility, columnWidths, columnOrder, textFilters, hasFilters, choiceFilters, clientSort } =
    layout;

  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const localScrollRef = useRef<HTMLDivElement>(null);
  const scroller = scrollRef ?? localScrollRef;

  const selected = selectedIds ?? EMPTY_SELECTION;
  const bulkMode = selected.size > 0;

  // --- Columns: visibility, order, widths ---

  // The instance's curated arrangement, consulted only where this user has no
  // preference of their own — so shipping a new default never overwrites a
  // column someone deliberately hid, widened, or moved.
  const preset = DEFAULT_TABLE_LAYOUTS[tableId] ?? EMPTY_DEFAULT_LAYOUT;

  const isColVisible = useCallback(
    (c: DataTableColumn<T>) =>
      columnVisibility[c.key] ?? preset.visibility?.[c.key] ?? !c.defaultHidden,
    [columnVisibility, preset]
  );

  // Apply the user's arrangement, falling back to the preset one; columns absent
  // from either (newly shipped) keep their declared position.
  const orderedColumns = useMemo(() => {
    const order = columnOrder.length > 0 ? columnOrder : (preset.order ?? []);
    if (order.length === 0) return columns;
    const byKey = new Map(columns.map((c) => [c.key, c]));
    const arranged: DataTableColumn<T>[] = [];
    for (const k of order) {
      const c = byKey.get(k);
      if (c) {
        arranged.push(c);
        byKey.delete(k);
      }
    }
    for (const c of columns) if (byKey.has(c.key)) arranged.push(c);
    // A pinned column has to sit at the edge it's pinned to, whatever order the
    // user dragged the rest into.
    return [...arranged.filter((c) => !c.sticky), ...arranged.filter((c) => c.sticky)];
  }, [columns, columnOrder, preset]);

  const visibleCols = useMemo(
    () => orderedColumns.filter(isColVisible),
    [orderedColumns, isColVisible]
  );

  const colWidth = useCallback(
    (c: DataTableColumn<T>) =>
      Math.max(c.minWidth ?? 40, columnWidths[c.key] ?? preset.widths?.[c.key] ?? c.width),
    [columnWidths, preset]
  );

  const gridTemplate = useMemo(() => {
    const cols = visibleCols.map((c) =>
      c.flex ? `minmax(${colWidth(c)}px, 1fr)` : `${colWidth(c)}px`
    );
    return selectable ? `36px ${cols.join(" ")}` : cols.join(" ");
  }, [visibleCols, colWidth, selectable]);

  const minTableWidth = useMemo(
    () => visibleCols.reduce((sum, c) => sum + colWidth(c), selectable ? 36 : 0),
    [visibleCols, colWidth, selectable]
  );

  // Header drag-reorder
  const [dragKey, setDragKey] = useState<string | null>(null);
  const [dropKey, setDropKey] = useState<string | null>(null);
  const handleHeaderDrop = useCallback(
    (targetKey: string) => {
      if (dragKey && dragKey !== targetKey) {
        const keys = orderedColumns.map((c) => c.key);
        const from = keys.indexOf(dragKey);
        const to = keys.indexOf(targetKey);
        keys.splice(from, 1);
        // Dragging rightward lands after the target; leftward lands before it.
        keys.splice(keys.indexOf(targetKey) + (from < to ? 1 : 0), 0, dragKey);
        setColumnOrder(tableId, keys);
      }
      setDragKey(null);
      setDropKey(null);
    },
    [dragKey, orderedColumns, setColumnOrder, tableId]
  );

  // Column drag-resize; width persists to the store on each move.
  const onResizeStart = useCallback(
    (e: React.PointerEvent, col: DataTableColumn<T>) => {
      e.preventDefault();
      e.stopPropagation();
      const startX = e.clientX;
      const startWidth = colWidth(col);
      const onMove = (ev: PointerEvent) => {
        setColumnWidth(tableId, col.key, Math.max(col.minWidth ?? 40, startWidth + ev.clientX - startX));
      };
      const onUp = () => {
        window.removeEventListener("pointermove", onMove);
        window.removeEventListener("pointerup", onUp);
      };
      window.addEventListener("pointermove", onMove);
      window.addEventListener("pointerup", onUp);
    },
    [colWidth, setColumnWidth, tableId]
  );

  // --- Filtering ---

  // Server-backed filters are excluded from the client pass — the rows that came
  // back are already narrowed.
  const clientFilteredRows = useMemo(() => {
    const textCols = columns.filter((c) => c.textValue && !c.serverText && textFilters[c.key]?.trim());
    const numCols = columns.filter((c) => c.numValue && hasFilters[c.key]);
    const choiceCols = columns.filter(
      (c) => c.choiceMatch && !c.serverChoice && choiceFilters[c.key] && choiceFilters[c.key] !== ALL
    );
    if (!textCols.length && !numCols.length && !choiceCols.length) return rows;
    return rows.filter((r) => {
      for (const col of textCols) {
        const q = textFilters[col.key].trim().toLowerCase();
        if (!col.textValue!(r).toLowerCase().includes(q)) return false;
      }
      for (const col of numCols) if (col.numValue!(r) <= 0) return false;
      for (const col of choiceCols) if (!col.choiceMatch!(r, choiceFilters[col.key])) return false;
      return true;
    });
  }, [rows, columns, textFilters, hasFilters, choiceFilters]);

  const displayRows = useMemo(() => {
    if (!clientSort) return clientFilteredRows;
    const col = columns.find((c) => c.key === clientSort.key);
    const getVal = col?.sortValue ?? col?.numValue;
    if (!getVal) return clientFilteredRows;
    const mul = clientSort.dir === "asc" ? 1 : -1;
    return [...clientFilteredRows].sort((a, b) => {
      const va = getVal(a);
      const vb = getVal(b);
      if (va < vb) return -mul;
      if (va > vb) return mul;
      return 0;
    });
  }, [clientFilteredRows, clientSort, columns]);

  const anyFilterActive =
    Object.values(textFilters).some((v) => v.trim()) ||
    Object.values(hasFilters).some(Boolean) ||
    Object.values(choiceFilters).some((v) => v && v !== ALL);

  // Only client filters can starve the virtual list; server filters come back
  // already narrowed, so they must not trigger the backfill loop.
  const anyClientFilterActive = useMemo(
    () =>
      columns.some(
        (c) =>
          (c.textValue && !c.serverText && textFilters[c.key]?.trim()) ||
          (c.numValue && hasFilters[c.key]) ||
          (c.choiceMatch && !c.serverChoice && choiceFilters[c.key] && choiceFilters[c.key] !== ALL)
      ),
    [columns, textFilters, hasFilters, choiceFilters]
  );

  const handleClearFilters = useCallback(() => clearFilters(tableId), [clearFilters, tableId]);

  // Human-readable list of what's currently narrowing the table, so an empty
  // result can name the filter responsible (including one persisted from an
  // earlier session that the user has forgotten about).
  const activeFilterSummary = useMemo(() => {
    const out: string[] = [];
    for (const c of columns) {
      const label = c.label || c.key;
      const text = textFilters[c.key]?.trim();
      if ((c.textValue || c.serverText) && text) out.push(`${label}: “${text}”`);
      if (c.numValue && hasFilters[c.key]) out.push(`${label}: >0`);
      const choice = choiceFilters[c.key];
      if (c.choices && choice && choice !== ALL) {
        out.push(`${label}: ${c.choices.find((o) => o.value === choice)?.label ?? choice}`);
      }
    }
    return out;
  }, [columns, textFilters, hasFilters, choiceFilters]);

  // --- Server filter relay (debounced) ---

  const serverFilters = useMemo(() => {
    const out: Record<string, string> = {};
    for (const c of columns) {
      if (c.serverText) {
        const v = textFilters[c.key]?.trim();
        if (v) out[c.serverParam ?? c.key] = v;
      }
      if (c.serverChoice) {
        const v = choiceFilters[c.key];
        if (v && v !== ALL) out[c.serverParam ?? c.key] = v;
      }
    }
    return out;
  }, [columns, textFilters, choiceFilters]);

  const serverFiltersJson = JSON.stringify(serverFilters);
  const onServerFiltersRef = useRef(onServerFiltersChange);
  onServerFiltersRef.current = onServerFiltersChange;
  const firstRelayRef = useRef(true);
  useEffect(() => {
    if (!onServerFiltersRef.current) return;
    const emit = () => onServerFiltersRef.current?.(JSON.parse(serverFiltersJson));
    // Persisted filters must reach the query on mount without a typing delay.
    if (firstRelayRef.current) {
      firstRelayRef.current = false;
      emit();
      return;
    }
    const t = setTimeout(emit, 300);
    return () => clearTimeout(t);
  }, [serverFiltersJson]);

  // --- Sorting ---

  const handleSort = useCallback(
    (col: DataTableColumn<T>) => {
      if (col.serverSort && onSortChange) {
        setClientSort(tableId, null);
        onSortChange({
          key: col.key,
          dir: sort?.key === col.key && sort.dir === "desc" ? "asc" : "desc",
        });
        return;
      }
      if (!col.sortValue && !col.numValue) return;
      setClientSort(
        tableId,
        clientSort?.key !== col.key
          ? { key: col.key, dir: "desc" }
          : clientSort.dir === "desc"
            ? { key: col.key, dir: "asc" }
            : null
      );
    },
    [sort, onSortChange, clientSort, setClientSort, tableId]
  );

  const sortIndicator = useCallback(
    (col: DataTableColumn<T>): SortDir | null => {
      if (clientSort?.key === col.key) return clientSort.dir;
      if (!clientSort && col.serverSort && sort?.key === col.key) return sort.dir;
      return null;
    },
    [clientSort, sort]
  );

  // --- Selection ---

  const lastCheckedRef = useRef<number | null>(null);
  // Two clicks inside one React batch would both read the same rendered
  // `selected` and the later one would clobber the earlier. Mirror each
  // mutation into a ref so same-tick clicks compose; the prop resyncs it on the
  // next render.
  const selectedRef = useRef(selected);
  selectedRef.current = selected;
  const applySelection = useCallback(
    (next: Set<string>) => {
      selectedRef.current = next;
      onSelectionChange?.(Array.from(next));
    },
    [onSelectionChange]
  );

  const handleCheck = useCallback(
    (index: number, id: string, e: React.MouseEvent) => {
      const next = new Set(selectedRef.current);
      if (e.shiftKey && lastCheckedRef.current !== null) {
        const start = Math.min(lastCheckedRef.current, index);
        const end = Math.max(lastCheckedRef.current, index);
        displayRows.slice(start, end + 1).forEach((r) => next.add(getRowId(r)));
      } else if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      lastCheckedRef.current = index;
      applySelection(next);
    },
    [displayRows, getRowId, applySelection]
  );

  const allShownSelected =
    displayRows.length > 0 && displayRows.every((r) => selected.has(getRowId(r)));
  const toggleSelectAll = useCallback(() => {
    const next = new Set(selectedRef.current);
    if (allShownSelected) displayRows.forEach((r) => next.delete(getRowId(r)));
    else displayRows.forEach((r) => next.add(getRowId(r)));
    applySelection(next);
  }, [allShownSelected, displayRows, getRowId, applySelection]);

  // --- Chrome ---

  useEffect(() => {
    if (!menuOpen) return;
    const onDown = (e: MouseEvent) => {
      if (!menuRef.current?.contains(e.target as Node)) setMenuOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [menuOpen]);

  const virtualizer = useVirtualizer({
    count: displayRows.length,
    getScrollElement: () => scroller.current,
    estimateSize: () => rowHeight,
    overscan: 15,
    getItemKey: (i) => (displayRows[i] ? getRowId(displayRows[i]) : i),
  });
  const virtualItems = virtualizer.getVirtualItems();

  // Infinite scroll near the end; with client filters active also backfill pages
  // until enough matches accumulate — those filters only see loaded rows, so a
  // sparse match rate would otherwise stall with a near-empty table.
  useEffect(() => {
    if (!hasNextPage || isFetchingNextPage || !fetchNextPage) return;
    const last = virtualItems[virtualItems.length - 1];
    const nearEnd = last != null && last.index >= displayRows.length - 10;
    const backfilling = anyClientFilterActive && displayRows.length < 50;
    if (nearEnd || backfilling) fetchNextPage();
  }, [
    virtualItems,
    displayRows.length,
    hasNextPage,
    isFetchingNextPage,
    fetchNextPage,
    anyClientFilterActive,
  ]);

  const pluralNoun = nounPlural ?? `${noun}s`;
  const plural = rows.length === 1 ? noun : pluralNoun;

  return (
    <div className={styles.container}>
      <div className={styles.tableBar}>
        <span className={styles.tableInfo}>
          {anyClientFilterActive
            ? `${displayRows.length.toLocaleString()} of ${rows.length.toLocaleString()} loaded`
            : `${rows.length.toLocaleString()} ${plural} loaded`}
          {totalCount != null && ` · ${totalCount.toLocaleString()} total`}
          {anyClientFilterActive && hasNextPage && " · loading more…"}
        </span>
        <div className={styles.tableBarRight}>
          {toolbar}
          {anyFilterActive && (
            <button type="button" className={styles.barBtn} onClick={handleClearFilters}>
              Clear filters
            </button>
          )}
          <div className={styles.columnsMenuWrap} ref={menuRef}>
            <button className={styles.barBtn} onClick={() => setMenuOpen((o) => !o)}>
              Columns <span className="caret-glyph">▾</span>
            </button>
            {menuOpen && (
              <div className={styles.columnsMenu}>
                {orderedColumns
                  .filter((c) => c.hideable)
                  .map((c) => (
                    <label key={c.key} className={styles.columnsMenuItem}>
                      <input
                        type="checkbox"
                        checked={isColVisible(c)}
                        onChange={() => setColumnVisible(tableId, c.key, !isColVisible(c))}
                      />
                      {c.label}
                    </label>
                  ))}
                <span className={styles.columnsMenuHint}>
                  Drag headers to reorder · choices, order &amp; widths save automatically
                </span>
                <button
                  className={styles.columnsMenuReset}
                  onClick={() => {
                    resetLayout(tableId);
                    setMenuOpen(false);
                  }}
                >
                  Reset to defaults
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className={styles.scroller} ref={scroller}>
        <div className={styles.inner} style={{ minWidth: minTableWidth }}>
          <div className={styles.headerRow} style={{ gridTemplateColumns: gridTemplate }}>
            {selectable && (
              <div className={`${styles.headerCell} ${styles.selectCell}`}>
                <input
                  type="checkbox"
                  className={styles.headerCheckbox}
                  aria-label="Select all loaded rows"
                  checked={allShownSelected}
                  onChange={toggleSelectAll}
                />
              </div>
            )}
            {visibleCols.map((col) => {
              const dir = sortIndicator(col);
              const sortable = !!((col.serverSort && onSortChange) || col.sortValue || col.numValue);
              return (
                <Hint
                  key={col.key}
                  title={col.hint?.title ?? col.label}
                  body={col.hint?.body ?? ""}
                  aside={col.hint?.aside}
                  disabled={!col.hint}
                >
                <div
                  className={`${styles.headerCell} ${sortable ? styles.sortable : ""} ${
                    col.sticky === "right" ? styles.stickyRight : ""
                  } ${dragKey === col.key ? styles.dragging : ""} ${
                    dropKey === col.key && dragKey !== col.key ? styles.dragOver : ""
                  }`}
                  onClick={sortable ? () => handleSort(col) : undefined}
                  title={
                    col.hint
                      ? undefined
                      : col.sticky
                        ? col.label
                        : sortable
                          ? `Sort by ${col.label} — drag to reorder`
                          : "Drag to reorder"
                  }
                  draggable={!col.sticky}
                  onDragStart={(e) => {
                    setDragKey(col.key);
                    e.dataTransfer.effectAllowed = "move";
                    e.dataTransfer.setData("text/plain", col.key);
                  }}
                  onDragOver={(e) => {
                    if (!dragKey) return;
                    e.preventDefault();
                    e.dataTransfer.dropEffect = "move";
                    setDropKey(col.key);
                  }}
                  onDragLeave={() => {
                    if (dropKey === col.key) setDropKey(null);
                  }}
                  onDrop={(e) => {
                    e.preventDefault();
                    handleHeaderDrop(col.key);
                  }}
                  onDragEnd={() => {
                    setDragKey(null);
                    setDropKey(null);
                  }}
                >
                  <span className={styles.ellipsis}>{col.label}</span>
                  {dir && <span className={styles.sortArrow}>{dir === "asc" ? "↑" : "↓"}</span>}
                  <span
                    className={styles.resizeHandle}
                    onPointerDown={(e) => onResizeStart(e, col)}
                    onClick={(e) => e.stopPropagation()}
                    onDragStart={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                    }}
                  />
                </div>
                </Hint>
              );
            })}
          </div>

          <div className={styles.filterRow} style={{ gridTemplateColumns: gridTemplate }}>
            {selectable && <div className={styles.filterCell} />}
            {visibleCols.map((col) => (
              <div
                key={col.key}
                className={`${styles.filterCell} ${col.sticky === "right" ? styles.stickyRight : ""}`}
              >
                {col.choices ? (
                  <select
                    className={styles.filterSelect}
                    value={choiceFilters[col.key] ?? ALL}
                    onChange={(e) => setChoiceFilter(tableId, col.key, e.target.value)}
                  >
                    {col.choices.map((o) => (
                      <option key={o.value} value={o.value}>
                        {o.label}
                      </option>
                    ))}
                  </select>
                ) : col.textValue || col.serverText ? (
                  <input
                    className={styles.filterInput}
                    placeholder={col.serverText ? "Search…" : "Filter…"}
                    value={textFilters[col.key] ?? ""}
                    onChange={(e) => setTextFilter(tableId, col.key, e.target.value)}
                  />
                ) : col.numValue ? (
                  <button
                    className={`${styles.hasBtn} ${hasFilters[col.key] ? styles.hasBtnActive : ""}`}
                    onClick={() => setHasFilter(tableId, col.key, !hasFilters[col.key])}
                    title={`Only rows with ${col.label}`}
                  >
                    &gt;0
                  </button>
                ) : null}
              </div>
            ))}
          </div>

          {isLoading && <TableSkeleton columns={Math.min(visibleCols.length, 8)} rows={14} />}

          <div className={styles.body} style={{ height: virtualizer.getTotalSize() }}>
            {virtualItems.map((vi) => {
              const row = displayRows[vi.index];
              if (!row) return null;
              const id = getRowId(row);
              const isChecked = selected.has(id);
              return (
                <div
                  key={id}
                  className={styles.rowWrap}
                  style={{ transform: `translateY(${vi.start}px)`, height: rowHeight }}
                >
                  <RowView
                    gridTemplate={gridTemplate}
                    className={[
                      styles.row,
                      rowClass?.(row),
                      activeRowId === id ? styles.rowSelected : "",
                      isChecked ? styles.rowChecked : "",
                      bulkMode ? styles.rowBulk : "",
                      onRowClick ? styles.rowClickable : "",
                    ]
                      .filter(Boolean)
                      .join(" ")}
                    onClick={onRowClick ? () => onRowClick(row) : undefined}
                    selectCell={
                      selectable ? (
                        <div
                          key={SELECT_KEY}
                          className={`${styles.cell} ${styles.selectCell}`}
                          onClick={(e) => {
                            e.stopPropagation();
                            handleCheck(vi.index, id, e);
                          }}
                        >
                          <input
                            type="checkbox"
                            className={styles.checkbox}
                            aria-label="Select row"
                            checked={isChecked}
                            onChange={() => {}}
                            tabIndex={-1}
                          />
                        </div>
                      ) : null
                    }
                    cells={visibleCols.map((c) => (
                      <div
                        key={c.key}
                        className={`${styles.cell} ${c.sticky === "right" ? styles.stickyRight : ""}`}
                      >
                        {c.render(row)}
                      </div>
                    ))}
                  />
                </div>
              );
            })}
          </div>

          {isFetchingNextPage && <div className={styles.loading}>Loading more…</div>}
          {!isLoading && displayRows.length === 0 && (
            <div className={styles.empty} role="status">
              {anyFilterActive ? (
                // A filter is on, so this is "no matches", not "no data" — never
                // tell someone to go create rows they may already have.
                <div className={styles.emptyFiltered}>
                  <p className={styles.emptyFilteredTitle}>No {pluralNoun} match these filters</p>
                  {activeFilterSummary.length > 0 && (
                    <p className={styles.emptyFilteredDetail}>
                      Filtering by {activeFilterSummary.join(" · ")}
                    </p>
                  )}
                  <button
                    type="button"
                    className={styles.emptyClearBtn}
                    onClick={handleClearFilters}
                  >
                    Clear filters
                  </button>
                </div>
              ) : (
                (emptyState ?? emptyMessage)
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
