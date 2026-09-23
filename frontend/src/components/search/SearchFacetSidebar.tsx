import { useMemo, useState } from "react";
import type { EntitySearchResult } from "@/api/types";
import type { ParsedFilter } from "@/utils/queryParser";
import type { SearchScope } from "@/stores/uiStore";
import { getEntityColor } from "@/utils/entityTheme";
import { FacetSection } from "@/components/primitives";
import { ENTITY_TYPE_LABELS, getSearchResultName } from "./EntityResults";
import styles from "./SearchFacetSidebar.module.css";

export type MatchKind = "direct" | "mention";

/**
 * A facet the sidebar drives by editing the query string rather than by holding
 * local state. `field` is the query-language field (`feed`, `tag`, `is`, ...),
 * so toggling a row produces `feed:"Bleeping Computer"` in the search box — the
 * user can see it, edit it by hand, and save it as a saved search.
 */
interface EntryFacetGroup {
  /** Query-language field this group writes. */
  field: string;
  label: string;
  /** Meilisearch facetDistribution key backing it, when it has one. */
  distributionKey?: string;
  /** Fixed rows, for groups the index can't enumerate (state, date). */
  fixed?: Array<{ value: string; label: string }>;
  /** Rows shown before "Show all"; only applies to distribution-backed groups. */
  cap?: number;
  /** Render a filter box once the group exceeds this many rows. */
  searchable?: boolean;
}

const SCOPES: Array<{ value: SearchScope; label: string; hint: string }> = [
  { value: "everything", label: "Everything", hint: "Entities and articles" },
  { value: "workbench", label: "Workbench", hint: "Entities only" },
  { value: "feeds", label: "Feeds", hint: "Articles only" },
];

// Date facets are relative, so their query value is computed at click time.
const DATE_RANGES: Array<{ key: string; label: string; days: number }> = [
  { key: "24h", label: "Last 24 hours", days: 1 },
  { key: "7d", label: "Last 7 days", days: 7 },
  { key: "30d", label: "Last 30 days", days: 30 },
  { key: "1y", label: "Last year", days: 365 },
];

/**
 * The query-language field each entity type filters through, so clicking a
 * threat actor in the rail writes `threat_actor:"LockBit"` — the same
 * mechanism the Feed facet uses, and equally hand-editable afterwards.
 */
const ENTITY_FACET_FIELD: Record<string, string> = {
  threat_actor: "threat_actor",
  malware: "malware",
  cve: "cve",
  ttp: "ttp",
  tool: "tool",
  vendor: "vendor",
  product: "product",
  country: "country",
  mitigation: "mitigation",
  cwe: "cwe",
  detection_rule: "rule",
  campaign: "campaign",
  intel_report: "intel_report",
  ransomware_victim: "ransomware_victim",
};

const ENTRY_FACETS: EntryFacetGroup[] = [
  {
    field: "is",
    label: "State",
    fixed: [
      { value: "unread", label: "Unread" },
      { value: "starred", label: "Starred" },
      { value: "bookmarked", label: "Bookmarked" },
      { value: "noted", label: "Has notes" },
    ],
  },
  { field: "feed", label: "Feed", distributionKey: "feed_title", cap: 8, searchable: true },
  { field: "type", label: "Content type", distributionKey: "feed_type", cap: 8 },
  { field: "tag", label: "Tags", distributionKey: "tags", cap: 8, searchable: true },
  { field: "media", label: "Media", distributionKey: "media_type", cap: 5 },
  { field: "lang", label: "Language", distributionKey: "language", cap: 5 },
];

interface Props {
  scope: SearchScope;
  onScopeChange: (scope: SearchScope) => void;

  /** True per-type totals from the server, not the trimmed payload's length. */
  entityCounts: Record<string, number>;
  /** The matched entities themselves, offered as value facets per type. */
  entities: EntitySearchResult[];
  activeEntityType: string | null;
  onEntityTypeChange: (type: string | null) => void;
  matchKinds: Set<MatchKind>;
  onToggleMatchKind: (kind: MatchKind) => void;
  directCount: number;
  mentionCount: number;

  entryTotal: number;
  facetDistribution?: Record<string, Record<string, number>> | null;
  /** Filters currently in the query, for checked state and for removal. */
  filters: ParsedFilter[];
  onToggleFilter: (field: string, value: string) => void;
  onSetDateFilter: (days: number | null) => void;
  activeDateDays: number | null;
  onClearFilters: () => void;
}

export function SearchFacetSidebar({
  scope,
  onScopeChange,
  entityCounts,
  entities,
  activeEntityType,
  onEntityTypeChange,
  matchKinds,
  onToggleMatchKind,
  directCount,
  mentionCount,
  entryTotal,
  facetDistribution,
  filters,
  onToggleFilter,
  onSetDateFilter,
  activeDateDays,
  onClearFilters,
}: Props) {
  const showIntel = scope !== "feeds";
  const showEntries = scope !== "workbench";

  const entityRows = useMemo(
    () =>
      Object.entries(entityCounts)
        .filter(([, n]) => n > 0)
        .sort((a, b) => b[1] - a[1]),
    [entityCounts],
  );
  const entityTotal = entityRows.reduce((sum, [, n]) => sum + n, 0);

  const activeFilterCount = filters.length;

  return (
    <div className={styles.rail}>
      <div className={styles.group}>
        <div className={styles.groupTitle}>Search in</div>
        {SCOPES.map((s) => (
          <button
            key={s.value}
            className={`${styles.row} ${scope === s.value ? styles.rowOn : ""}`}
            onClick={() => onScopeChange(s.value)}
            aria-pressed={scope === s.value}
          >
            <span className={`${styles.radio} ${scope === s.value ? styles.radioOn : ""}`} />
            <span className={styles.rowLabel}>{s.label}</span>
            <span className={styles.rowHint}>{s.hint}</span>
          </button>
        ))}
      </div>

      {showIntel && (
        <>
          <div className={styles.group}>
            <div className={styles.groupTitle}>Entity type</div>
            <button
              className={`${styles.row} ${activeEntityType === null ? styles.rowOn : ""}`}
              onClick={() => onEntityTypeChange(null)}
            >
              <span className={styles.dot} style={{ background: "var(--text-muted)" }} />
              <span className={styles.rowLabel}>All types</span>
              <span className={styles.count}>{entityTotal}</span>
            </button>
            {entityRows.map(([type, n]) => (
              <button
                key={type}
                className={`${styles.row} ${activeEntityType === type ? styles.rowOn : ""}`}
                onClick={() => onEntityTypeChange(activeEntityType === type ? null : type)}
              >
                <span className={styles.dot} style={{ background: getEntityColor(type) }} />
                <span className={styles.rowLabel}>{ENTITY_TYPE_LABELS[type] || type}</span>
                <span className={styles.count}>{n}</span>
              </button>
            ))}
            {entityRows.length === 0 && <div className={styles.empty}>No entities matched</div>}
          </div>

          {/* Entity value facets, one group per type present — the intelligence
              equivalent of the Feed list below, so a broad search can be
              narrowed to a specific actor or family without retyping it. */}
          {entityRows.map(([type]) => (
            <EntityValueFacet
              key={type}
              type={type}
              field={ENTITY_FACET_FIELD[type]}
              entities={entities}
              filters={filters}
              onToggle={onToggleFilter}
            />
          ))}

          <div className={styles.group}>
            {/* The API says which column matched; this turns that into the one
                distinction that actually changes how a result should be read. */}
            <div className={styles.groupTitle}>Matched on</div>
            <button
              className={`${styles.row} ${matchKinds.has("direct") ? styles.rowOn : ""}`}
              onClick={() => onToggleMatchKind("direct")}
            >
              <span className={`${styles.check} ${matchKinds.has("direct") ? styles.checkOn : ""}`} />
              <span className={styles.rowLabel}>Name or alias</span>
              <span className={styles.count}>{directCount}</span>
            </button>
            <button
              className={`${styles.row} ${matchKinds.has("mention") ? styles.rowOn : ""}`}
              onClick={() => onToggleMatchKind("mention")}
            >
              <span className={`${styles.check} ${matchKinds.has("mention") ? styles.checkOn : ""}`} />
              <span className={styles.rowLabel}>Mentioned in text</span>
              <span className={styles.count}>{mentionCount}</span>
            </button>
          </div>
        </>
      )}

      {showEntries && (
        <>
          <div className={styles.group}>
            <div className={styles.groupTitle}>
              Published
              <span className={styles.groupTotal}>{entryTotal.toLocaleString()} articles</span>
            </div>
            {DATE_RANGES.map((r) => (
              <button
                key={r.key}
                className={`${styles.row} ${activeDateDays === r.days ? styles.rowOn : ""}`}
                onClick={() => onSetDateFilter(activeDateDays === r.days ? null : r.days)}
              >
                <span className={`${styles.radio} ${activeDateDays === r.days ? styles.radioOn : ""}`} />
                <span className={styles.rowLabel}>{r.label}</span>
              </button>
            ))}
          </div>

          {ENTRY_FACETS.map((facet) => (
            <EntryFacetSection
              key={facet.field}
              facet={facet}
              distribution={facet.distributionKey ? facetDistribution?.[facet.distributionKey] : undefined}
              filters={filters}
              onToggle={onToggleFilter}
            />
          ))}
        </>
      )}

      {activeFilterCount > 0 && (
        <div className={styles.footer}>
          <button className={styles.clearBtn} onClick={onClearFilters}>
            Clear {activeFilterCount} filter{activeFilterCount === 1 ? "" : "s"}
          </button>
        </div>
      )}
    </div>
  );
}

function EntryFacetSection({
  facet,
  distribution,
  filters,
  onToggle,
}: {
  facet: EntryFacetGroup;
  distribution?: Record<string, number>;
  filters: ParsedFilter[];
  onToggle: (field: string, value: string) => void;
}) {
  const active = useMemo(
    () => new Set(filters.filter((f) => f.field === facet.field && !f.negated).map((f) => f.value.toLowerCase())),
    [filters, facet.field],
  );

  const rows = useMemo(() => {
    if (facet.fixed) return facet.fixed.map((r) => ({ value: r.value, label: r.label }));
    return Object.entries(distribution ?? {})
      .filter(([, n]) => n > 0)
      .sort((a, b) => b[1] - a[1])
      .map(([value, count]) => ({ value, label: value, count }));
  }, [facet.fixed, distribution]);

  return (
    <FacetSection
      label={facet.label}
      rows={rows}
      active={active}
      onToggle={(value) => onToggle(facet.field, value)}
      cap={facet.cap}
      searchable={facet.searchable}
    />
  );
}


/**
 * One entity type's matched values, as a filter list.
 *
 * Counts are the entity's linked-article count where it has one — the same
 * number the result row shows — so the rail reads consistently with the stream
 * rather than inventing its own tally.
 */
function EntityValueFacet({
  type,
  field,
  entities,
  filters,
  onToggle,
}: {
  type: string;
  field?: string;
  entities: EntitySearchResult[];
  filters: ParsedFilter[];
  onToggle: (field: string, value: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [needle, setNeedle] = useState("");
  const CAP = 6;

  const rows = useMemo(
    () =>
      entities
        .filter((e) => e.type === type)
        .map((e) => ({ value: getSearchResultName(e), count: e.article_count ?? null }))
        .filter((r) => r.value)
        .sort((a, b) => (b.count ?? 0) - (a.count ?? 0)),
    [entities, type],
  );

  const active = useMemo(
    () =>
      new Set(
        filters.filter((f) => f.field === field && !f.negated).map((f) => f.value.toLowerCase()),
      ),
    [filters, field],
  );

  const filtered = useMemo(() => {
    if (!needle.trim()) return rows;
    const n = needle.trim().toLowerCase();
    return rows.filter((r) => r.value.toLowerCase().includes(n) || active.has(r.value.toLowerCase()));
  }, [rows, needle, active]);

  if (!field || rows.length === 0) return null;

  const capped = expanded || filtered.length <= CAP;
  const visible = capped
    ? filtered
    : [...filtered.slice(0, CAP), ...filtered.slice(CAP).filter((r) => active.has(r.value.toLowerCase()))];

  return (
    <div className={styles.group}>
      <div className={styles.groupTitle}>
        <span className={styles.dot} style={{ background: getEntityColor(type) }} />
        {ENTITY_TYPE_LABELS[type] || type}
      </div>
      {rows.length > CAP && (
        <input
          className={styles.facetSearch}
          value={needle}
          onChange={(e) => setNeedle(e.target.value)}
          placeholder={`Filter ${(ENTITY_TYPE_LABELS[type] || type).toLowerCase()}…`}
        />
      )}
      {visible.map((row) => {
        const on = active.has(row.value.toLowerCase());
        return (
          <button
            key={row.value}
            className={`${styles.row} ${on ? styles.rowOn : ""}`}
            onClick={() => onToggle(field, row.value)}
            title={row.value}
          >
            <span className={`${styles.check} ${on ? styles.checkOn : ""}`} />
            <span className={styles.rowLabel}>{row.value}</span>
            {row.count != null && row.count > 0 && (
              <span className={styles.count}>{row.count.toLocaleString()}</span>
            )}
          </button>
        );
      })}
      {!capped && (
        <button className={styles.moreBtn} onClick={() => setExpanded(true)}>
          Show all {filtered.length}
        </button>
      )}
      {expanded && filtered.length > CAP && (
        <button className={styles.moreBtn} onClick={() => setExpanded(false)}>
          Show fewer
        </button>
      )}
    </div>
  );
}
