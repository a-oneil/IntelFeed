import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";

import type { EntityRelationship } from "@/api/types";
import { entityProfilePath } from "@/components/entityProfile/entityProfileConfig";
import {
  useConfirmRelationship,
  useDeleteRelationship,
  useRejectRelationship,
} from "@/hooks/useRelationships";
import {
  useAllRelationships,
  useBulkUnlink,
  useEntityLinkStats,
  useEntityLinks,
  useUnlink,
  type EntityLink,
  type LinkRef,
} from "@/hooks/useAutolinking";
import type { EntityType } from "@/stores/intelStore";
import { getEntityCssVar, getEntityLabel } from "@/utils/entityTheme";

import styles from "./AutolinkingSection.module.css";

type View = "links" | "relationships";

const PAGE = 25;

// The seven entity types the autolinker writes junction rows for.
const LINK_TYPES = ["threat_actor", "malware", "tool", "vendor", "product", "ttp", "cve"];
// Labels for the raw junction `source` values.
const SOURCE_LABELS: Record<string, string> = {
  auto_link: "Autolinker",
  ai: "AI extraction",
  ai_reconcile: "AI reconcile",
  auto_extracted: "Auto-extracted",
  manual: "Analyst",
  unattributed: "Unattributed",
};

const MONO_TYPES = new Set(["cve", "ttp"]);

function Ico({ d, size = 14 }: { d: string; size?: number }) {
  return (
    <svg className={styles.ico} viewBox="0 0 24 24" width={size} height={size} aria-hidden>
      <path d={d} />
    </svg>
  );
}
const ICON = {
  pivot: "M7 17 17 7M8 7h9v9",
  unlink: "M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6",
  check: "M20 6 9 17l-5-5",
  x: "M18 6 6 18M6 6l12 12",
  graph: "M6 6a3 3 0 1 0 0 .01M18 18a3 3 0 1 0 0 .01M8.5 8.5 15.5 15.5",
  search: "M11 4a7 7 0 1 0 .01 0M21 21l-4.3-4.3",
};

function confidenceBars(level: string | null) {
  const l = (level ?? "").toLowerCase();
  const strong = new Set(["high", "confirmed"]);
  const mid = new Set(["medium", "probable"]);
  let cls = "";
  let filled = 0;
  if (strong.has(l)) {
    cls = styles.barGood;
    filled = 3;
  } else if (mid.has(l)) {
    cls = styles.barWarn;
    filled = 2;
  } else if (l) {
    cls = styles.barCrit;
    filled = 1;
  }
  return (
    <span className={styles.conf}>
      <span className={styles.bars}>
        {[0, 1, 2].map((i) => (
          <i key={i} className={i < filled ? cls : undefined} />
        ))}
      </span>
      {level ?? "—"}
    </span>
  );
}

function sourcePill(source: string | null) {
  const s = source ?? "";
  let cls = styles.srcNeutral;
  if (s === "auto_link") cls = styles.srcAuto;
  else if (s === "ai" || s === "ai_reconcile") cls = styles.srcAi;
  else if (s === "manual" || s.startsWith("analyst")) cls = styles.srcAnalyst;
  return <span className={`${styles.pill} ${cls}`}>{SOURCE_LABELS[s] ?? s ?? "—"}</span>;
}

/** Clickable entity chip that navigates to the specific entity's profile. */
function EntityChipLink({ type, id, name }: { type: string; id: string; name: string | null | undefined }) {
  const navigate = useNavigate();
  return (
    <button
      className={styles.ent}
      title={`Open ${getEntityLabel(type)} profile`}
      onClick={() => navigate(entityProfilePath(type as EntityType, id))}
    >
      <span className={styles.entDot} style={{ background: getEntityCssVar(type) }} />
      <span className={`${styles.entName} ${MONO_TYPES.has(type) ? styles.entMono : ""}`}>
        {name ?? "(unknown)"}
      </span>
      <span className={styles.etype}>{getEntityLabel(type)}</span>
    </button>
  );
}

const linkKey = (l: EntityLink | LinkRef) => `${l.entity_type}|${l.entity_id}|${l.entry_id}`;

export function AutolinkingSection({
  embedded = false,
  view: viewProp,
}: {
  /** Render inside the Engine console card: no KPI tiles, no view toggle
   *  (the parent's tabs control links vs relationships). */
  embedded?: boolean;
  view?: View;
}) {
  const navigate = useNavigate();
  const [view, setView] = useState<View>(viewProp ?? "links");

  useEffect(() => {
    if (viewProp) setView(viewProp);
  }, [viewProp]);
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [entityType, setEntityType] = useState("");
  const [source, setSource] = useState("");
  const [confidence, setConfidence] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  // Debounce the search box into the query param.
  useEffect(() => {
    const t = setTimeout(() => setSearch(searchInput.trim()), 300);
    return () => clearTimeout(t);
  }, [searchInput]);

  // Reset paging + selection whenever the query changes.
  useEffect(() => {
    setOffset(0);
    setSelected(new Set());
  }, [view, search, entityType, source, confidence]);

  const { data: stats } = useEntityLinkStats();
  const linksQuery = useEntityLinks({
    entity_type: entityType || undefined,
    source: source || undefined,
    confidence: confidence || undefined,
    search: search || undefined,
    limit: PAGE,
    offset,
  });
  const relsQuery = useAllRelationships({
    entity_type: entityType || undefined,
    limit: PAGE,
    offset,
  });

  const unlink = useUnlink();
  const bulkUnlink = useBulkUnlink();
  const confirmRel = useConfirmRelationship();
  const rejectRel = useRejectRelationship();
  const deleteRel = useDeleteRelationship();

  const active = view === "links" ? linksQuery : relsQuery;
  const total = active.data?.total ?? 0;
  const items = useMemo(() => active.data?.items ?? [], [active.data]);

  const toggle = (key: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  const toggleAll = (keys: string[]) =>
    setSelected((prev) => (keys.every((k) => prev.has(k)) ? new Set() : new Set(keys)));

  const pageKeys = useMemo(
    () =>
      view === "links"
        ? (items as EntityLink[]).map(linkKey)
        : (items as EntityRelationship[]).map((r) => r.id),
    [items, view],
  );
  const allSelected = pageKeys.length > 0 && pageKeys.every((k) => selected.has(k));

  async function doBulkUnlink() {
    const refs: LinkRef[] = (items as EntityLink[])
      .filter((l) => selected.has(linkKey(l)))
      .map((l) => ({ entity_type: l.entity_type, entity_id: l.entity_id, entry_id: l.entry_id }));
    if (!refs.length) return;
    const { deleted } = await bulkUnlink.mutateAsync(refs);
    toast.success(`Unlinked ${deleted} link${deleted === 1 ? "" : "s"}`);
    setSelected(new Set());
  }

  async function doBulkRel(action: "confirm" | "reject" | "delete") {
    const ids = (items as EntityRelationship[]).filter((r) => selected.has(r.id)).map((r) => r.id);
    if (!ids.length) return;
    const fn = action === "confirm" ? confirmRel : action === "reject" ? rejectRel : deleteRel;
    await Promise.all(ids.map((id) => fn.mutateAsync(id)));
    toast.success(`${action[0].toUpperCase()}${action.slice(1)}ed ${ids.length} relationship${ids.length === 1 ? "" : "s"}`);
    setSelected(new Set());
  }

  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + PAGE, total);

  return (
    <div className={styles.wrap}>
      {/* KPI row + view toggle — standalone only; the Engine console renders
          its own healthline/tabs when embedding this table. */}
      {!embedded && (
        <>
          <div className={styles.kpis}>
            <Kpi cap="Total links" val={stats?.total} sub="across 7 entity types" color="var(--accent)" />
            <Kpi cap="Autolinker" val={stats?.by_source?.auto_link} sub="dictionary-matched" color="var(--accent)" />
            <Kpi
              cap="AI-extracted"
              val={(stats?.by_source?.ai ?? 0) + (stats?.by_source?.ai_reconcile ?? 0)}
              sub="one-pass + reconcile"
              color="var(--entity-malware)"
            />
            <Kpi cap="Analyst" val={stats?.by_source?.manual} sub="manually linked" color="var(--success)" />
            <Kpi cap="Pending links" val={stats?.pending} sub="held for confirmation" color="var(--warning)" />
            <Kpi cap="Relationships" val={stats?.relationships_total} sub="entity → entity edges" color="var(--entity-ttp)" />
          </div>

          <div className={styles.segRow}>
            <div className={styles.seg}>
              <button
                className={view === "links" ? styles.segOn : ""}
                onClick={() => setView("links")}
              >
                Entity links <span className={styles.segCnt}>{stats ? stats.total.toLocaleString() : "—"}</span>
              </button>
              <button
                className={view === "relationships" ? styles.segOn : ""}
                onClick={() => setView("relationships")}
              >
                Relationships{" "}
                <span className={styles.segCnt}>{stats ? stats.relationships_total.toLocaleString() : "—"}</span>
              </button>
            </div>
            <span className={styles.rangeNote}>
              {view === "links"
                ? "Entry → entity autolinks · newest first"
                : "Entity → entity relationships · newest first"}
            </span>
          </div>
        </>
      )}

      {/* filters */}
      <div className={styles.filters}>
        <span className={styles.search}>
          <Ico d={ICON.search} />
          <input
            placeholder={view === "links" ? "Search entity or entry title…" : "Filter relationships…"}
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            disabled={view === "relationships"}
          />
        </span>
        <select className={styles.filt} value={entityType} onChange={(e) => setEntityType(e.target.value)}>
          <option value="">All entity types</option>
          {LINK_TYPES.map((t) => (
            <option key={t} value={t}>
              {getEntityLabel(t)}
            </option>
          ))}
        </select>
        {view === "links" && (
          <>
            <select className={styles.filt} value={source} onChange={(e) => setSource(e.target.value)}>
              <option value="">Any source</option>
              {Object.entries(SOURCE_LABELS).map(([k, v]) => (
                <option key={k} value={k}>
                  {v}
                </option>
              ))}
            </select>
            <select className={styles.filt} value={confidence} onChange={(e) => setConfidence(e.target.value)}>
              <option value="">Any confidence</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </>
        )}
      </div>

      {/* bulk bar */}
      {selected.size > 0 && (
        <div className={styles.bulk}>
          <span className={styles.bulkN}>{selected.size} selected</span>
          <div className={styles.bulkGrp}>
            {view === "links" ? (
              <button className={`${styles.btn} ${styles.btnDanger}`} onClick={doBulkUnlink} disabled={bulkUnlink.isPending}>
                <Ico d={ICON.unlink} /> Unlink
              </button>
            ) : (
              <>
                <button className={`${styles.btn} ${styles.btnGood}`} onClick={() => doBulkRel("confirm")}>
                  <Ico d={ICON.check} /> Confirm
                </button>
                <button className={styles.btn} onClick={() => doBulkRel("reject")}>
                  <Ico d={ICON.x} /> Reject
                </button>
                <button className={`${styles.btn} ${styles.btnDanger}`} onClick={() => doBulkRel("delete")}>
                  <Ico d={ICON.unlink} /> Delete
                </button>
              </>
            )}
          </div>
        </div>
      )}

      {/* table */}
      <div className={styles.tableWrap}>
        <div className={styles.scroll}>
          {view === "links" ? (
            <table className={styles.table}>
              <thead>
                <tr>
                  <th className={styles.colCheck}>
                    <input type="checkbox" checked={allSelected} onChange={() => toggleAll(pageKeys)} />
                  </th>
                  <th>Entity</th>
                  <th>Matched as</th>
                  <th>Entry</th>
                  <th>Source</th>
                  <th>Confidence</th>
                  <th>¶</th>
                  <th>Linked</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {(items as EntityLink[]).map((l) => {
                  const key = linkKey(l);
                  return (
                    <tr key={key} className={selected.has(key) ? styles.rowSel : ""}>
                      <td className={styles.colCheck}>
                        <input type="checkbox" checked={selected.has(key)} onChange={() => toggle(key)} />
                      </td>
                      <td>
                        <EntityChipLink type={l.entity_type} id={l.entity_id} name={l.entity_name} />
                      </td>
                      <td>
                        {l.matched_names?.length ? (
                          <span className={styles.matched}>
                            {l.matched_names.map((m) => (
                              <span key={m} className={styles.surf}>
                                {m}
                              </span>
                            ))}
                          </span>
                        ) : (
                          <span className={styles.muted}>—</span>
                        )}
                      </td>
                      <td>
                        <span className={styles.entry} title={l.entry_title ?? ""}>
                          {l.entry_title ?? "(untitled)"}
                        </span>
                      </td>
                      <td>{sourcePill(l.source)}</td>
                      <td>{confidenceBars(l.confidence)}</td>
                      <td className={styles.para}>{l.paragraph_indices?.join(", ") || "—"}</td>
                      <td className={styles.muted}>{new Date(l.extracted_at).toLocaleDateString()}</td>
                      <td>
                        <div className={styles.rowActs}>
                          <button
                            className={`${styles.iact} ${styles.iactAccent}`}
                            title="Open entity profile"
                            onClick={() => navigate(entityProfilePath(l.entity_type as EntityType, l.entity_id))}
                          >
                            <Ico d={ICON.pivot} />
                          </button>
                          <button
                            className={`${styles.iact} ${styles.iactDanger}`}
                            title="Unlink"
                            onClick={async () => {
                              await unlink.mutateAsync({
                                entity_type: l.entity_type,
                                entity_id: l.entity_id,
                                entry_id: l.entry_id,
                              });
                              toast.success("Link removed");
                            }}
                          >
                            <Ico d={ICON.unlink} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : (
            <table className={styles.table}>
              <thead>
                <tr>
                  <th className={styles.colCheck}>
                    <input type="checkbox" checked={allSelected} onChange={() => toggleAll(pageKeys)} />
                  </th>
                  <th>Source</th>
                  <th>Relationship</th>
                  <th>Target</th>
                  <th>Confidence</th>
                  <th>Origin</th>
                  <th>Evidence</th>
                  <th>Created</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {(items as EntityRelationship[]).map((r) => (
                  <tr key={r.id} className={selected.has(r.id) ? styles.rowSel : ""}>
                    <td className={styles.colCheck}>
                      <input type="checkbox" checked={selected.has(r.id)} onChange={() => toggle(r.id)} />
                    </td>
                    <td>
                      <EntityChipLink type={r.source_type} id={r.source_id} name={r.source_name} />
                    </td>
                    <td>
                      <span className={styles.verb}>{r.relationship_type}</span>
                    </td>
                    <td>
                      <EntityChipLink type={r.target_type} id={r.target_id} name={r.target_name} />
                    </td>
                    <td>{confidenceBars(r.confidence)}</td>
                    <td>{sourcePill(r.source)}</td>
                    <td className={styles.ev}>
                      <b>{r.evidence_entry_ids?.length ?? 0}</b>{" "}
                      {(r.evidence_entry_ids?.length ?? 0) === 1 ? "entry" : "entries"}
                    </td>
                    <td className={styles.muted}>{new Date(r.created_at).toLocaleDateString()}</td>
                    <td>
                      <div className={styles.rowActs}>
                        <button
                          className={`${styles.iact} ${styles.iactGood}`}
                          title="Confirm"
                          onClick={async () => {
                            await confirmRel.mutateAsync(r.id);
                            toast.success("Relationship confirmed");
                          }}
                        >
                          <Ico d={ICON.check} />
                        </button>
                        <button
                          className={styles.iact}
                          title="Reject"
                          onClick={async () => {
                            await rejectRel.mutateAsync(r.id);
                            toast.success("Relationship rejected");
                          }}
                        >
                          <Ico d={ICON.x} />
                        </button>
                        <button
                          className={`${styles.iact} ${styles.iactDanger}`}
                          title="Delete"
                          onClick={async () => {
                            await deleteRel.mutateAsync(r.id);
                            toast.success("Relationship deleted");
                          }}
                        >
                          <Ico d={ICON.unlink} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {!active.isLoading && items.length === 0 && (
            <div className={styles.empty}>No {view === "links" ? "links" : "relationships"} match these filters.</div>
          )}
          {active.isLoading && <div className={styles.empty}>Loading…</div>}
        </div>
      </div>

      {/* pending callout (links view only) */}
      {view === "links" && ((stats?.pending ?? 0) > 0 || (stats?.pending_dropped_ai_off ?? 0) > 0) && (
        <div className={styles.pending}>
          <div>
            <h3>{(stats?.pending ?? 0).toLocaleString()} matches held for confirmation</h3>
            <p>
              Dictionary-word hits (like <span className={styles.surf}>Royal</span>{" "}
              <span className={styles.surf}>Hive</span> <span className={styles.surf}>Turkey</span>) are parked in the
              pending tier and won&apos;t become real links until AI or an analyst confirms them.{" "}
              <b>{stats?.pending_ready ?? 0}</b> are ready to auto-promote at high confidence.
              {(stats?.pending_dropped_ai_off ?? 0) > 0 && (
                <>
                  {" "}
                  <b>{stats?.pending_dropped_ai_off?.toLocaleString()}</b> were dropped in the last 30 days because
                  their feed has AI off, so nothing would ever confirm them.
                </>
              )}
            </p>
          </div>
        </div>
      )}

      {/* footer / pager */}
      <div className={styles.foot}>
        <span>
          {total === 0 ? "No results" : `Showing ${from}–${to} of ${total.toLocaleString()}`}
        </span>
        <div className={styles.pager}>
          <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
            ‹ Prev
          </button>
          <button disabled={offset + PAGE >= total} onClick={() => setOffset(offset + PAGE)}>
            Next ›
          </button>
        </div>
      </div>
    </div>
  );
}

function Kpi({ cap, val, sub, color }: { cap: string; val?: number; sub: string; color: string }) {
  return (
    <div className={styles.kpi}>
      <span className={styles.strip} style={{ background: color }} />
      <div className={styles.kpiCap}>{cap}</div>
      <div className={styles.kpiVal}>{val === undefined ? "—" : val.toLocaleString()}</div>
      <div className={styles.kpiSub}>{sub}</div>
    </div>
  );
}
