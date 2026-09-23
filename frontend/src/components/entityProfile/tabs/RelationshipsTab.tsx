/**
 * RelationshipsTab — Direction A: claims & context.
 *
 * Asserted relationships (typed, matrix-valid, trust-graded) group by verb and
 * read as sentences ("APT29 uses → …"); trust is machine-earned (MITRE / AI
 * adjudicator / analyst pin) and shown as the only graded chip. Co-mentions
 * demote to an "appears alongside" chip shelf, specificity-ranked, with
 * ubiquitous reporting vendors folded away. Three controls replace the old
 * six; strength words never appear.
 */
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { useVirtualizer } from "@tanstack/react-virtual";

import api from "@/api/client";
import {
  EntityGraph,
  type CoveringRule,
  type EntityEdge,
  type EntityNode,
  type GraphNodeInfo,
  type GraphStoryCluster,
} from "@/components/EntityGraph";
import { usePivot, useEntityGraph, useUnlinkRelatedEntity } from "@/hooks/useCorrelation";
import {
  useCreateRelationship,
  useConfirmRelationship,
  useRejectRelationship,
} from "@/hooks/useRelationships";
import type { EntityType } from "@/stores/intelStore";
import type { GraphResponse, PivotResponse } from "@/api/types";
import { getEntityColor, getEntityPluralLabel } from "@/utils/entityTheme";
import {
  allowedVerbsForPair,
  buildStoryMap,
  clusterHeading,
  flattenRelated,
  groupByVerb,
  isEverydaySoftware,
  isImplausibleCveId,
  partitionEarned,
  REGION_NAMES,
  RELATED_KEY,
  rowKey,
  splitAssertedContext,
  structurePhrase,
  trustOf,
  TYPE_ORDER,
  type RelRow,
  type VerbGroup,
} from "@/utils/relationshipBrowser";
import { Segmented } from "@/components/primitives";
import { useOpenThread } from "@/utils/openEntry";
import { RelationshipRow } from "../RelationshipRow";
import styles from "../entityProfile.module.css";

const NAV_TYPES = new Set([
  "threat_actor", "malware", "cve", "ttp", "country", "tool", "mitigation", "vendor", "product", "cwe",
]);
const MAX_GRAPH_NODES = 500;
const GROUP_PREVIEW = 12;

type Scope = "claims" | "context";

/** Windowed rendering for long open groups (dynamic row heights measured). */
function VirtualRows({ rows, renderRow }: { rows: RelRow[]; renderRow: (r: RelRow) => ReactNode }) {
  const parentRef = useRef<HTMLDivElement>(null);
  const virt = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 34,
    overscan: 12,
  });
  return (
    <div ref={parentRef} style={{ maxHeight: 480, overflowY: "auto" }}>
      <div style={{ height: virt.getTotalSize(), position: "relative" }}>
        {virt.getVirtualItems().map((vi) => (
          <div
            key={vi.key}
            data-index={vi.index}
            ref={virt.measureElement}
            style={{ position: "absolute", top: 0, left: 0, width: "100%", transform: `translateY(${vi.start}px)` }}
          >
            {renderRow(rows[vi.index])}
          </div>
        ))}
      </div>
    </div>
  );
}

export function RelationshipsTab({
  entityType,
  entityId,
  entityLabel,
  related,
  relatedCounts,
  ruleCoverage,
  graphData,
  onOpenEntity,
  onOpenArticle,
  onOpenEntry,
}: {
  entityType: EntityType;
  entityId: string;
  entityLabel: string;
  related: PivotResponse["related"];
  relatedCounts?: Record<string, number>;
  ruleCoverage?: PivotResponse["rule_coverage"];
  graphData?: GraphResponse;
  onOpenEntity: (type: EntityType, id: string, label: string) => void;
  onOpenArticle: (entryId: string) => void;
  onOpenEntry: (entryId: string) => void;
}) {
  const navigate = useNavigate();
  const openThread = useOpenThread();
  const [graphCollapsed, setGraphCollapsed] = useState(false);
  const [storyFilter, setStoryFilter] = useState<{ title: string; keys: Set<string> } | null>(null);
  // On-demand neighbor sets fetched per node from the inspector's
  // "Expand connections" — keyed by graph node id.
  const [graphExpansions, setGraphExpansions] = useState<
    Map<string, { nodes: EntityNode[]; edges: EntityEdge[]; clusters: GraphStoryCluster[] }>
  >(new Map());
  const [expansionInfo, setExpansionInfo] = useState<Map<string, GraphNodeInfo>>(new Map());
  const [search, setSearch] = useState("");
  const [scope, setScope] = useState<Scope>("claims");
  const [windowDays, setWindowDays] = useState(0); // 0 = all time
  const [serverExpanded, setServerExpanded] = useState(false);
  const [openGroups, setOpenGroups] = useState<Set<string>>(new Set());
  const [reportingOpen, setReportingOpen] = useState(false);
  const [pendingEdge, setPendingEdge] = useState<{
    sourceId: string;
    sourceType: string;
    targetId: string;
    targetType: string;
    verb: string;
    confidence: string;
  } | null>(null);
  const pendingVerbs = pendingEdge ? allowedVerbsForPair(pendingEdge.sourceType, pendingEdge.targetType) : [];

  useEffect(() => {
    setGraphExpansions(new Map());
    setExpansionInfo(new Map());
    setStoryFilter(null);
  }, [entityId]);

  const unlinkRelated = useUnlinkRelatedEntity();
  const confirmRel = useConfirmRelationship();
  const rejectRel = useRejectRelationship();
  const createRelationship = useCreateRelationship();

  // Window / show-all re-query the pivot with parameters; the default view
  // reuses the page-level pivot passed in as props.
  const needsParamFetch = windowDays > 0 || serverExpanded;
  const paramPivot = usePivot(entityType, needsParamFetch ? entityId : undefined, {
    window_days: windowDays > 0 ? windowDays : undefined,
    limit_per_type: serverExpanded ? 500 : undefined,
  });
  const effRelated = (needsParamFetch ? paramPivot.data?.related : undefined) ?? related;
  const effCounts = (needsParamFetch ? paramPivot.data?.related_counts : undefined) ?? relatedCounts;

  // Time-scoped graph mirrors the same evidence window as the rows.
  const windowGraph = useEntityGraph(
    entityType,
    windowDays > 0 && !graphCollapsed ? entityId : undefined,
    1,
    windowDays > 0 ? windowDays : undefined,
  );
  const effGraph = windowDays > 0 ? windowGraph.data : graphData;

  const allRows = useMemo(() => flattenRelated(effRelated, entityType), [effRelated, entityType]);

  const searched = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return allRows;
    return allRows.filter(
      ({ item, label }) =>
        label.toLowerCase().includes(q) || (item.aliases ?? []).some((a) => (a || "").toLowerCase().includes(q)),
    );
  }, [allRows, search]);

  // Country profiles keep their semantic verb groups (targets / operates from /
  // infrastructure) — junction-derived, rendered ahead of the typed groups.
  const countryGroups =
    entityType === "country"
      ? {
          targets: searched.filter((r) => r.item.country_relationship === "targets"),
          operates: searched.filter((r) => r.item.country_relationship === "operates_from"),
          infra: searched.filter((r) => r.item.country_relationship === "infrastructure"),
        }
      : null;
  const countryGrouped = new Set(
    [...(countryGroups?.targets ?? []), ...(countryGroups?.operates ?? []), ...(countryGroups?.infra ?? [])].map(
      rowKey,
    ),
  );
  const rest = countryGroups ? searched.filter((r) => !countryGrouped.has(rowKey(r))) : searched;

  const { asserted, context } = useMemo(() => splitAssertedContext(rest), [rest]);
  // A story-map cluster click narrows the list to that incident's members.
  const assertedView = useMemo(
    () => (storyFilter ? asserted.filter((r) => storyFilter.keys.has(rowKey(r))) : asserted),
    [asserted, storyFilter],
  );
  const verbGroups = useMemo(() => groupByVerb(assertedView), [assertedView]);

  // The operations map + the header transparency note both come from the
  // earned/folded split over everything asserted (unfiltered).
  const { earned: earnedAll, folded: foldedAll } = useMemo(() => partitionEarned(asserted), [asserted]);
  const mapClusters = useMemo(() => buildStoryMap(earnedAll), [earnedAll]);
  // Detection coverage: prefer the pivot's library-wide rule_coverage (how
  // many rules in the WHOLE library reference each technique/CVE — counts
  // feed the inspector). Fall back to source refs on the pivot's own rules
  // for older cached payloads; never claim a gap blindly without either.
  const coverage = useMemo(() => {
    const effCoverage = (needsParamFetch ? paramPivot.data?.rule_coverage : undefined) ?? ruleCoverage;
    if (effCoverage) {
      return {
        ttps: new Map(Object.entries(effCoverage.ttps ?? {})),
        cves: new Map(Object.entries(effCoverage.cves ?? {})),
        present: true,
      };
    }
    const rules = effRelated?.detection_rules ?? [];
    const hasSourceData = rules.some((r) => "source_ttps" in r || "source_cves" in r);
    const ttps = new Map<string, number>();
    const cves = new Map<string, number>();
    for (const r of rules) {
      (r.source_ttps ?? []).forEach((t) => ttps.set(t, (ttps.get(t) ?? 0) + 1));
      (r.source_cves ?? []).forEach((c) => cves.set(c, (cves.get(c) ?? 0) + 1));
    }
    return { ttps, cves, present: hasSourceData };
  }, [effRelated, ruleCoverage, needsParamFetch, paramPivot.data]);

  // Inspector facts per graph node — trust, evidence shape, counts, the
  // profile description, KEV, and detection coverage.
  const graphNodeInfo = useMemo(() => {
    const m = new Map<string, GraphNodeInfo>();
    for (const r of asserted) {
      const t = trustOf(r.item);
      const p = structurePhrase(r.item);
      let covered: boolean | undefined;
      let ruleCount: number | undefined;
      if (coverage.present && r.type === "ttp" && r.item.technique_id) {
        ruleCount = coverage.ttps.get(r.item.technique_id) ?? 0;
        covered = ruleCount > 0;
      } else if (coverage.present && r.type === "cve" && r.item.cve_id) {
        ruleCount = coverage.cves.get(r.item.cve_id) ?? 0;
        covered = ruleCount > 0;
      }
      const desc = r.item.description?.trim();
      m.set(rowKey(r), {
        trust: t ? (t.provenance ? `${t.tier} · ${t.provenance}` : t.tier) : null,
        phrase: p ? `${p.lead} ${p.rest}`.trim() : null,
        articles: r.item.strength?.articles,
        feeds: r.item.strength?.sources,
        description: desc ? (desc.length > 600 ? `${desc.slice(0, 599)}…` : desc) : null,
        kev: r.type === "cve" ? !!r.item.is_kev : undefined,
        covered,
        ruleCount,
      });
    }
    for (const [k, v] of expansionInfo) if (!m.has(k)) m.set(k, v);
    return m;
  }, [asserted, coverage, expansionInfo]);

  const graphClusters = useMemo<GraphStoryCluster[]>(
    () =>
      mapClusters.map((c, i) => ({
        id: c.slug ?? `story-${i}`,
        heading: clusterHeading(c),
        corroborated: c.corroborated,
        articles: c.entryIds.length,
        nodeIds: c.members.map((m) => rowKey(m.row)),
        slug: c.slug,
      })),
    [mapClusters],
  );
  const ctxRegular = context.filter((r) => r.item.context_role !== "reporting_source");
  const ctxReporting = context.filter((r) => r.item.context_role === "reporting_source");

  const totalKnown = TYPE_ORDER.reduce(
    (sum, t) => sum + (effCounts?.[RELATED_KEY[t]] ?? allRows.filter((r) => r.type === t).length),
    0,
  );

  const rowActions = {
    viewedLabel: entityLabel,
    onOpen: onOpenEntity,
    onOpenArticle,
    onConfirm: (id: string) => confirmRel.mutate(id),
    onReject: (id: string) => rejectRel.mutate(id),
    onUnlink: (row: RelRow) =>
      unlinkRelated.mutate({ entityType, entityId, otherType: row.type, otherId: row.item.id }),
  };

  // Inspector "Expand connections": fetch the clicked node's own PIVOT —
  // its earned claims become satellite nodes, and its evidence stories
  // become mini hulls orbiting it. Collapse just drops the set.
  const toggleGraphExpand = (nodeId: string, nodeType: string, expand: boolean) => {
    if (!expand) {
      setGraphExpansions((prev) => {
        const next = new Map(prev);
        next.delete(nodeId);
        // Cascade: an expansion anchored to a node that just vanished (it
        // only existed inside the collapsed set) goes with it, repeatedly,
        // so multi-layer chains fold back cleanly.
        const baseIds = new Set((effGraph?.nodes ?? []).map((n) => n.id));
        let changed = true;
        while (changed) {
          changed = false;
          const present = new Set(baseIds);
          for (const exp of next.values()) for (const n of exp.nodes) present.add(n.id);
          for (const key of [...next.keys()]) {
            if (!present.has(key)) {
              next.delete(key);
              changed = true;
            }
          }
        }
        return next;
      });
      return;
    }
    const rawId = nodeId.replace(`${nodeType}-`, "");
    api
      .get<PivotResponse>(`/intelligence/pivot/${nodeType}/${rawId}`)
      .then(({ data }) => {
        const rows = flattenRelated(data.related, nodeType as EntityType);
        const { asserted: exAsserted } = splitAssertedContext(rows);
        const { earned } = partitionEarned(exAsserted);
        const top = earned.slice(0, 24);
        const exNodes: EntityNode[] = top.map((r) => ({
          id: rowKey(r),
          type: r.type,
          label: r.label,
          size: Math.min((r.item.strength?.articles ?? 1) * 10, 60),
          data: r.item as unknown as Record<string, unknown>,
        }));
        const exEdges: EntityEdge[] = top.map((r) => {
          const inbound = r.item.relationship_direction === "inbound";
          return {
            source: inbound ? rowKey(r) : nodeId,
            target: inbound ? nodeId : rowKey(r),
            weight: 1,
            label: r.item.relationship_type ?? "related_to",
            proximity_score: r.item.proximity_score ?? undefined,
            confidence: r.item.relationship_confidence,
            provenance: r.item.relationship_source,
            entries: (r.item.proximity_entries ?? []).slice(0, 6).map((pe) => ({
              entry_id: pe.entry_id,
              title: pe.title ?? "",
              score: pe.score,
            })),
          } as EntityEdge;
        });
        const exClusters: GraphStoryCluster[] = buildStoryMap(top).map((c, i) => ({
          id: `${nodeId}:${c.slug ?? `story-${i}`}`,
          heading: clusterHeading(c),
          corroborated: c.corroborated,
          articles: c.entryIds.length,
          nodeIds: c.members.map((m) => rowKey(m.row)),
          slug: c.slug,
          external: true,
        }));
        setExpansionInfo((prev) => {
          const next = new Map(prev);
          const exCov = data.rule_coverage;
          for (const r of top) {
            const t = trustOf(r.item);
            const p = structurePhrase(r.item);
            const desc = r.item.description?.trim();
            let covered: boolean | undefined;
            let ruleCount: number | undefined;
            if (exCov && r.type === "ttp" && r.item.technique_id) {
              ruleCount = exCov.ttps?.[r.item.technique_id] ?? 0;
              covered = ruleCount > 0;
            } else if (exCov && r.type === "cve" && r.item.cve_id) {
              ruleCount = exCov.cves?.[r.item.cve_id] ?? 0;
              covered = ruleCount > 0;
            }
            next.set(rowKey(r), {
              trust: t ? (t.provenance ? `${t.tier} · ${t.provenance}` : t.tier) : null,
              phrase: p ? `${p.lead} ${p.rest}`.trim() : null,
              articles: r.item.strength?.articles,
              feeds: r.item.strength?.sources,
              description: desc ? (desc.length > 600 ? `${desc.slice(0, 599)}…` : desc) : null,
              kev: r.type === "cve" ? !!r.item.is_kev : undefined,
              covered,
              ruleCount,
            });
          }
          return next;
        });
        setGraphExpansions((prev) =>
          new Map(prev).set(nodeId, { nodes: exNodes, edges: exEdges, clusters: exClusters }),
        );
      })
      .catch(() => undefined);
  };

  // The rules behind a coverage tick — fetched when the inspector asks,
  // filtered library-wide by the node's technique/CVE id.
  const fetchCoveringRules = useCallback(async (node: EntityNode): Promise<CoveringRule[]> => {
    const d = node.data as { technique_id?: string; cve_id?: string } | undefined;
    const params =
      node.type === "ttp" && d?.technique_id
        ? { technique: d.technique_id }
        : node.type === "cve" && d?.cve_id
          ? { cve: d.cve_id }
          : null;
    if (!params) return [];
    const { data } = await api.get<{ items: CoveringRule[] }>("/detection-rules", {
      params: { ...params, limit: 8 },
    });
    return data.items ?? [];
  }, []);

  // Trim graph to the largest nodes around the center for very dense entities.
  let nodes = effGraph?.nodes ?? [];
  let edges = effGraph?.edges ?? [];
  if (nodes.length > MAX_GRAPH_NODES) {
    const center = `${entityType}-${entityId}`;
    const sorted = [...nodes].sort((a, b) => (a.id === center ? -1 : b.id === center ? 1 : b.size - a.size));
    nodes = sorted.slice(0, MAX_GRAPH_NODES);
    const kept = new Set(nodes.map((n) => n.id));
    edges = edges.filter((e) => kept.has(e.source) && kept.has(e.target));
  }

  const toggleGroup = (key: string) =>
    setOpenGroups((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  // Country targeting rendered as a ranked pattern, not rows — 32 identical
  // "targets Country" rows say nothing; the weight distribution is the intel.
  // Region names mis-filed as countries ("Europe") are kept out of the bars.
  const renderTargetingBlock = (g: VerbGroup, rows: RelRow[]) => {
    const regions = rows.filter((r) => REGION_NAMES.has(r.label.toLowerCase()));
    const countries = rows.filter((r) => !REGION_NAMES.has(r.label.toLowerCase()));
    const ranked = [...countries].sort((a, b) => ctxCount(b) - ctxCount(a));
    const top = ranked.slice(0, 8);
    const max = Math.max(ctxCount(top[0]), 1);
    return (
      <div className={styles.targetBlock}>
        <div className={styles.targetSummary}>
          Targeting reported across {countries.length} countries — weighted to{" "}
          {top.slice(0, 3).map((r) => r.label).join(", ")}.
          {regions.length > 0 && (
            <span className={styles.groupNote}>
              {" "}
              {regions.map((r) => `“${r.label}”`).join(", ")} {regions.length === 1 ? "is a region" : "are regions"}{" "}
              mis-filed as {regions.length === 1 ? "a country" : "countries"} — folded here.
            </span>
          )}
        </div>
        <div className={styles.targetBars}>
          {top.map((r) => (
            <button
              key={rowKey(r)}
              className={styles.targetBarRow}
              onClick={() => onOpenEntity(r.type, r.item.id, r.label)}
              title={`${r.label} — ${ctxCount(r)} article${ctxCount(r) === 1 ? "" : "s"}`}
            >
              <span className={styles.targetLabel}>{r.label}</span>
              <span className={styles.targetTrack}>
                <span className={styles.targetFill} style={{ width: `${(ctxCount(r) / max) * 100}%` }} />
              </span>
              <span className={styles.targetCount}>{ctxCount(r)}</span>
            </button>
          ))}
        </div>
        <button className={styles.metaLink} onClick={() => toggleGroup(`targetrows:${g.key}`)}>
          all {rows.length} as rows <span className="caret-glyph">▸</span>
        </button>
      </div>
    );
  };

  // Quiet full-width band shared by the three fold kinds: story-less claims,
  // everyday software, implausible ids. Bold label — muted note, mono caption
  // hard right. Nothing is deleted — a second story promotes any folded claim
  // back to a row automatically.
  const renderFold = (
    key: string,
    label: string,
    note: ReactNode,
    cap: ReactNode,
    rows: RelRow[],
    explain?: string,
  ) => {
    const open = openGroups.has(key);
    return (
      <div className={styles.claimFold} key={key}>
        <button className={styles.foldToggle} onClick={() => toggleGroup(key)}>
          <span className="caret-glyph">{open ? "▾" : "▸"}</span> <b>{label}</b>
          {note && <span> — {note}</span>}
        </button>
        {cap && <span className={styles.foldCap}>{cap}</span>}
        {open && (
          <div className={styles.foldBody}>
            <div className={styles.ctxShelf}>{rows.map((r) => ctxChip(r, { dim: true }))}</div>
            {explain && <div className={styles.foldExplain}>{explain}</div>}
          </div>
        )}
      </div>
    );
  };

  // The tab's one identity-level claim reads as a sentence, not a row in a
  // crowd ("Attributed to Russia").
  const renderAttributedSentence = (g: VerbGroup) => {
    const r = g.rows[0];
    return (
      <div className={styles.verbGroup} key={g.key}>
        <button className={styles.attribRow} onClick={() => onOpenEntity(r.type, r.item.id, r.label)}>
          <span className={styles.relDot} style={{ background: getEntityColor(r.type) }} />
          <span className={styles.attribText}>
            Attributed to <b>{r.label}</b>
          </span>
          <span className={styles.attribCap}>
            {r.item.strength?.articles ? `${r.item.strength.articles} art` : ""}
            {r.item.strength && r.item.strength.sources > 1 ? ` · ${r.item.strength.sources} feeds` : ""}
          </span>
        </button>
      </div>
    );
  };

  const TARGET_BLOCK_MIN = 6;

  const renderVerbGroup = (g: VerbGroup) => {
    if (g.verb === "attributed_to" && g.direction === "outbound" && g.rows.length === 1) {
      return renderAttributedSentence(g);
    }
    const open = openGroups.has(g.key);
    // Searching or a story filter disables folding and pattern blocks — a
    // match must never hide behind a fold.
    const searching = search.trim().length > 0 || storyFilter !== null;
    const countryRows =
      !searching && g.verb === "targets" && g.direction === "outbound"
        ? g.rows.filter((r) => r.type === "country")
        : [];
    const useTargetBlock = countryRows.length >= TARGET_BLOCK_MIN && !openGroups.has(`targetrows:${g.key}`);
    const baseRows = useTargetBlock ? g.rows.filter((r) => r.type !== "country") : g.rows;

    // Fold order: junk ids out first, then everyday software, then the
    // earned/story-less split over what remains.
    const implausible = searching ? [] : baseRows.filter((r) => r.type === "cve" && isImplausibleCveId(r.label));
    const afterJunk = searching ? baseRows : baseRows.filter((r) => !implausible.includes(r));
    const everyday = searching ? [] : afterJunk.filter(isEverydaySoftware);
    const remaining = searching ? afterJunk : afterJunk.filter((r) => !everyday.includes(r));
    const { earned, folded } = searching ? { earned: remaining, folded: [] } : partitionEarned(remaining);
    const shown = open ? earned : earned.slice(0, GROUP_PREVIEW);
    return (
      <div className={styles.verbGroup} key={g.key}>
        <div className={styles.verbGroupHeader}>
          {g.direction === "outbound" ? (
            <>
              <span className={styles.verbGroupSubject}>{entityLabel}</span>{" "}
              <span className={styles.verbGroupVerb}>{g.label}</span>
            </>
          ) : (
            <span className={styles.verbGroupVerb}>{g.label}</span>
          )}
          <span className={styles.verbCount}>{g.rows.length}</span>
          {countryRows.length >= TARGET_BLOCK_MIN && !useTargetBlock && (
            <button className={styles.metaLink} onClick={() => toggleGroup(`targetrows:${g.key}`)}>
              <span className="caret-glyph">▾</span> targeting summary
            </button>
          )}
        </div>
        {useTargetBlock && renderTargetingBlock(g, countryRows)}
        {open && shown.length > 60 ? (
          <VirtualRows rows={shown} renderRow={(row) => <RelationshipRow key={rowKey(row)} row={row} {...rowActions} />} />
        ) : (
          shown.map((row) => <RelationshipRow key={rowKey(row)} row={row} {...rowActions} />)
        )}
        {earned.length > GROUP_PREVIEW && (
          <button className={styles.showMoreBtn} onClick={() => toggleGroup(g.key)}>
            {open ? "Show less" : `Show all ${earned.length}`}
          </button>
        )}
        {everyday.length > 0 &&
          renderFold(
            `everyday:${g.key}`,
            "Everyday software named in passing",
            everyday
              .slice(0, 4)
              .map((r) => r.label)
              .join(", ") + (everyday.length > 4 ? ` + ${everyday.length - 4} more` : ""),
            "same fold as reporting vendors",
            everyday,
          )}
        {folded.length > 0 &&
          renderFold(
            `fold:${g.key}`,
            `${folded.length} thin claim${folded.length === 1 ? "" : "s"}`,
            folded.every((r) => (r.item.strength?.articles ?? 1) <= 1)
              ? "one loose mention each, no story yet"
              : "loose mentions & roundup co-mentions, no story yet",
            "held from promotion",
            folded,
            "Each of these stays a claim — if a second story ever asserts one, it earns a row and surfaces automatically.",
          )}
        {implausible.length > 0 &&
          renderFold(
            `junk:${g.key}`,
            `${implausible.length} implausible CVE id${implausible.length === 1 ? "" : "s"}`,
            implausible
              .slice(0, 3)
              .map((r) => r.label)
              .join(", ") +
              (implausible.length > 3 ? ` + ${implausible.length - 3} more` : "") +
              " · likely extraction junk",
            <button className={styles.metaLink} onClick={() => navigate("/settings?section=engine&view=entities")}>
              review in Engine →
            </button>,
            implausible,
          )}
      </div>
    );
  };

  const renderCountrySection = (title: string, rows: RelRow[]) => {
    if (rows.length === 0) return null;
    const open = openGroups.has(title);
    const shown = open ? rows : rows.slice(0, GROUP_PREVIEW * 2);
    return (
      <div className={styles.verbGroup} key={title}>
        <div className={styles.verbGroupHeader}>
          <span className={styles.verbGroupVerb}>{title}</span>
          <span className={styles.verbCount}>{rows.length}</span>
        </div>
        {open && shown.length > 60 ? (
          <VirtualRows rows={shown} renderRow={(row) => <RelationshipRow key={rowKey(row)} row={row} {...rowActions} />} />
        ) : (
          shown.map((row) => <RelationshipRow key={rowKey(row)} row={row} {...rowActions} />)
        )}
        {rows.length > GROUP_PREVIEW * 2 && (
          <button className={styles.showMoreBtn} onClick={() => toggleGroup(title)}>
            {open ? "Show less" : `Show all ${rows.length}`}
          </button>
        )}
      </div>
    );
  };

  const ctxCount = (row: RelRow) => row.item.strength?.articles ?? row.item.co_occurrence_count ?? 0;

  const ctxChip = (row: RelRow, opts?: { dot?: boolean; dim?: boolean }) => {
    const n = ctxCount(row);
    return (
      <button
        key={rowKey(row)}
        className={`${styles.ctxChip} ${opts?.dim ? styles.ctxChipDim : ""}`}
        onClick={() => onOpenEntity(row.type, row.item.id, row.label)}
        title={`${row.label} — co-mentioned in ${n} shared article${n === 1 ? "" : "s"}`}
      >
        {opts?.dot && <span className={styles.relDot} style={{ background: getEntityColor(row.type) }} />}
        {row.label}
        {n > 1 && <span className={styles.ctxChipCount}>×{n}</span>}
      </button>
    );
  };

  // Context, grouped by type: one labeled row per entity type, repeat
  // co-mentions up front (sorted by count), the ×1 tail folded into a quiet
  // "+N seen once" — hierarchy instead of a 200-chip wall.
  const ctxGroups = useMemo(() => {
    const byType = new Map<EntityType, RelRow[]>();
    for (const r of ctxRegular) {
      const list = byType.get(r.type) ?? [];
      list.push(r);
      byType.set(r.type, list);
    }
    return TYPE_ORDER.filter((t) => byType.has(t)).map((t) => {
      const rows = [...byType.get(t)!].sort((a, b) => ctxCount(b) - ctxCount(a));
      const repeats = rows.filter((r) => ctxCount(r) > 1);
      const singles = rows.filter((r) => ctxCount(r) <= 1);
      return { type: t, repeats, singles };
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ctxRegular]);

  const CTX_PREVIEW = 10;

  const renderCtxGroup = (g: { type: EntityType; repeats: RelRow[]; singles: RelRow[] }) => {
    const key = `ctx:${g.type}`;
    const open = openGroups.has(key);
    // Fill the preview budget: repeats first, then the strongest singles
    // (dimmed) — sparse profiles with only ×1 co-mentions still show chips
    // instead of collapsing whole rows behind a "seen once" link.
    const shownRepeats = open ? g.repeats : g.repeats.slice(0, CTX_PREVIEW);
    const singleBudget = open ? g.singles.length : Math.max(0, CTX_PREVIEW - shownRepeats.length);
    const shownSingles = g.singles.slice(0, singleBudget);
    const hiddenCount = g.repeats.length - shownRepeats.length + g.singles.length - shownSingles.length;
    return (
      <div className={styles.ctxGroupRow} key={g.type}>
        <span className={styles.ctxGroupLabel}>
          <span className={styles.relDot} style={{ background: getEntityColor(g.type) }} />
          {getEntityPluralLabel(g.type)}
        </span>
        <span className={styles.ctxGroupChips}>
          {shownRepeats.map((r) => ctxChip(r))}
          {shownSingles.map((r) => ctxChip(r, { dim: true }))}
          {!open && hiddenCount > 0 && (
            <button className={styles.ctxTail} onClick={() => toggleGroup(key)}>
              +{hiddenCount} more
            </button>
          )}
          {open && (
            <button className={styles.ctxTail} onClick={() => toggleGroup(key)}>
              show less
            </button>
          )}
        </span>
      </div>
    );
  };

  // Co-mentions never render on the default view — they are the discovery
  // layer, reachable only when explicitly asked for.
  const showAsserted = scope === "claims";
  const showContext = scope === "context";

  return (
    <div className={styles.tabPanel}>
      {/* The panel's control bar: mode first (it swaps the view below), a
          flexible search, then the view controls right-aligned. Counts live
          in the segments — no separate tally. */}
      <div className={styles.relControls}>
        <Segmented
          options={[
            { value: "claims", label: `Claims${asserted.length ? ` · ${asserted.length}` : ""}` },
            { value: "context", label: `Co-mentions${context.length ? ` · ${context.length}` : ""}` },
          ]}
          value={scope}
          onChange={setScope}
          label="Relationship scope"
          role="tablist"
          size="sm"
        />
        <input
          className={styles.relSearch}
          placeholder="Search relationships…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        {storyFilter && (
          <button className={styles.storyFilterChip} onClick={() => setStoryFilter(null)}>
            Story: {storyFilter.title} ✕
          </button>
        )}
        <div className={styles.relControlsRight}>
          <select
            className={styles.browserSelect}
            value={windowDays}
            onChange={(e) => setWindowDays(Number(e.target.value))}
          >
            <option value={0}>All time</option>
            <option value={30}>Last 30d</option>
            <option value={90}>Last 90d</option>
            <option value={365}>Last year</option>
          </select>
          <button
            className={`${styles.graphToggleBtn} ${!graphCollapsed ? styles.graphToggleBtnOn : ""}`}
            onClick={() => setGraphCollapsed((c) => !c)}
          >
            {graphCollapsed ? "Show graph" : "Hide graph"}
          </button>
        </div>
      </div>

      {!graphCollapsed && nodes.length > 0 && (
        <div className={styles.section}>
          <div style={{ height: 620, border: "1px solid var(--border)", borderRadius: 8, overflow: "hidden" }}>
            <EntityGraph
              nodes={nodes}
              edges={edges}
              height={620}
              storyClusters={graphClusters}
              nodeInfo={graphNodeInfo}
              highlightQuery={search}
              expansions={graphExpansions}
              onToggleExpand={toggleGraphExpand}
              onOpenThread={openThread}
              onFetchCoveringRules={fetchCoveringRules}
              onOpenRule={(ruleId) => navigate(`/workbench/rule/${ruleId}`)}
              onClusterClick={(c) => setStoryFilter({ title: c.heading, keys: new Set(c.nodeIds) })}
              onNodeClick={(nodeId, nodeType) => {
                if (!NAV_TYPES.has(nodeType)) return;
                onOpenEntity(nodeType as EntityType, nodeId.replace(`${nodeType}-`, ""), "");
              }}
              onEdgeCreate={(sourceId, sourceType, targetId, targetType) =>
                setPendingEdge({
                  sourceId,
                  sourceType,
                  targetId,
                  targetType,
                  verb: allowedVerbsForPair(sourceType, targetType)[0] ?? "related_to",
                  confidence: "probable",
                })
              }
              onEntryClick={onOpenEntry}
            />
          </div>
          {pendingEdge && pendingVerbs.length === 0 && (
            <div className={styles.filterRow} style={{ alignItems: "center", marginTop: 8, flexWrap: "wrap" }}>
              <span className={styles.groupNote}>
                {pendingEdge.sourceType.replace(/_/g, " ")} ↔ {pendingEdge.targetType.replace(/_/g, " ")} is not a
                tracked relationship combination
              </span>
              <button className={styles.rowActionBtn} onClick={() => setPendingEdge(null)}>
                Dismiss
              </button>
            </div>
          )}
          {pendingEdge && pendingVerbs.length > 0 && (
            <div className={styles.filterRow} style={{ alignItems: "center", marginTop: 8, flexWrap: "wrap" }}>
              <span className={styles.groupNote}>
                Link {nodes.find((n) => n.id === pendingEdge.sourceId)?.label || pendingEdge.sourceId} →{" "}
                {nodes.find((n) => n.id === pendingEdge.targetId)?.label || pendingEdge.targetId} as
              </span>
              <select
                className={styles.browserSelect}
                value={pendingEdge.verb}
                onChange={(e) => setPendingEdge({ ...pendingEdge, verb: e.target.value })}
              >
                {pendingVerbs.map((v) => (
                  <option key={v} value={v}>{v.replace(/_/g, " ")}</option>
                ))}
              </select>
              <select
                className={styles.browserSelect}
                value={pendingEdge.confidence}
                onChange={(e) => setPendingEdge({ ...pendingEdge, confidence: e.target.value })}
              >
                <option value="possible">possible</option>
                <option value="probable">probable</option>
                <option value="confirmed">confirmed</option>
              </select>
              <button
                className={`${styles.rowActionBtn} ${styles.rowActionConfirm}`}
                onClick={() => {
                  createRelationship.mutate({
                    source_type: pendingEdge.sourceType,
                    source_id: pendingEdge.sourceId.replace(`${pendingEdge.sourceType}-`, ""),
                    target_type: pendingEdge.targetType,
                    target_id: pendingEdge.targetId.replace(`${pendingEdge.targetType}-`, ""),
                    relationship_type: pendingEdge.verb,
                    confidence: pendingEdge.confidence,
                  });
                  setPendingEdge(null);
                }}
              >
                Create
              </button>
              <button className={styles.rowActionBtn} onClick={() => setPendingEdge(null)}>
                Cancel
              </button>
            </div>
          )}
        </div>
      )}

      {countryGroups && showAsserted && (
        <>
          {renderCountrySection(`Targeting ${entityLabel}`, countryGroups.targets)}
          {renderCountrySection(`Operating from ${entityLabel}`, countryGroups.operates)}
          {renderCountrySection(`Infrastructure in ${entityLabel}`, countryGroups.infra)}
        </>
      )}

      {showAsserted && (
        <div className={styles.section}>
          <div className={styles.sectionHeader}>
            Asserted relationships <span className={styles.sectionCount}>{asserted.length}</span>
            <span className={styles.sectionNote}>
              {storyFilter
                ? `filtered to one story · ${assertedView.length} claims`
                : foldedAll.length > 0
                  ? `${earnedAll.length} shown · rest folded below each group`
                  : "typed claims, graded by trust"}
            </span>
          </div>
          {verbGroups.length === 0 ? (
            <div className={styles.emptySection}>
              No asserted relationships{search ? " match the search" : " yet"}.
            </div>
          ) : (
            verbGroups.map(renderVerbGroup)
          )}
        </div>
      )}

      {showContext && (
        <div className={styles.section}>
          <div className={styles.sectionHeader}>
            Appears alongside <span className={styles.sectionCount}>{context.length}</span>
            <span className={styles.sectionNote}>co-mentioned in shared reporting — not claims</span>
          </div>
          {context.length === 0 ? (
            <div className={styles.emptySection}>No co-mention context{search ? " matches the search" : ""}.</div>
          ) : (
            <>
              <div className={styles.ctxGroups}>{ctxGroups.map(renderCtxGroup)}</div>
              {ctxReporting.length > 0 && (
                <div className={styles.ctxFold}>
                  <button
                    className={styles.metaLink}
                    onClick={() => setReportingOpen((o) => !o)}
                    title="Vendors & products named across most coverage — the reporter or the platform in the story, not a relationship"
                  >
                    <span className="caret-glyph">{reportingOpen ? "▾" : "▸"}</span> {ctxReporting.length} ubiquitous vendor
                    {ctxReporting.length === 1 ? "" : "s"} &amp; products
                  </button>
                  <span className={styles.groupNote}>
                    {reportingOpen
                      ? "named across most coverage — background, not relationships"
                      : ctxReporting
                          .slice(0, 4)
                          .map((r) => r.label)
                          .join(", ") + (ctxReporting.length > 4 ? "…" : "")}
                  </span>
                  {reportingOpen && (
                    <div className={styles.ctxShelf}>{ctxReporting.map((r) => ctxChip(r, { dot: true }))}</div>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* The server-side tail is almost entirely co-mention context — the
          claims view never needs this button. */}
      {scope === "context" && totalKnown > allRows.length && !serverExpanded && (
        <button className={styles.showMoreBtn} onClick={() => setServerExpanded(true)}>
          Load all {totalKnown} from server…
        </button>
      )}
    </div>
  );
}
