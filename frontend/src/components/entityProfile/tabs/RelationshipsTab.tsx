/**
 * RelationshipsTab — the entity's relationships as a compact list beside an
 * evidence panel.
 *
 * The list reads as sentences grouped by verb and type ("Qilin uses ·
 * techniques"), each row naming its source (MITRE ATT&CK, a feed, AI-reviewed
 * articles, an analyst) and how many articles it was seen in. Selecting a row
 * opens the panel: why it's listed, the articles that state it, the reviews,
 * and — kept apart — the articles that merely mention both. CVE and CWE
 * profiles add the links that come from reference data. Co-mentions (no
 * relationship stated) and names no entity matches sit below, on request.
 */
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { useIsVisitor } from "@/stores/authStore";
import { useIsMobile } from "@/hooks/useMediaQuery";
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
import { pruneExpansions } from "@/components/entityGraph/expansions";
import { usePivot, useEntityGraph } from "@/hooks/useCorrelation";
import {
  useCreateRelationship,
  useConfirmRelationship,
  useRejectRelationship,
  useRelationClaims,
  useUpdateRelationship,
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
  partitionEarned,
  RELATED_KEY,
  rowKey,
  splitAssertedContext,
  structurePhrase,
  trustOf,
  TYPE_ORDER,
  type RelRow,
} from "@/utils/relationshipBrowser";
import { sourceLabel, sourcesOf, type SourcePart } from "@/utils/relationshipSource";
import { useOpenThread } from "@/utils/openEntry";
import { EvidencePanel } from "../relationships/EvidencePanel";
import { ReferenceLinks, hasReferenceLinks } from "../relationships/ReferenceLinks";
import { CoMentions, NotMatched } from "../relationships/CoMentions";
import rel from "../relationships/relationships.module.css";
import styles from "../entityProfile.module.css";

const NAV_TYPES = new Set([
  "threat_actor", "malware", "cve", "ttp", "country", "sector", "tool", "mitigation", "vendor", "product", "cwe",
]);
const MAX_GRAPH_NODES = 500;
const GROUP_PREVIEW = 12;

/** A story's articles with their titles, taken from the evidence on its rows. */
function storyEntries(entryIds: string[], rows: RelRow[]): Array<{ entry_id: string; title: string }> {
  const titles = new Map<string, string>();
  for (const r of rows) for (const pe of r.item.proximity_entries ?? []) if (pe.title && !titles.has(pe.entry_id)) titles.set(pe.entry_id, pe.title);
  return entryIds.map((id) => ({ entry_id: id, title: titles.get(id) ?? "Untitled" }));
}

/** "uses" → "use", "attributed to" → "are attributed to": the verb after a plural subject. */
function pluralVerb(active: string): string {
  const [first, ...rest] = active.split(" ");
  if (first.length > 3 && first.endsWith("s") && !first.endsWith("ss")) return [first.slice(0, -1), ...rest].join(" ");
  return `are ${active}`;
}

const articleCount = (row: RelRow) => row.item.strength?.articles ?? row.item.co_occurrence_count ?? 0;

/** Windowed rendering for long open groups. */
function VirtualRows({ rows, renderRow }: { rows: RelRow[]; renderRow: (r: RelRow) => ReactNode }) {
  const parentRef = useRef<HTMLDivElement>(null);
  const virt = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 40,
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

interface ListGroup {
  key: string;
  head: ReactNode;
  rows: RelRow[];
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
  // A visitor browses: no Shift+drag links, no moderation, no review evidence.
  const isVisitor = useIsVisitor();
  const openThread = useOpenThread();
  // A 620px graph would fill a phone before the list: start it hidden there.
  const [graphCollapsed, setGraphCollapsed] = useState(() => window.matchMedia("(max-width: 767px)").matches);
  const [storyFilter, setStoryFilter] = useState<{ title: string; keys: Set<string> } | null>(null);
  // On-demand neighbor sets fetched per node from the graph's +/− badge —
  // keyed by graph node id.
  const [graphExpansions, setGraphExpansions] = useState<
    Map<string, { nodes: EntityNode[]; edges: EntityEdge[]; clusters: GraphStoryCluster[] }>
  >(new Map());
  const [expansionInfo, setExpansionInfo] = useState<Map<string, GraphNodeInfo>>(new Map());
  const [search, setSearch] = useState("");
  const [sourceFilter, setSourceFilter] = useState<string>("");
  const [windowDays, setWindowDays] = useState(0); // 0 = all time
  const [serverExpanded, setServerExpanded] = useState(false);
  const [openGroups, setOpenGroups] = useState<Set<string>>(new Set());
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [heldOpen, setHeldOpen] = useState(false);
  const [coOpen, setCoOpen] = useState(false);
  const [pendingEdge, setPendingEdge] = useState<{
    sourceId: string;
    sourceType: string;
    targetId: string;
    targetType: string;
    verb: string;
    confidence: string;
  } | null>(null);
  const pendingVerbs = pendingEdge ? allowedVerbsForPair(pendingEdge.sourceType, pendingEdge.targetType) : [];
  const panelRef = useRef<HTMLDivElement>(null);
  // Phone: the evidence opens under the tapped row instead of beside the list.
  const isMobile = useIsMobile();

  useEffect(() => {
    setGraphExpansions(new Map());
    setExpansionInfo(new Map());
    setStoryFilter(null);
    setSourceFilter("");
    setSelectedKey(null);
    setHeldOpen(false);
    setCoOpen(false);
  }, [entityId]);

  // Which enrichment sources claim each connection, and the names they gave
  // that resolved to nothing (held). Signed-in only.
  const { data: claims } = useRelationClaims(entityType, entityId, !isVisitor);
  const viaOf = useCallback(
    (row: RelRow) => {
      const labels = new Map<string, string>();
      for (const x of claims?.sources ?? []) labels.set(x.source_type, x.label);
      return (claims?.by_target[rowKey(row)] ?? []).map((st) => labels.get(st) ?? st);
    },
    [claims],
  );

  const confirmRel = useConfirmRelationship();
  const rejectRel = useRejectRelationship();
  const updateRel = useUpdateRelationship();
  const createRelationship = useCreateRelationship();

  // Window / load-all re-query the pivot with parameters; the default view
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

  // Country profiles' targeting / origin / infrastructure rows come from
  // article tagging, not typed relationships — listed with the relationships.
  const countryRole = (r: RelRow) => (entityType === "country" ? r.item.country_relationship : undefined);
  const { asserted: typed, context: untyped } = useMemo(() => splitAssertedContext(allRows), [allRows]);
  const asserted = useMemo(
    () => (entityType === "country" ? [...typed, ...untyped.filter((r) => r.item.country_relationship)] : typed),
    [typed, untyped, entityType],
  );
  const context = useMemo(
    () => (entityType === "country" ? untyped.filter((r) => !r.item.country_relationship) : untyped),
    [untyped, entityType],
  );
  const hasRelationships = asserted.length > 0;

  // The panel stays in view while the list scrolls: pinned just below any bar
  // pinned to the top of the area the page scrolls in (the profile's tab bar),
  // and no taller than what's visible there, so its own scroll reaches the end.
  useLayoutEffect(() => {
    const slot = panelRef.current;
    if (!slot) return;
    let scroller: HTMLElement | null = slot.parentElement;
    while (scroller && !/(auto|scroll)/.test(getComputedStyle(scroller).overflowY)) scroller = scroller.parentElement;
    const fit = () => {
      let pinned = 0;
      const bar = scroller?.querySelector<HTMLElement>("[role=tablist]") ?? null;
      for (let el = bar; el && el !== scroller; el = el.parentElement) {
        if (getComputedStyle(el).position === "sticky") {
          pinned = el.getBoundingClientRect().height;
          break;
        }
      }
      slot.style.top = `${pinned + 12}px`;
      // Until it pins, the panel starts lower down the page: fit it to the
      // space between where it starts now and the bottom of the visible area.
      const visibleBottom = scroller ? scroller.getBoundingClientRect().top + scroller.clientHeight : window.innerHeight;
      slot.style.maxHeight = `${Math.max(240, visibleBottom - slot.getBoundingClientRect().top - 12)}px`;
    };
    let frame = 0;
    const onScroll = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(fit);
    };
    fit();
    const ro = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(fit);
    if (scroller) ro?.observe(scroller);
    ro?.observe(slot.parentElement!);
    (scroller ?? window).addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", fit);
    return () => {
      cancelAnimationFrame(frame);
      ro?.disconnect();
      (scroller ?? window).removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", fit);
    };
  }, [isMobile, hasRelationships]);

  const sourcesByKey = useMemo(() => {
    const m = new Map<string, SourcePart[]>();
    for (const r of asserted) m.set(rowKey(r), sourcesOf(r, viaOf(r)));
    return m;
  }, [asserted, viaOf]);

  // Source filter options, with counts, from everything listed.
  const sourceOptions = useMemo(() => {
    const m = new Map<string, { label: string; count: number }>();
    for (const parts of sourcesByKey.values()) {
      for (const p of parts) {
        const o = m.get(p.key) ?? { label: p.label, count: 0 };
        o.count++;
        m.set(p.key, o);
      }
    }
    return [...m.entries()].sort((a, b) => b[1].count - a[1].count);
  }, [sourcesByKey]);

  const listed = useMemo(() => {
    const q = search.trim().toLowerCase();
    return asserted.filter(
      (r) =>
        (!sourceFilter || (sourcesByKey.get(rowKey(r)) ?? []).some((p) => p.key === sourceFilter)) &&
        (!storyFilter || storyFilter.keys.has(rowKey(r))) &&
        (!q ||
          r.label.toLowerCase().includes(q) ||
          (r.item.aliases ?? []).some((a) => (a || "").toLowerCase().includes(q))),
    );
  }, [asserted, search, sourceFilter, storyFilter, sourcesByKey]);

  // Groups: the sentence head, then the rows by evidence volume.
  const groups = useMemo<ListGroup[]>(() => {
    const byCount = (a: RelRow, b: RelRow) => articleCount(b) - articleCount(a) || a.label.localeCompare(b.label);
    const out: ListGroup[] = [];
    if (entityType === "country") {
      const roles: Array<[string, string]> = [
        ["targets", "that target"],
        ["operates_from", "that operate from"],
        ["infrastructure", "with infrastructure in"],
      ];
      for (const [role, phrase] of roles) {
        const rows = listed.filter((r) => countryRole(r) === role);
        if (rows.length) out.push({ key: `country:${role}`, head: <>Entities <b>{phrase}</b> {entityLabel}</>, rows: rows.sort(byCount) });
      }
    }
    for (const g of groupByVerb(listed.filter((r) => !countryRole(r)))) {
      const byType = new Map<EntityType, RelRow[]>();
      for (const r of g.rows) (byType.get(r.type) ?? byType.set(r.type, []).get(r.type)!).push(r);
      for (const t of TYPE_ORDER) {
        const rows = byType.get(t);
        if (!rows) continue;
        const plural = getEntityPluralLabel(t);
        const active = g.verb.replace(/_/g, " ");
        out.push({
          key: `${g.key}:${t}`,
          head:
            g.direction === "outbound" ? (
              <>
                {entityLabel} <b>{g.label}</b> · {plural}
              </>
            ) : (
              <>
                {plural} that <b>{pluralVerb(active)}</b> {entityLabel}
              </>
            ),
          rows: rows.sort(byCount),
        });
      }
    }
    return out;
    // countryRole only reads entityType
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [listed, entityType, entityLabel]);

  // Beside the list, keep a row selected so the panel always explains
  // something. On a phone nothing opens until a row is tapped.
  const visibleKeys = useMemo(() => new Set(groups.flatMap((g) => g.rows.map(rowKey))), [groups]);
  const selected = useMemo(() => {
    const fallback = !isMobile && groups[0] ? rowKey(groups[0].rows[0]) : null;
    const key = selectedKey && visibleKeys.has(selectedKey) ? selectedKey : fallback;
    return key ? asserted.find((r) => rowKey(r) === key) ?? null : null;
  }, [selectedKey, visibleKeys, groups, asserted, isMobile]);

  // A second tap on the open row closes it (phone only: beside the list,
  // something is always open).
  const selectRow = (row: RelRow) =>
    setSelectedKey((prev) => (isMobile && prev === rowKey(row) ? null : rowKey(row)));

  // The graph's story clusters and inspector facts come from the earned
  // (story-backed) typed relationships, unfiltered.
  const { earned: earnedAll } = useMemo(() => partitionEarned(typed), [typed]);
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
    for (const r of typed) {
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
  }, [typed, coverage, expansionInfo]);

  const graphClusters = useMemo<GraphStoryCluster[]>(
    () =>
      mapClusters.map((c, i) => ({
        id: c.slug ?? `story-${i}`,
        heading: clusterHeading(c),
        corroborated: c.corroborated,
        articles: c.entryIds.length,
        nodeIds: c.members.map((m) => rowKey(m.row)),
        slug: c.slug,
        entries: storyEntries(c.entryIds, earnedAll),
      })),
    [mapClusters, earnedAll],
  );
  const ctxRegular = context.filter((r) => r.item.context_role !== "reporting_source");
  const ctxReporting = context.filter((r) => r.item.context_role === "reporting_source");

  const totalKnown = TYPE_ORDER.reduce(
    (sum, t) => sum + (effCounts?.[RELATED_KEY[t]] ?? allRows.filter((r) => r.type === t).length),
    0,
  );

  // The node's +/− badge (or the inspector): fetch the node's own PIVOT —
  // its earned claims become satellite nodes, and its evidence stories
  // become mini hulls orbiting it. Collapse just drops the set.
  const toggleGraphExpand = (nodeId: string, nodeType: string, expand: boolean) => {
    if (!expand) {
      setGraphExpansions((prev) => {
        const next = new Map(prev);
        next.delete(nodeId);
        // Cascade: expansions hanging off the collapsed one fold back with it.
        return pruneExpansions(next, new Set((effGraph?.nodes ?? []).map((n) => n.id)));
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
          entries: storyEntries(c.entryIds, top),
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

  const renderPanel = (row: RelRow) => (
    <EvidencePanel
      row={row}
      viewedType={entityType}
      viewedLabel={entityLabel}
      sources={sourcesByKey.get(rowKey(row)) ?? []}
      isVisitor={isVisitor}
      onOpen={onOpenEntity}
      onOpenArticle={onOpenArticle}
      onOpenThread={openThread}
      onConfirm={(id) => confirmRel.mutate(id)}
      onReject={(id) => rejectRel.mutate(id)}
      onChangeVerb={(id, verb) => updateRel.mutate({ id, relationship_type: verb })}
    />
  );

  const renderRow = (row: RelRow) => {
    const parts = sourcesByKey.get(rowKey(row)) ?? [];
    const n = articleCount(row);
    const on = !!selected && rowKey(selected) === rowKey(row);
    const button = (
      <button
        key={rowKey(row)}
        className={`${rel.row} ${on ? rel.rowOn : ""}`}
        aria-pressed={on}
        aria-expanded={isMobile ? on : undefined}
        onClick={() => selectRow(row)}
      >
        <span className={rel.rowName}>
          <span className={rel.dot} style={{ background: getEntityColor(row.type) }} />
          <span>{row.label}</span>
        </span>
        <span className={`${rel.rowSource} ${rel[`tone_${parts[0]?.tone ?? "articles"}`]}`}>{sourceLabel(parts)}</span>
        <span className={rel.rowCount}>{n ? `${n} article${n === 1 ? "" : "s"}` : "no articles"}</span>
      </button>
    );
    if (!(isMobile && on)) return button;
    return (
      <div key={rowKey(row)}>
        {button}
        <div className={rel.inlinePanel}>{renderPanel(row)}</div>
      </div>
    );
  };

  const renderGroup = (g: ListGroup) => {
    const open = openGroups.has(g.key);
    const shown = open ? g.rows : g.rows.slice(0, GROUP_PREVIEW);
    return (
      <div key={g.key}>
        <div className={rel.groupHead}>
          <span>{g.head}</span>
          <span className={rel.groupCount}>{g.rows.length}</span>
        </div>
        {open && shown.length > 60 ? <VirtualRows rows={shown} renderRow={renderRow} /> : shown.map(renderRow)}
        {g.rows.length > GROUP_PREVIEW && (
          <button className={rel.linkBtn} onClick={() => toggleGroup(g.key)}>
            {open ? "Show fewer" : `Show all ${g.rows.length}`}
          </button>
        )}
      </div>
    );
  };

  const heldCount = claims?.held_count ?? 0;

  return (
    <div className={styles.tabPanel}>
      <div className={styles.relControls}>
        <input
          className={styles.relSearch}
          placeholder="Find a relationship…"
          aria-label="Find a relationship"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        {sourceOptions.length > 1 && (
          <select
            className={styles.browserSelect}
            aria-label="Source"
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
          >
            <option value="">All sources ({asserted.length})</option>
            {sourceOptions.map(([key, o]) => (
              <option key={key} value={key}>
                {o.label} ({o.count})
              </option>
            ))}
          </select>
        )}
        {storyFilter && (
          <button className={styles.storyFilterChip} onClick={() => setStoryFilter(null)}>
            Story: {storyFilter.title} ✕
          </button>
        )}
        <div className={styles.relControlsRight}>
          <select
            className={styles.browserSelect}
            aria-label="Time window"
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
              onEdgeCreate={
                isVisitor
                  ? undefined
                  : (sourceId, sourceType, targetId, targetType) =>
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

      <div className={rel.layout}>
        <div className={rel.list}>
          {hasReferenceLinks(entityType) && (
            <ReferenceLinks entityType={entityType} entityId={entityId} onOpen={onOpenEntity} />
          )}

          <div className={rel.sectionHead}>
            Relationships <span className={rel.count}>{asserted.length}</span>
          </div>
          {groups.length === 0 ? (
            <div className={rel.empty}>
              {asserted.length === 0
                ? context.length > 0
                  ? `No relationship is recorded yet. ${context.length} entities are named in the same articles, listed below.`
                  : "No relationship is recorded yet."
                : "Nothing matches the filters."}
            </div>
          ) : (
            groups.map(renderGroup)
          )}

          <div className={rel.footerLinks}>
            {heldCount > 0 && (
              <button className={rel.linkBtn} aria-expanded={heldOpen} onClick={() => setHeldOpen((o) => !o)}>
                <span className="caret-glyph">{heldOpen ? "▾" : "▸"}</span> Not matched yet · {heldCount}
              </button>
            )}
            <button className={rel.linkBtn} aria-expanded={coOpen} onClick={() => setCoOpen((o) => !o)}>
              <span className="caret-glyph">{coOpen ? "▾" : "▸"}</span> Mentioned in the same articles · {context.length}
            </button>
          </div>

          {heldOpen && claims && claims.held.length > 0 && (
            <>
              <div className={rel.sectionHead}>
                Not matched yet <span className={rel.count}>{heldCount}</span>
              </div>
              <NotMatched held={claims.held} />
            </>
          )}

          {coOpen && (
            <>
              <div className={rel.sectionHead}>
                Mentioned in the same articles <span className={rel.count}>{context.length}</span>
              </div>
              <p className={rel.sectionNote}>No relationship is stated for these. The number is how many articles name both.</p>
              <CoMentions rows={ctxRegular} reporting={ctxReporting} onOpen={onOpenEntity} />
              {totalKnown > allRows.length && !serverExpanded && (
                <button className={rel.linkBtn} style={{ paddingLeft: 0 }} onClick={() => setServerExpanded(true)}>
                  Load all {totalKnown} from the server
                </button>
              )}
            </>
          )}
        </div>

        {!isMobile && hasRelationships && (
          <div className={rel.panelSlot} ref={panelRef}>
            {selected ? (
              renderPanel(selected)
            ) : (
              <div className={`${rel.panel} ${rel.reasonText}`}>Select a relationship to see why it's listed.</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
