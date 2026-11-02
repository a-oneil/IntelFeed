/**
 * EntityProfilePage — the unified, full-width, config-driven entity profile.
 * One shell renders every entity type via entityProfileConfig — campaigns
 * included: a campaign is not extracted from anything, but its articles are a
 * pivot seed like any other, so it renders here rather than on a page of its own.
 */
import { useEffect, useMemo, useState, useCallback } from "react";
import { useParams, useNavigate, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";
import { useIntelStore, type EntityType } from "@/stores/intelStore";
import { usePivot, useEntityGraph, useEntityTimeline } from "@/hooks/useCorrelation";
import { useEntityStoryThreads, useUpdateEntity } from "@/hooks/useEntityProfile";
import { useEntityProvenance } from "@/hooks/useEntityProvenance";
import {
  getEntityProfileConfig,
  entityDisplayName,
  entityProfilePath,
  type TabKey,
} from "@/components/entityProfile/entityProfileConfig";
import { MentionsTimeline, windowCutoff } from "@/components/entityProfile/MentionsTimeline";
import type { MentionsWindow } from "@/hooks/useEntityProfile";
import type { TimelineEvent } from "@/api/types";
import { useOpenThread } from "@/utils/openEntry";
import { PulseLine } from "@/components/entityProfile/PulseLine";
import { ProfileHeader } from "@/components/entityProfile/ProfileHeader";

import { ProfileTabs } from "@/components/entityProfile/ProfileTabs";
import { OverviewDensityToggle } from "@/components/entityProfile/OverviewSection";
import { OverviewTab } from "@/components/entityProfile/tabs/OverviewTab";
import { RelationshipsTab } from "@/components/entityProfile/tabs/RelationshipsTab";
import { VulnerabilitiesTab } from "@/components/entityProfile/tabs/VulnerabilitiesTab";
import { WeaknessesTab } from "@/components/entityProfile/tabs/WeaknessesTab";
import { useAffectedCveCount } from "@/hooks/useAffectedCves";
import { useCVE, useCVEWeaknesses, useObservable } from "@/hooks/useIntelligence";
import { CveLifecycleStrip } from "@/components/entityProfile/CveLifecycleStrip";
import { ObservableLifecycleStrip } from "@/components/entityProfile/ObservableLifecycleStrip";
import { DetectionTab } from "@/components/entityProfile/tabs/DetectionTab";
import { GeographyTab } from "@/components/entityProfile/tabs/GeographyTab";
import { VictimologyTab } from "@/components/entityProfile/tabs/VictimologyTab";
import { DetectionGapsTab } from "@/components/entityProfile/tabs/DetectionGapsTab";
import styles from "@/components/entityProfile/entityProfile.module.css";
import { useIsVisitor } from "@/stores/authStore";

/** Profile tabs about rules and coverage — not part of the public read-only view. */
const VISITOR_HIDDEN_TABS = new Set<TabKey>(["detection", "detection_gaps"]);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RESOLVE_ENDPOINTS: Record<string, (id: string) => string> = {
  ttp: (id) => `/ttps/by-technique/${id}`,
  cve: (id) => `/cves/${id}`,
  // /cwes/{id} takes a UUID or a catalog id, so the same route resolves both.
  cwe: (id) => `/cwes/${id}`,
  // /sectors/{ref} takes a UUID or the canonical slug (healthcare).
  sector: (id) => `/sectors/${id}`,
};

export function EntityProfilePage({ slug }: { slug: string }) {
  const isVisitor = useIsVisitor();
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const entityType = slug as EntityType;
  const addToRecentPivots = useIntelStore((s) => s.addToRecentPivots);

  // Resolve human-readable IDs (e.g. CVE-2024-1234, T1059) to UUIDs.
  const isUUID = id ? UUID_RE.test(id) : false;
  const needsResolve = !!id && !isUUID && !!RESOLVE_ENDPOINTS[slug];
  const { data: resolved } = useQuery({
    queryKey: ["resolve-entity", slug, id],
    queryFn: async () => {
      const { data } = await api.get<{ id: string }>(RESOLVE_ENDPOINTS[slug]!(id!));
      return data;
    },
    enabled: needsResolve,
    retry: false,
  });
  useEffect(() => {
    if (resolved?.id && needsResolve) navigate(`/workbench/${slug}/${resolved.id}`, { replace: true });
  }, [resolved, needsResolve, slug, navigate]);

  const entityId = id || "";
  const config = entityType ? getEntityProfileConfig(entityType) : undefined;

  const { data: pivot, isLoading } = usePivot(entityType, needsResolve ? undefined : entityId);
  // Types with an authoritative NVD-derived CVE list: vendor/product via CPE,
  // weakness via the NVD weakness block.
  const affectedKind =
    entityType === "vendor" || entityType === "product" || entityType === "cwe" ? entityType : undefined;
  const { data: affectedCount } = useAffectedCveCount(affectedKind, needsResolve ? undefined : entityId);
  const { data: cveWeaknesses } = useCVEWeaknesses(
    entityType === "cve" && !needsResolve ? entityId : undefined,
  );
  const cveWeaknessCount = cveWeaknesses?.length ?? 0;
  const { data: graphData } = useEntityGraph(entityType, needsResolve ? undefined : entityId, 1);
  const { data: timeline } = useEntityTimeline(entityType, needsResolve ? undefined : entityId);
  // Story threads join the event stream as first-class rows: a blue marker on
  // the chart and a STORY row in the feed, each at the story's first coverage.
  const { data: storyThreads } = useEntityStoryThreads(
    entityType,
    needsResolve ? undefined : entityId,
    { limit: 10, status: "any" },
  );
  const events = useMemo<TimelineEvent[]>(() => {
    const storyRows: TimelineEvent[] = (storyThreads ?? [])
      .filter((t) => t.first_seen)
      .map((t) => ({
        event_type: "story",
        title: t.title,
        date: t.first_seen,
        entry_id: null,
        url: null,
        thread_slug: t.slug,
      }));
    return [...(timeline?.events ?? []), ...storyRows];
  }, [timeline, storyThreads]);
  // A story takes the same docked reader an article does — the profile stays
  // on screen as the list either way.
  const openStory = useOpenThread();

  // The CVE lifecycle strip reads the detail record; OverviewTab shares the
  // same query key, so this costs nothing when Overview is mounted too.
  const { data: cveDetail } = useCVE(entityType === "cve" && !needsResolve ? entityId : undefined);
  const { data: observableDetail } = useObservable(
    entityType === "observable" && !needsResolve ? entityId : undefined,
  );

  const [searchParams, setSearchParams] = useSearchParams();
  const [activeTab, setActiveTab] = useState<TabKey>("overview");
  // ?tab=notes / ?tab=ai land on the Overview module that absorbed those tabs.
  const [overviewAnchor, setOverviewAnchor] = useState<"notes" | null>(null);
  const [timeWindow, setTimeWindow] = useState<MentionsWindow>("90d");
  // The header chart ships collapsed to a pulse line; Expand unfolds the full
  // MentionsTimeline in place and the choice sticks across profiles.
  const [pulseExpanded, setPulseExpanded] = useState(
    () => localStorage.getItem("intelfeed:pulse-expanded") === "1",
  );
  const togglePulse = useCallback((next: boolean) => {
    setPulseExpanded(next);
    localStorage.setItem("intelfeed:pulse-expanded", next ? "1" : "0");
  }, []);

  // Stamp the visit when LEAVING the profile, not on render — stamping on
  // mount rebased the since-last-visit baseline on every tab flip and
  // permanently suppressed the ribbon within a session.
  useEffect(() => {
    if (!entityId) return;
    return () => {
      useIntelStore.getState().markEntityVisited(entityId);
    };
  }, [entityId]);
  useEffect(() => {
    // `?tab=` lets another surface open the profile *at* something — global
    // search sends an entity note straight to Notes — and is consumed on
    // arrival so the tab stays free to change afterwards.
    const requested = searchParams.get("tab");
    if (requested === "notes" || requested === "ai") {
      // The old Notes/AI tabs are Overview modules now — land there, scrolled.
      setActiveTab("overview");
      setOverviewAnchor(requested === "notes" ? "notes" : null);
      const next = new URLSearchParams(searchParams);
      next.delete("tab");
      setSearchParams(next, { replace: true });
      return;
    }
    if (requested && config?.tabs.includes(requested as TabKey) && !(isVisitor && VISITOR_HIDDEN_TABS.has(requested as TabKey))) {
      setActiveTab(requested as TabKey);
      const next = new URLSearchParams(searchParams);
      next.delete("tab");
      setSearchParams(next, { replace: true });
      return;
    }
    setActiveTab(config?.tabs[0] ?? "overview");
    // Re-running on every searchParams change would fight the user's own tab
    // clicks; only the entity or its config changing resets the tab.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entityId, config]);

  const updateEntity = useUpdateEntity();
  const updateField = useCallback(
    (field: string, value: string | string[]) => updateEntity(entityType, entityId, { [field]: value }),
    [updateEntity, entityType, entityId],
  );

  const entity = pivot?.entity;
  const related = pivot?.related;
  const entries = useMemo(() => pivot?.entries ?? [], [pivot]);
  const displayName = entityDisplayName(entity, entityId);

  // Record the current entity in the pivot trail (covers direct URL loads).
  useEffect(() => {
    if (entity && entityType) {
      addToRecentPivots({ type: entityType, id: entityId, label: displayName, timestamp: Date.now() });
    }
  }, [entity, entityType, entityId, displayName, addToRecentPivots]);

  // Field-level provenance for the header's "who says so" markers — one
  // request per profile, shared by every field on it.
  const { data: provenance } = useEntityProvenance(entityType, entityId);

  const openArticle = useCallback((entryId: string) => {
    // Every entry link on a profile opens the workbench's docked reader — the
    // profile stays put as the list, the same pairing as the rest of the app.
    useIntelStore.getState().openWorkbenchReader(entryId);
  }, []);

  const openEntity = useCallback(
    (type: EntityType, eid: string, label?: string) => {
      addToRecentPivots({ type, id: eid, label: label || eid, timestamp: Date.now() });
      navigate(entityProfilePath(type, eid));
    },
    [navigate, addToRecentPivots],
  );

  const relatedCountries = useMemo(
    () => (related?.countrys ?? []).map((c) => ({ id: c.id, name: c.name, region: c.region })),
    [related],
  );

  if (!entityType || !config) {
    return <div className={styles.loading}>Unknown entity type.</div>;
  }
  if (needsResolve || isLoading) {
    return <div className={styles.loading}>Loading profile…</div>;
  }
  if (!entity || !related) {
    return <div className={styles.loading}>This entity could not be loaded.</div>;
  }

  // Related arrays are truncated server-side; related_counts carries the
  // pre-truncation totals.
  const relatedCounts = pivot?.related_counts;
  const countOf = (key: string, arr?: unknown[]) => relatedCounts?.[key] ?? arr?.length ?? 0;
  const counts: Partial<Record<TabKey, number>> = {
    relationships:
      countOf("threat_actors", related.threat_actors) +
      countOf("malwares", related.malwares) +
      countOf("ttps", related.ttps) +
      countOf("cves", related.cves) +
      countOf("countrys", related.countrys) +
      countOf("sectors", related.sectors) +
      countOf("vendors", related.vendors) +
      countOf("products", related.products) +
      countOf("tools", related.tools) +
      countOf("mitigations", related.mitigations) +
      countOf("cwes", related.cwes),
    detection: countOf("detection_rules", related.detection_rules),
    vulnerabilities: affectedCount?.total ?? 0,
    weaknesses: cveWeaknessCount,
  };

  return (
    <div className={styles.page}>
      <ProfileHeader
        entityType={entityType}
        entityId={entityId}
        entity={entity}
        config={config}
        entries={entries}
        relatedCountries={relatedCountries}
        provenance={provenance}
        onUpdateField={updateField}
        onOpenEntity={openEntity}
        onOpenArticle={openArticle}
        onNavigateAway={() => navigate("/workbench/explore")}
      />

      {/* The activity readout (pulse line / expanded timeline) renders on every
          tab so the tab bar doesn't jump when switching away from Overview. */}
      <div className={styles.heroExtras}>
          {pulseExpanded ? (
            <MentionsTimeline
              entityType={entityType}
              entityId={entityId}
              events={events}
              window={timeWindow}
              onWindowChange={setTimeWindow}
              onOpenArticle={openArticle}
              onOpenEntity={openEntity}
              onOpenStory={openStory}
              onCollapse={() => togglePulse(false)}
            />
          ) : (
            <PulseLine
              entityType={entityType}
              entityId={entityId}
              window={timeWindow}
              onWindowChange={setTimeWindow}
              onExpand={() => togglePulse(true)}
            />
          )}
          {entityType === "cve" && <CveLifecycleStrip entity={entity} cveDetail={cveDetail} />}
          {entityType === "observable" && <ObservableLifecycleStrip detail={observableDetail} />}
        </div>

      {/* detection_gaps is in no config — it appends itself while active so
          the rail's "Review gaps" jump gets a highlighted tab and a way back. */}
      <ProfileTabs
        tabs={
          isVisitor
            ? config.tabs.filter((t) => !VISITOR_HIDDEN_TABS.has(t))
            : activeTab === "detection_gaps"
              ? [...config.tabs, "detection_gaps"]
              : config.tabs
        }
        active={activeTab}
        counts={counts}
        onChange={setActiveTab}
        trailing={activeTab === "overview" ? <OverviewDensityToggle /> : null}
      />

      <div className={styles.body}>
        {activeTab === "overview" && (
          <OverviewTab
            entityType={entityType}
            entityId={entityId}
            entity={entity}
            entityLabel={displayName}
            config={config}
            entries={entries}
            events={events}
            related={related}
            activitySince={windowCutoff(timeWindow)}
            onShowRelationships={() => setActiveTab("relationships")}
            onShowDetectionGaps={() => setActiveTab("detection_gaps")}
            onUpdateField={updateField}
            onOpenArticle={openArticle}
            onOpenEntity={openEntity}
            onOpenStory={openStory}
            provenance={provenance}
            anchor={overviewAnchor}
          />
        )}
        {activeTab === "vulnerabilities" && affectedKind && (
          <VulnerabilitiesTab mode={affectedKind} entityId={entityId} entityName={displayName} />
        )}
        {activeTab === "weaknesses" && entityType === "cve" && <WeaknessesTab entityId={entityId} />}
        {activeTab === "victimology" && entityType === "sector" && (
          <VictimologyTab entityId={entityId} entityLabel={displayName} onOpenEntity={openEntity} onOpenArticle={openArticle} />
        )}
        {activeTab === "relationships" && (
          <RelationshipsTab
            entityType={entityType}
            entityId={entityId}
            entityLabel={displayName}
            related={related}
            relatedCounts={relatedCounts}
            ruleCoverage={pivot?.rule_coverage}
            graphData={graphData}
            onOpenEntity={openEntity}
            onOpenArticle={openArticle}
            onOpenEntry={openArticle}
          />
        )}
        {activeTab === "detection" && !isVisitor && (
          <DetectionTab
            entityType={entityType}
            entityId={entityId}
            entity={entity}
            related={related}
            onNavigateRule={(ruleId) => navigate(`/workbench/rule/${ruleId}`)}
          />
        )}
        {activeTab === "geography" && <GeographyTab entityId={entityId} entityLabel={displayName} onOpenEntity={openEntity} />}
        {activeTab === "detection_gaps" && !isVisitor && (
          <DetectionGapsTab entityType={entityType} entityId={entityId} onOpenEntity={openEntity} />
        )}
      </div>
    </div>
  );
}
