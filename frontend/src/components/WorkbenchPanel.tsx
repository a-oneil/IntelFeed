import { useState, useCallback, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { useUIStore } from "@/stores/uiStore";
import { Chip } from "@/components/primitives";
import { severityChipColors } from "@/utils/severity";
import type { TTP, CVE, Country, EntrySector, ThreatActor, MalwareFamily, Mitigation, OffensiveTool, Vendor, Product, DetectionRule, DetectionRuleListItem, ExtractionStatus, GraphNode, GraphEdge, ObservableEntryPayload } from "@/api/types";
import {
  useEntryURLs,
  useEntryTTPs,
  useEntryKillChain,
  useEntryArticleMetadata,
  useEntryCVEs,
  useEntryCountries,
  useEntrySectors,
  useEntryThreatActors,
  useEntryMalware,
  useEntryMitigations,
  useEntryTools,
  useExtractTTPs,
  useExtractCVEs,
  useExtractThreatActors,
  useExtractMalware,
  useExtractCountries,
  useExtractMitigations,
  useExtractTools,
  useEntryVendors,
  useEntryProducts,
  useEntryObservables,
  usePromoteObservable,
  useDismissObservableCandidate,
  useGenerateDetectionRules,
  useDetectionRules,
  useDetectionRule,
  useUpdateDetectionRule,
  useDeleteDetectionRule,
  useNavigatorLayer,
  useAutolinkEntry,
} from "@/hooks/useIntelligence";
import { useEntryInsights } from "@/hooks/useAnalytics";
import { getPivotLinks } from "@/utils/pivotLinks";
import { defangObservable, stixBundle } from "@/utils/observables";
import { toast } from "sonner";
import { useEntryGraph } from "@/hooks/useCorrelation";
import { useDetectGlossaryTerms } from "@/hooks/useGlossary";
import type { GlossaryMatch } from "@/api/types";
import { useIntelStore } from "@/stores/intelStore";
import { UnlinkArticleButton } from "./UnlinkArticleButton";
import { ActionableInsights } from "./ActionableInsights";
import { EntityGraph } from "./EntityGraph";
import EntityActionMenu from "./EntityActionMenu";
import { CampaignMenuButton } from "./CampaignMenuButton";
import { GlossaryPanel } from "./GlossaryPanel";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import api from "@/api/client";
import { useOpenEntry } from "@/utils/openEntry";
import styles from "./WorkbenchPanel.module.css";
import { useIsVisitor } from "@/stores/authStore";

/**
 * Severity chip colours come from the shared `severityChipColors` helper — the
 * one place that pairs each --severity-* fill with a measured foreground. The
 * old local map painted the fill hue as TEXT (`.severityHigh` was a raw
 * #e74c3c); this fills instead, so the foreground has to be derived, not
 * guessed. An unrecognised severity has no fill, so it falls back to the
 * neutral chip rather than rendering white-on-nothing.
 */
function severityChipProps(level: string | null | undefined) {
  const colors = severityChipColors(level);
  return { tone: colors.tint ? ("solid" as const) : ("default" as const), ...colors };
}

interface PreloadedData {
  ttps?: TTP[];
  cves?: CVE[];
  actors?: ThreatActor[];
  malware?: MalwareFamily[];
  countries?: Country[];
  sectors?: EntrySector[];
  mitigations?: Mitigation[];
  tools?: OffensiveTool[];
  vendors?: Vendor[];
  products?: Product[];
  rules?: DetectionRule[];
  urls?: { url: string; context: string }[];
}

interface WorkbenchPanelProps {
  entryId: string;
  entryTitle: string;
  /** Read-only mode for shared pages — hides mutation UI, uses preloaded data */
  readOnly?: boolean;
  preloadedData?: PreloadedData;
  /** Search-related-articles handler for glossary terms (from EntryReader). */
  onGlossarySearch?: (term: GlossaryMatch["term"]) => void;
  /** Increment to force the Glossary section open (e.g. from in-article tooltips). */
  expandGlossarySignal?: number;
}

export default function WorkbenchPanel({
  entryId,
  entryTitle: _entryTitle,
  readOnly,
  preloadedData,
  onGlossarySearch,
  expandGlossarySignal,
}: WorkbenchPanelProps) {
  const navigate = useNavigate();
  const openEntry = useOpenEntry();
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set());

  // In readOnly mode, pass empty entryId to hooks so they don't fire (enabled: !!entryId)
  const fetchId = readOnly ? "" : entryId;
  // Public read-only mode: the extracted intel reads like the share page's —
  // no extraction, rules, campaigns or observables, nothing that edits.
  const isVisitor = useIsVisitor();
  const editLocked = readOnly || isVisitor;

  const { data: entryUrls } = useEntryURLs(fetchId);
  const { data: hookTTPs, isLoading: ttpsLoading } = useEntryTTPs(fetchId);
  const { data: hookCVEs, isLoading: cvesLoading } = useEntryCVEs(fetchId);
  const { data: hookActors, isLoading: actorsLoading } = useEntryThreatActors(fetchId);
  const { data: hookMalware, isLoading: malwareLoading } = useEntryMalware(fetchId);
  const { data: hookCountries, isLoading: countriesLoading } = useEntryCountries(fetchId);
  const { data: hookSectors, isLoading: sectorsLoading } = useEntrySectors(fetchId);
  const { data: hookMitigations, isLoading: mitigationsLoading } = useEntryMitigations(fetchId);
  const { data: hookTools, isLoading: toolsLoading } = useEntryTools(fetchId);
  const { data: hookVendors, isLoading: vendorsLoading } = useEntryVendors(fetchId);
  const { data: hookProducts, isLoading: productsLoading } = useEntryProducts(fetchId);
  const { data: hookObservables, isLoading: observablesLoading } = useEntryObservables(isVisitor ? "" : fetchId);
  const { data: rulesData, isLoading: rulesLoading } = useDetectionRules(
    editLocked ? { entry_id: "" } : { entry_id: entryId },
  );
  // Observables stay off the map unless asked for — ledger atoms as nodes is
  // the graph bloat the design guards against.
  const [graphObservables, setGraphObservables] = useState(false);
  const { data: graphData, isLoading: graphLoading } = useEntryGraph(fetchId, graphObservables);
  const { data: glossaryMatches, isLoading: glossaryLoading } = useDetectGlossaryTerms(fetchId);

  // In-article glossary tooltips can request the Glossary section be opened.
  useEffect(() => {
    if (expandGlossarySignal) {
      setExpandedSections((prev) => new Set(prev).add("glossary"));
    }
  }, [expandGlossarySignal]);

  // Use preloaded data when readOnly, otherwise use hook data
  const ttps = readOnly ? (preloadedData?.ttps || []) : hookTTPs;
  const cves = readOnly ? (preloadedData?.cves || []) : hookCVEs;
  const actors = readOnly ? (preloadedData?.actors || []) : hookActors;
  const malware = readOnly ? (preloadedData?.malware || []) : hookMalware;
  const countries = readOnly ? (preloadedData?.countries || []) : hookCountries;
  const sectors = readOnly ? (preloadedData?.sectors || []) : hookSectors;
  const mitigations = readOnly ? (preloadedData?.mitigations || []) : hookMitigations;
  const tools = readOnly ? (preloadedData?.tools || []) : hookTools;
  const vendors = readOnly ? (preloadedData?.vendors || []) : hookVendors;
  const products = readOnly ? (preloadedData?.products || []) : hookProducts;
  const actualUrls = readOnly ? (preloadedData?.urls || []) : entryUrls;
  const observablePayload: ObservableEntryPayload = readOnly
    ? { items: [], candidates: [] }
    : (hookObservables ?? { items: [], candidates: [] });

  const extractTTPs = useExtractTTPs();
  const extractCVEs = useExtractCVEs();
  const extractActors = useExtractThreatActors();
  const extractMalware = useExtractMalware();
  const extractCountries = useExtractCountries();
  const extractMitigations = useExtractMitigations();
  const extractTools = useExtractTools();
  const autolinkEntry = useAutolinkEntry();
  const generateRules = useGenerateDetectionRules();
  const { refetch: fetchNavigator } = useNavigatorLayer(
    ttps?.length ? entryId : undefined
  );

  const [extractionStatus, setExtractionStatus] = useState<Record<string, ExtractionStatus>>({});

  const isExtracting =
    extractTTPs.isPending ||
    extractCVEs.isPending ||
    extractActors.isPending ||
    extractMalware.isPending ||
    extractCountries.isPending ||
    extractMitigations.isPending ||
    extractTools.isPending;

  const handleExtractAll = async () => {
    await autolinkEntry.mutateAsync(entryId).catch(() => {});

    const results = await Promise.allSettled([
      extractTTPs.mutateAsync({ entryId }),
      extractCVEs.mutateAsync({ entryId }),
      extractActors.mutateAsync(entryId),
      extractMalware.mutateAsync(entryId),
      extractCountries.mutateAsync(entryId),
      extractMitigations.mutateAsync({ entryId }),
      extractTools.mutateAsync(entryId),
    ]);

    const statuses: Record<string, ExtractionStatus> = {};
    const keys = ["ttps", "cves", "actors", "malware", "countries", "mitigations", "tools"];
    results.forEach((r, i) => {
      if (r.status === "fulfilled" && r.value && "status" in r.value) {
        statuses[keys[i]] = r.value.status as ExtractionStatus;
      }
    });
    setExtractionStatus(statuses);

    // Auto-expand sections that have data after extraction
    // We use a short delay to allow query cache to update
    setTimeout(() => {
      const sectionsToExpand = new Set<string>();
      if (ttps?.length) sectionsToExpand.add("ttps");
      if (cves?.length) sectionsToExpand.add("cves");
      if (actors?.length) sectionsToExpand.add("actors");
      if (malware?.length) sectionsToExpand.add("malware");
      if (countries?.length) sectionsToExpand.add("countries");
      if (mitigations?.length) sectionsToExpand.add("mitigations");
      if (tools?.length) sectionsToExpand.add("tools");
      if (sectionsToExpand.size > 0) setExpandedSections(sectionsToExpand);
    }, 500);
  };

  const handleDownloadNavigator = async () => {
    const { data } = await fetchNavigator();
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "navigator-layer.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleGenerateRules = () => {
    generateRules.mutate({
      entryId,
      ruleTypes: ["sigma", "splunk_spl"],
    });
  };

  const rules = readOnly ? (preloadedData?.rules || []) : (rulesData?.items || []);

  const hasAnyEntities = !!(ttps?.length || cves?.length || actors?.length || malware?.length || countries?.length || mitigations?.length || tools?.length || rules.length);
  const hasExtractedThisSession = Object.keys(extractionStatus).length > 0;
  const hasExtracted = hasAnyEntities || hasExtractedThisSession;

  const autoOpenIntelPanel = useIntelStore((s) => s.autoOpenIntelPanel);
  const toggleAutoOpenIntelPanel = useIntelStore((s) => s.toggleAutoOpenIntelPanel);

  const toggleSection = useCallback((section: string) => {
    setExpandedSections((prev) => {
      const next = new Set(prev);
      if (next.has(section)) next.delete(section);
      else next.add(section);
      return next;
    });
  }, []);

  // Entity counts for the summary overview
  const ttpCount = ttps?.length ?? 0;
  const cveCount = cves?.length ?? 0;
  const actorCount = actors?.length ?? 0;
  const malwareCount = malware?.length ?? 0;
  const countryCount = countries?.length ?? 0;
  const sectorCount = sectors?.length ?? 0;
  const mitigationCount = mitigations?.length ?? 0;
  const toolCount = tools?.length ?? 0;
  const vendorCount = vendors?.length ?? 0;
  const productCount = products?.length ?? 0;
  const ruleCount = rules.length;
  const totalEntities = ttpCount + cveCount + actorCount + malwareCount + countryCount + sectorCount + mitigationCount + toolCount + vendorCount + productCount;

  return (
    <div className={styles.panel}>
      {/* Action bar — hidden in readOnly mode and for visitors */}
      {!editLocked && (
        <div className={styles.actionBarPrimary}>
          <button
            className={styles.actionBtnPrimary}
            onClick={handleExtractAll}
            disabled={isExtracting}
          >
            {isExtracting ? "Extracting..." : "Extract All"}
          </button>
          <button
            className={styles.actionBtn}
            onClick={handleGenerateRules}
            disabled={generateRules.isPending}
          >
            {generateRules.isPending ? "Generating..." : "Gen Rules"}
          </button>
          <CampaignMenuButton entryId={entryId} />

          {ttps && ttps.length > 0 && (
            <button
              className={`${styles.actionBtn} ${styles.actionBtnAccent}`}
              onClick={handleDownloadNavigator}
              title="Download ATT&CK Navigator layer JSON"
            >
              Navigator
            </button>
          )}
          <button
            className={`${styles.actionBtn} ${styles.actionBtnAuto} ${autoOpenIntelPanel ? styles.actionBtnAutoActive : ""}`}
            onClick={toggleAutoOpenIntelPanel}
            title={autoOpenIntelPanel ? "Auto-open enabled for high-value entries" : "Auto-open disabled"}
          >
            Auto-Open
          </button>
        </div>
      )}

      {/* Scrollable content area */}
      <div className={styles.scrollArea}>
        {/* Extraction status banners — hidden in readOnly */}
        {!readOnly && <ExtractionStatusBanner status={extractionStatus.ttps} label="TTP" />}

        {/* Sections in fixed alphabetical order \u2014 stable between articles */}
        <AccordionSection
          title="CVEs"
          count={cveCount}
          loading={readOnly ? false : cvesLoading}
          expanded={expandedSections.has("cves")}
          onToggle={() => toggleSection("cves")}
          accentClass={cveCount > 0 ? styles.sectionAccentCVE : undefined}
        >
          <CVEList cves={cves || []} entryId={entryId} hasExtracted={hasExtracted} readOnly={editLocked} />
        </AccordionSection>
        <AccordionSection
          title="Countries"
          count={countryCount}
          loading={readOnly ? false : countriesLoading}
          expanded={expandedSections.has("countries")}
          onToggle={() => toggleSection("countries")}
          accentClass={countryCount > 0 ? styles.sectionAccentCountry : undefined}
        >
          <CountryList countries={countries || []} entryId={entryId} hasExtracted={hasExtracted} readOnly={editLocked} />
        </AccordionSection>
        <AccordionSection
          title="Sectors"
          count={sectorCount}
          loading={readOnly ? false : sectorsLoading}
          expanded={expandedSections.has("sectors")}
          onToggle={() => toggleSection("sectors")}
          accentClass={sectorCount > 0 ? styles.sectionAccentSector : undefined}
        >
          <SectorList sectors={sectors || []} entryId={entryId} hasExtracted={hasExtracted} readOnly={editLocked} />
        </AccordionSection>
        {!isVisitor && (
        <AccordionSection
          title="Detection Rules"
          count={ruleCount}
          loading={readOnly ? false : rulesLoading}
          expanded={expandedSections.has("rules")}
          onToggle={() => toggleSection("rules")}
          accentClass={ruleCount > 0 ? styles.sectionAccentRule : undefined}
        >
          <RuleList rules={rules} hasExtracted={hasExtracted} hasEntities={!!(ttpCount || cveCount)} readOnly={editLocked} />
        </AccordionSection>
        )}
        {/* Entity Graph — hidden in readOnly (requires auth endpoint) */}
        {!readOnly && graphData && graphData.nodes.length >= 2 && (
          <div className={styles.section}>
            <button
              className={styles.sectionHeader}
              onClick={() => toggleSection("graph")}
              style={{ borderLeftColor: "var(--accent)" }}
            >
              <span className={styles.sectionTitle}>Entity Graph</span>
              <span className={styles.sectionCount}>{graphData.nodes.length}</span>
              <span className={styles.sectionArrow}>
                {expandedSections.has("graph") ? "\u25B4" : "\u25BE"}
              </span>
            </button>
            {expandedSections.has("graph") && (
              <>
                <div className={styles.graphContainer}>
                  <EntityGraph
                    nodes={graphData.nodes}
                    edges={graphData.edges}
                    height={280}
                    onNodeClick={(nodeId, nodeType) => {
                      const rawId = nodeId.includes("-") ? nodeId.split("-").slice(1).join("-") : nodeId;
                      const pathSegment = nodeType;
                      navigate(`/workbench/${pathSegment}/${rawId}`);
                    }}
                    // Docked in the workbench this swaps the dock rather than
                    // bouncing the analyst out to the feed.
                    onEntryClick={openEntry}
                  />
                </div>
                <EntityRelationshipSummary nodes={graphData.nodes} edges={graphData.edges} />
                <label className={styles.graphObsToggle} title="Ledger atoms as nodes — off by default to keep the map readable">
                  <input
                    type="checkbox"
                    checked={graphObservables}
                    onChange={(e) => setGraphObservables(e.target.checked)}
                  />
                  Show observables
                </label>
              </>
            )}
          </div>
        )}
        {!readOnly && graphLoading && totalEntities > 0 && (
          <div className={styles.section}>
            <div className={styles.sectionHeader} style={{ borderLeftColor: "var(--accent)" }}>
              <span className={styles.sectionTitle}>Entity Graph</span>
              <span className={styles.sectionCount}>
                <span className={styles.aiTaskSpinner} />
              </span>
            </div>
          </div>
        )}

        {!readOnly && (
          <AccordionSection
            title="Glossary"
            count={glossaryMatches?.length ?? 0}
            loading={glossaryLoading}
            expanded={expandedSections.has("glossary")}
            onToggle={() => toggleSection("glossary")}
            accentClass={(glossaryMatches?.length ?? 0) > 0 ? styles.sectionAccentGlossary : undefined}
          >
            <GlossaryPanel matches={glossaryMatches ?? []} isLoading={glossaryLoading} onSearchArticles={onGlossarySearch} />
          </AccordionSection>
        )}
        {/* Intelligence Insights (PIR matches live in their own section) */}
        {!editLocked && (
          <InsightsSection entryId={entryId} expanded={expandedSections.has("insights")} onToggle={() => toggleSection("insights")} />
        )}
        <AccordionSection
          title="Malware"
          count={malwareCount}
          loading={readOnly ? false : malwareLoading}
          expanded={expandedSections.has("malware")}
          onToggle={() => toggleSection("malware")}
          accentClass={malwareCount > 0 ? styles.sectionAccentMalware : undefined}
        >
          <MalwareList malware={malware || []} entryId={entryId} hasExtracted={hasExtracted} readOnly={editLocked} />
        </AccordionSection>
        <AccordionSection
          title="Mitigations"
          count={mitigationCount}
          loading={readOnly ? false : mitigationsLoading}
          expanded={expandedSections.has("mitigations")}
          onToggle={() => toggleSection("mitigations")}
          accentClass={mitigationCount > 0 ? styles.sectionAccentMitigation : undefined}
        >
          <MitigationList mitigations={mitigations || []} entryId={entryId} hasExtracted={hasExtracted} readOnly={editLocked} />
        </AccordionSection>
        {(observablePayload.items.length > 0 || observablePayload.candidates.length > 0) && (
          <AccordionSection
            title="Observables"
            count={observablePayload.items.length}
            loading={readOnly ? false : observablesLoading}
            expanded={expandedSections.has("observables")}
            onToggle={() => toggleSection("observables")}
            accentClass={styles.sectionAccentObservable}
          >
            <ObservableList payload={observablePayload} entryId={entryId} readOnly={editLocked} />
          </AccordionSection>
        )}
        <AccordionSection
          title="Tools"
          count={toolCount}
          loading={readOnly ? false : toolsLoading}
          expanded={expandedSections.has("tools")}
          onToggle={() => toggleSection("tools")}
          accentClass={toolCount > 0 ? styles.sectionAccentTool : undefined}
        >
          <ToolList tools={tools || []} entryId={entryId} hasExtracted={hasExtracted} readOnly={editLocked} />
        </AccordionSection>
        {!editLocked && (
          <PIRSection entryId={entryId} expanded={expandedSections.has("pir")} onToggle={() => toggleSection("pir")} />
        )}
        <AccordionSection
          title="Products"
          count={productCount}
          loading={readOnly ? false : productsLoading}
          expanded={expandedSections.has("products")}
          onToggle={() => toggleSection("products")}
          accentClass={productCount > 0 ? styles.sectionAccentProduct : undefined}
        >
          <ProductList products={products || []} entryId={entryId} hasExtracted={hasExtracted} readOnly={editLocked} />
        </AccordionSection>
        {(actualUrls?.length ?? 0) > 0 && (
          <AccordionSection
            title="Referenced URLs"
            count={actualUrls?.length ?? 0}
            loading={false}
            expanded={expandedSections.has("urls")}
            onToggle={() => toggleSection("urls")}
            accentClass={(actualUrls?.length ?? 0) > 0 ? styles.sectionAccentURLs : undefined}
          >
            <URLList urls={actualUrls || []} />
          </AccordionSection>
        )}
        <AccordionSection
          title="Threat Actors"
          count={actorCount}
          loading={readOnly ? false : actorsLoading}
          expanded={expandedSections.has("actors")}
          onToggle={() => toggleSection("actors")}
          accentClass={actorCount > 0 ? styles.sectionAccentActor : undefined}
        >
          <ActorList actors={actors || []} entryId={entryId} hasExtracted={hasExtracted} readOnly={editLocked} />
        </AccordionSection>
        <AccordionSection
          title="TTPs (MITRE ATT&CK)"
          count={ttpCount}
          loading={readOnly ? false : ttpsLoading}
          expanded={expandedSections.has("ttps")}
          onToggle={() => toggleSection("ttps")}
          accentClass={ttpCount > 0 ? styles.sectionAccentTTP : undefined}
        >
          <TTPList ttps={ttps || []} entryId={entryId} hasExtracted={hasExtracted} readOnly={editLocked} />
        </AccordionSection>
        <AccordionSection
          title="Vendors"
          count={vendorCount}
          loading={readOnly ? false : vendorsLoading}
          expanded={expandedSections.has("vendors")}
          onToggle={() => toggleSection("vendors")}
          accentClass={vendorCount > 0 ? styles.sectionAccentVendor : undefined}
        >
          <VendorList vendors={vendors || []} entryId={entryId} hasExtracted={hasExtracted} readOnly={editLocked} />
        </AccordionSection>
      </div>
    </div>
  );
}

/* ─── Insights Section ─── */

function InsightsSection({ entryId, expanded, onToggle }: { entryId: string; expanded: boolean; onToggle: () => void }) {
  const { data: insights, isLoading } = useEntryInsights(entryId);

  // PIR matches have their own section — everything else stays here.
  const count = insights?.filter((i) => i.type !== "requirement_match").length ?? 0;
  if (count === 0 && !isLoading) return null;

  return (
    <AccordionSection
      title="Intelligence Insights"
      count={count}
      loading={isLoading}
      expanded={expanded}
      onToggle={onToggle}
      accentClass={count > 0 ? styles.sectionAccentInsights : undefined}
    >
      <ActionableInsights entryId={entryId} excludeTypes={["requirement_match"]} />
    </AccordionSection>
  );
}

/* ─── PIR Matches Section ─── */

function PIRSection({ entryId, expanded, onToggle }: { entryId: string; expanded: boolean; onToggle: () => void }) {
  const { data: insights, isLoading: insightsLoading } = useEntryInsights(entryId);
  // PIR matches from intel-counts (always available, unlike analytics insights)
  const { data: pirData, isLoading: pirLoading } = useQuery({
    queryKey: ["entry-intel-counts-single", entryId],
    queryFn: async () => {
      const { data } = await api.post<Record<string, { pir_matches?: Array<{ id: string; title: string; priority: string; category: string }> }>>(
        "/entries/intel-counts",
        [entryId],
      );
      return data[entryId]?.pir_matches || [];
    },
    enabled: !!entryId,
    staleTime: 60_000,
  });

  const requirementCount = insights?.filter((i) => i.type === "requirement_match").length ?? 0;
  const pirCount = pirData?.length ?? 0;
  // Both sources describe the same matches — don't double-count.
  const count = requirementCount > 0 ? requirementCount : pirCount;
  const isLoading = insightsLoading || pirLoading;
  if (count === 0 && !isLoading) return null;

  return (
    <AccordionSection
      title="PIR Matches"
      count={count}
      loading={isLoading}
      expanded={expanded}
      onToggle={onToggle}
      accentClass={count > 0 ? styles.sectionAccentPIR : undefined}
    >
      {requirementCount > 0 && (
        <ActionableInsights entryId={entryId} includeTypes={["requirement_match"]} />
      )}
      {requirementCount === 0 && pirData && pirData.length > 0 && (
        <div className={styles.cardList}>
          {pirData.map((pir) => (
            <div key={pir.id} className={styles.pirInsightCard} data-priority={pir.priority}>
              <span className={styles.pirInsightBody}>
                <span className={styles.pirInsightLabel}>{pir.category}</span>
                <span className={styles.pirInsightTitle}>{pir.title}</span>
              </span>
              <span className={styles.pirInsightPriority}>{pir.priority}</span>
            </div>
          ))}
        </div>
      )}
    </AccordionSection>
  );
}



/* ─── Entity History Badge ─── */

function formatRelativeTime(dateStr: string | null | undefined): string | null {
  if (!dateStr) return null;
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.floor(days / 30);
  return `${months}mo ago`;
}

function HistoryBadge({ firstSeen, articleCount, searchValue }: { firstSeen?: string | null; articleCount?: number | null; searchValue?: string }) {
  const navigate = useNavigate();
  const setHeaderSearchQuery = useUIStore((s) => s.setHeaderSearchQuery);
  const time = formatRelativeTime(firstSeen);
  if (!time && !articleCount) return null;

  const handleArticleClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (searchValue) {
      setHeaderSearchQuery(searchValue);
      navigate("/search");
    }
  };

  return (
    <span className={styles.historyBadge} title={firstSeen ? `First seen: ${new Date(firstSeen).toLocaleDateString()}` : undefined}>
      {time && <span>{time}</span>}
      {time && articleCount != null && articleCount > 0 && <span className={styles.historyDot}>{"\u00B7"}</span>}
      {articleCount != null && articleCount > 0 && (
        <span
          className={searchValue ? styles.historyArticleLink : undefined}
          onClick={searchValue ? handleArticleClick : undefined}
          title={searchValue ? "Search related articles" : undefined}
        >
          {articleCount} art.
        </span>
      )}
    </span>
  );
}

/* ─── Entity Relationship Summary ─── */

function EntityRelationshipSummary({ nodes, edges }: { nodes: GraphNode[]; edges: GraphEdge[] }) {
  const [showAll, setShowAll] = useState(false);

  if (!edges.length) return null;

  const nodeMap = new Map(nodes.map((n) => [n.id, n.label]));
  const lines = edges
    .sort((a, b) => b.weight - a.weight)
    .map((edge) => ({
      source: nodeMap.get(edge.source) || edge.source,
      label: edge.label || "related to",
      target: nodeMap.get(edge.target) || edge.target,
    }));

  const visible = showAll ? lines : lines.slice(0, 5);

  return (
    <div className={styles.relationshipSummary}>
      {visible.map((line, i) => (
        <div key={i} className={styles.relationshipLine}>
          <span className={styles.relationshipEntity}>{line.source}</span>
          <span className={styles.relationshipArrow}>{"\u2192"}</span>
          <span className={styles.relationshipLabel}>{line.label}</span>
          <span className={styles.relationshipArrow}>{"\u2192"}</span>
          <span className={styles.relationshipEntity}>{line.target}</span>
        </div>
      ))}
      {lines.length > 5 && (
        <button
          className={styles.lowConfidenceToggle}
          onClick={() => setShowAll(!showAll)}
        >
          {showAll ? "Show fewer" : `Show all ${lines.length} relationships`}
        </button>
      )}
    </div>
  );
}

/* ─── Copy Button ─── */

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <button
      className={`${styles.copyBtn} ${copied ? styles.copyBtnDone : ""}`}
      onClick={handleCopy}
      title={copied ? "Copied!" : `Copy ${value}`}
    >
      {copied ? "\u2713" : (
        <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
          <rect x="5.5" y="5.5" width="9" height="9" rx="1.5" />
          <path d="M10.5 5.5V3a1.5 1.5 0 0 0-1.5-1.5H3A1.5 1.5 0 0 0 1.5 3v6A1.5 1.5 0 0 0 3 10.5h2.5" />
        </svg>
      )}
    </button>
  );
}

/* ─── AI Analysis Section ─── */
// Extracted to AIAnalysisSection.tsx for reuse on shared pages

/* ─── Accordion Section ─── */

function AccordionSection({
  title,
  count,
  loading,
  expanded,
  onToggle,
  accentClass,
  children,
}: {
  title: string;
  count: number;
  loading: boolean;
  expanded: boolean;
  onToggle: () => void;
  accentClass?: string;
  children: React.ReactNode;
}) {
  if (count === 0 && !loading) return null;

  return (
    <div className={`${styles.section} ${accentClass || ""}`}>
      <button className={styles.sectionHeader} onClick={onToggle}>
        <span className={styles.sectionTitle}>{title}</span>
        <span className={styles.sectionCount}>
          {loading ? "..." : count}
        </span>
        <span className={styles.sectionArrow}>{expanded ? "\u25B4" : "\u25BE"}</span>
      </button>
      {expanded && (
        <div className={styles.sectionBody}>
          {loading ? (
            <div className={styles.skeletonList}>
              <div className={styles.skeletonCard} />
              <div className={styles.skeletonCard} />
              <div className={styles.skeletonCard} />
            </div>
          ) : children}
        </div>
      )}
    </div>
  );
}

/* ─── Extraction Status ─── */

const STATUS_MESSAGES: Record<string, string> = {
  ai_not_configured: "AI provider not configured for this task. Configure in Settings > AI.",
  provider_error: "AI extraction failed. Check provider settings and try again.",
  parse_error: "AI returned unexpected format. Results may be incomplete.",
};

function ExtractionStatusBanner({ status, label }: { status: ExtractionStatus | undefined; label?: string }) {
  if (!status || status === "success") return null;
  return (
    <div className={styles.statusBanner}>
      {label && <strong>{label}: </strong>}
      {STATUS_MESSAGES[status] || "Extraction encountered an issue."}
    </div>
  );
}

/* ─── URL List (extracted article URLs for pivoting) ─── */

function URLList({ urls }: { urls: { url: string; context: string }[] }) {
  const [expanded, setExpanded] = useState(false);
  const visible = expanded ? urls : urls.slice(0, 10);

  return (
    <div className={styles.cardList}>
      {visible.map((u, i) => (
        <div key={i} className={`${styles.entityCard} ${styles.entityCardURL}`}>
          <div className={styles.entityCardRow}>
            <Chip className={`${styles.typeBadge} ${styles.typeBadgeURL}`}>URL</Chip>
            <a
              href={u.url}
              target="_blank"
              rel="noopener noreferrer"
              className={styles.entityValue}
              title={u.context}
              style={{ textDecoration: "none" }}
            >
              {u.url.length > 80 ? u.url.slice(0, 80) + "…" : u.url}
            </a>
          </div>
        </div>
      ))}
      {urls.length > 10 && (
        <button
          className={styles.lowConfidenceToggle}
          onClick={() => setExpanded(!expanded)}
        >
          {expanded ? "Show fewer" : `Show all ${urls.length} URLs`}
        </button>
      )}
    </div>
  );
}

/* ─── Observables (the IOC ledger) ─── */

const OBSERVABLE_KIND_GROUPS: Array<[string, string[]]> = [
  ["IPs", ["ipv4", "ipv6"]],
  ["Domains", ["domain"]],
  ["URLs & paths", ["url", "uri_path"]],
  ["Hashes & fingerprints", ["md5", "sha1", "sha256", "cert_fingerprint", "ja3", "ja4"]],
  ["Commands & host artifacts", ["cmdline", "registry", "path", "mutex", "named_pipe", "service_name", "scheduled_task", "user_agent", "http_header"]],
  ["Scripts", ["script"]],
  ["Emails", ["email"]],
];

function ObservableList({
  payload,
  entryId,
  readOnly,
}: {
  payload: ObservableEntryPayload;
  entryId: string;
  readOnly?: boolean;
}) {
  const navigate = useNavigate();
  const promote = usePromoteObservable();
  const dismiss = useDismissObservableCandidate();
  const [candidatesOpen, setCandidatesOpen] = useState(false);
  const [copiedAll, setCopiedAll] = useState<string | null>(null);
  const { items, candidates } = payload;

  const grouped = OBSERVABLE_KIND_GROUPS.map(
    ([label, kinds]) => [label, items.filter((i) => kinds.includes(i.kind))] as const,
  );
  // Self-healing: a kind the groups don't know yet still renders instead of
  // silently vanishing while the header counts it.
  const knownKinds = new Set(OBSERVABLE_KIND_GROUPS.flatMap(([, kinds]) => kinds));
  const groups = [...grouped, ["Other", items.filter((i) => !knownKinds.has(i.kind))] as const].filter(
    ([, rows]) => rows.length > 0,
  );

  const copyAll = async (mode: "plain" | "defanged" | "csv" | "stix") => {
    const text =
      mode === "stix"
        ? stixBundle(items)
        : (mode === "csv"
            ? [
                "kind,value,role,confidence",
                ...items.map(
                  (i) =>
                    `${i.kind},"${i.value.replace(/"/g, '""')}",${i.role ?? ""},${i.current_confidence.toFixed(2)}`,
                ),
              ]
            : items.map((i) => (mode === "defanged" ? defangObservable(i.kind, i.value) : i.value))
          ).join("\n");
    try {
      await navigator.clipboard.writeText(text);
      setCopiedAll(mode);
      setTimeout(() => setCopiedAll(null), 1500);
    } catch {
      toast.error("Copy failed — clipboard unavailable");
    }
  };

  return (
    <div className={styles.cardList}>
      {groups.map(([label, rows]) => (
        <div key={label}>
          <div className={styles.obsKindLabel}>
            {label} · {rows.length}
          </div>
          {rows.map((o) => (
            <div key={o.id} className={styles.entityCardRow}>
              <span
                className={`${styles.entityValue} ${styles.obsValue}`}
                title={[o.label, o.role && `role: ${o.role}`, o.evidence].filter(Boolean).join(" — ") || o.value}
                onClick={readOnly ? undefined : () => navigate(`/workbench/observable/${o.id}`)}
              >
                {o.kind === "script" && o.label ? `“${o.label}” · ${o.value.slice(0, 12)}…` : o.value}
              </span>
              <span className={styles.obsConf} title={`Current confidence${o.status !== "active" ? ` · ${o.status}` : ""}`}>
                {Math.round(o.current_confidence * 100)}%
              </span>
              <span onClick={(e) => e.stopPropagation()}>
                <CopyButton value={o.value} />
              </span>
            </div>
          ))}
        </div>
      ))}
      {candidates.length > 0 && !readOnly && (
        <div className={styles.obsCandidates}>
          <button className={styles.lowConfidenceToggle} onClick={() => setCandidatesOpen(!candidatesOpen)}>
            Candidates · {candidates.length} — not captured{" "}
            <span className="caret-glyph">{candidatesOpen ? "▴" : "▾"}</span>
          </button>
          {candidatesOpen &&
            candidates.map((c) => (
              <div key={`${c.kind}:${c.value}`} className={`${styles.entityCardRow} ${styles.obsCandidateRow}`}>
                <span className={`${styles.entityValue} ${styles.obsValue} ${styles.obsCandidateValue}`} title={`${c.kind} — pattern nomination, judged by no door`}>
                  {c.value}
                </span>
                <button
                  className={styles.obsPromoteBtn}
                  disabled={promote.isPending}
                  onClick={() =>
                    promote.mutate({ entryId, kind: c.kind, value: c.value, surfaceForm: c.surface_form })
                  }
                  title="Promote to the ledger (analyst door)"
                >
                  promote
                </button>
                <button
                  className={styles.obsPromoteBtn}
                  disabled={dismiss.isPending}
                  onClick={() => dismiss.mutate({ entryId, kind: c.kind, value: c.value })}
                  title="Dismiss from this article (the value can nominate again elsewhere)"
                >
                  dismiss
                </button>
              </div>
            ))}
        </div>
      )}
      {items.length > 0 && (
        <div className={styles.obsCopyAllRow}>
          <span className={styles.obsKindLabel}>Copy all {items.length}</span>
          {(["plain", "defanged", "csv", "stix"] as const).map((mode) => (
            <button key={mode} className={styles.obsPromoteBtn} onClick={() => copyAll(mode)}>
              {copiedAll === mode ? "✓" : mode}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/* ─── Attack-chain (kill-chain) strip — plan item 3.9.4 ─── */

function KillChainStrip({ entryId, readOnly }: { entryId: string; readOnly?: boolean }) {
  const navigate = useNavigate();
  const { data: phases } = useEntryKillChain(readOnly ? undefined : entryId);
  // Only worth showing once the attack spans at least two ordered phases.
  const ordered = (phases || []).filter((p) => p.tactic !== null);
  if (ordered.length < 2) return null;
  return (
    <div className={styles.killChain} title="Attack chain — techniques ordered by ATT&CK kill-chain phase">
      {ordered.map((phase, i) => (
        <div key={phase.tactic} className={styles.killChainPhase}>
          <span className={styles.killChainLabel}>{phase.label}</span>
          <div className={styles.killChainTechs}>
            {phase.techniques.map((t) => (
              <span
                key={`${phase.tactic}-${t.technique_id}`}
                className={styles.killChainTech}
                title={t.technique_name}
                onClick={readOnly ? undefined : () => navigate(`/workbench/explore?section=ttps&rules_q=${t.technique_id}`)}
              >
                {t.technique_id}
              </span>
            ))}
          </div>
          {i < ordered.length - 1 && <span className={styles.killChainArrow}>→</span>}
        </div>
      ))}
    </div>
  );
}

/* ─── Article intelligence metadata — plan items 3.9.6–3.9.9 ─── */

const REPORT_TYPE_LABELS: Record<string, string> = {
  news: "News",
  advisory: "Advisory",
  incident_report: "Incident Report",
  malware_analysis: "Malware Analysis",
  research: "Research",
  vendor_marketing: "Vendor Marketing",
  opinion: "Opinion",
};

function ArticleIntelCard({ entryId, readOnly }: { entryId: string; readOnly?: boolean }) {
  const { data: meta } = useEntryArticleMetadata(readOnly ? undefined : entryId);
  if (!meta) return null;
  const { report_type, victim_organizations, timeline, patch } = meta;
  const dates = [
    ["Disclosed", timeline?.disclosure_date],
    ["Compromised", timeline?.compromise_date],
    ["Patched", timeline?.patch_date],
  ].filter(([, v]) => v) as [string, string][];
  const hasPatch = patch && patch.status && patch.status !== "unknown";
  if (!report_type && !victim_organizations?.length && !dates.length && !hasPatch) return null;
  return (
    <div className={styles.articleIntel}>
      {report_type && (
        <span className={styles.articleIntelType} title="Report type">
          {REPORT_TYPE_LABELS[report_type] || report_type}
        </span>
      )}
      {hasPatch && (
        <span className={styles.articleIntelChip} title={patch.reference || undefined}>
          Patch: {patch.status}
        </span>
      )}
      {dates.map(([label, v]) => (
        <span key={label} className={styles.articleIntelChip}>{label}: {v}</span>
      ))}
      {victim_organizations?.length > 0 && (
        <span className={styles.articleIntelChip} title={victim_organizations.join(", ")}>
          Victims: {victim_organizations.slice(0, 2).join(", ")}
          {victim_organizations.length > 2 ? ` +${victim_organizations.length - 2}` : ""}
        </span>
      )}
    </div>
  );
}

/* ─── TTP List (card-based) ─── */

function TTPList({ ttps, entryId, hasExtracted, readOnly }: { ttps: TTP[]; entryId: string; hasExtracted: boolean; readOnly?: boolean }) {
  const navigate = useNavigate();

  if (!ttps.length)
    return (
      <div className={styles.placeholder}>
        <ArticleIntelCard entryId={entryId} readOnly={readOnly} />
        {hasExtracted ? "No TTPs identified." : "No extraction run yet."}
      </div>
    );

  return (
    <div className={styles.cardList}>
      <ArticleIntelCard entryId={entryId} readOnly={readOnly} />
      <KillChainStrip entryId={entryId} readOnly={readOnly} />
      {ttps.map((ttp) => (
        <div
          key={ttp.id}
          className={`${styles.entityCard} ${styles.entityCardTTP} ${!readOnly ? styles.entityCardClickable : ""}`}
          onClick={readOnly ? undefined : () => navigate(`/workbench/ttp/${ttp.id}`)}
        >
          <div className={styles.entityCardRow}>
            <Chip className={styles.typeBadge}>{ttp.technique_id}</Chip>
            <span className={styles.entityName}>{ttp.technique_name}</span>
            <span onClick={(e) => e.stopPropagation()}><CopyButton value={ttp.technique_id} /></span>
          </div>
          <div className={styles.entityCardMeta}>
            {ttp.tactic && <span className={styles.tacticTag}>{ttp.tactic}</span>}
            <HistoryBadge firstSeen={ttp.first_seen_at} articleCount={ttp.article_count} searchValue={readOnly ? undefined : ttp.technique_id} />
            {!readOnly && (
              <div className={styles.entityBtns} onClick={(e) => e.stopPropagation()}>
                <EntityActionMenu
                  entity={{ id: ttp.id, type: "ttp", value: ttp.technique_id, entryId }}
                />
                <UnlinkArticleButton entryId={entryId} entityId={ttp.id} entityType="ttp" />
              </div>
            )}
          </div>
          <div className={styles.entityCardActions} onClick={(e) => e.stopPropagation()}>
            <div className={styles.pivotLinks}>
              {getPivotLinks("ttp", ttp.technique_id).slice(0, 2).map((link) => (
                <a
                  key={link.platform}
                  href={link.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className={styles.pivotLink}
                  title={`Look up on ${link.platform}`}
                >
                  {link.platform}
                </a>
              ))}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

/* ─── CVE List (card-based) ─── */

function CVEList({ cves, entryId, hasExtracted, readOnly }: { cves: CVE[]; entryId: string; hasExtracted: boolean; readOnly?: boolean }) {
  const navigate = useNavigate();

  if (!cves.length)
    return (
      <div className={styles.placeholder}>
        {hasExtracted ? "No CVEs found." : "No extraction run yet."}
      </div>
    );

  return (
    <div className={styles.cardList}>
      {cves.map((cve) => (
        <div
          key={cve.id}
          className={`${styles.entityCard} ${styles.entityCardCVE} ${!readOnly ? styles.entityCardClickable : ""}`}
          onClick={readOnly ? undefined : () => navigate(`/workbench/cve/${cve.id}`)}
        >
          <div className={styles.entityCardRow}>
            <span className={styles.cveId}>{cve.cve_id}</span>
            <span onClick={(e) => e.stopPropagation()}><CopyButton value={cve.cve_id} /></span>
            {cve.is_kev && (
              <Chip tone="solid" tint="var(--danger)" className={styles.kevTag} title="CISA Known Exploited Vulnerability">
                KEV
              </Chip>
            )}
            {cve.cvss_score != null && (
              <span className={styles.cvssScore}>{cve.cvss_score}</span>
            )}
            {cve.severity && (
              <Chip {...severityChipProps(cve.severity)} className={styles.severityBadge}>
                {cve.severity}
              </Chip>
            )}
            {cve.epss_score != null && (
              <span className={styles.epssTag} title={`EPSS exploit-probability${cve.epss_percentile != null ? ` (${(Number(cve.epss_percentile) * 100).toFixed(0)}th percentile)` : ""}`}>
                EPSS {(Number(cve.epss_score) * 100).toFixed(Number(cve.epss_score) < 0.1 ? 1 : 0)}%
              </span>
            )}
            {(cve.github_poc_count || cve.metasploit_module) ? (
              <Chip tone="toned" tint="var(--danger)" className={styles.exploitTag} title={[
                cve.github_poc_count ? `${cve.github_poc_count} GitHub PoC repo${cve.github_poc_count > 1 ? "s" : ""}` : null,
                cve.metasploit_module ? `Metasploit: ${cve.metasploit_module}` : null,
              ].filter(Boolean).join(" · ")}>PoC</Chip>
            ) : null}
            {cve.exploit_status && !cve.is_kev && (
              <Chip tone="toned" tint="var(--danger)" className={styles.exploitTag}>exploited</Chip>
            )}
          </div>
          {cve.description && (
            <div className={styles.entityCardDesc}>
              {cve.description.length > 120 ? cve.description.slice(0, 120) + "..." : cve.description}
            </div>
          )}
          <div className={styles.entityCardMeta}>
            <HistoryBadge firstSeen={cve.first_seen_at} articleCount={cve.article_count} searchValue={readOnly ? undefined : cve.cve_id} />
          </div>
          <div className={styles.entityCardActions} onClick={(e) => e.stopPropagation()}>
            <div className={styles.pivotLinks}>
              {getPivotLinks("cve", cve.cve_id).slice(0, 3).map((link) => (
                <a
                  key={link.platform}
                  href={link.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className={styles.pivotLink}
                  title={`Look up on ${link.platform}`}
                >
                  {link.platform}
                </a>
              ))}
            </div>
            {!readOnly && (
              <div className={styles.entityBtns}>
                <EntityActionMenu
                  entity={{ id: cve.id, type: "cve", value: cve.cve_id, entryId }}
                />
                <UnlinkArticleButton entryId={entryId} entityId={cve.id} entityType="cve" />
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

/* ─── Actor List ─── */

function ActorList({ actors, entryId, hasExtracted, readOnly }: { actors: ThreatActor[]; entryId: string; hasExtracted: boolean; readOnly?: boolean }) {
  const navigate = useNavigate();
  if (!actors.length)
    return (
      <div className={styles.placeholder}>
        {hasExtracted ? "No threat actors identified." : "No extraction run yet."}
      </div>
    );

  return (
    <div className={styles.cardList}>
      {actors.map((actor) => (
        <div
          key={actor.id}
          className={`${styles.entityCard} ${styles.entityCardActor} ${!readOnly ? styles.entityCardClickable : ""}`}
          onClick={readOnly ? undefined : () => navigate(`/workbench/threat_actor/${actor.id}`)}
        >
          <div className={styles.entityCardRow}>
            <span className={styles.entityName}>{actor.name}</span>
            {actor.aliases?.length > 0 && (
              <span className={styles.aliasTag}>aka {actor.aliases[0]}</span>
            )}
            <span onClick={(e) => e.stopPropagation()}><CopyButton value={actor.name} /></span>
          </div>
          <div className={styles.entityCardMeta}>
            {actor.country && <span className={styles.tacticTag}>{actor.country}</span>}
            {actor.motivation && <span className={styles.tacticTag}>{actor.motivation}</span>}
            <HistoryBadge firstSeen={actor.first_seen_at} articleCount={actor.article_count} searchValue={readOnly ? undefined : actor.name} />
          </div>
          <div className={styles.entityCardActions} onClick={(e) => e.stopPropagation()}>
            <div className={styles.pivotLinks}>
              {getPivotLinks("threat_actor", actor.name).slice(0, 3).map((link) => (
                <a
                  key={link.platform}
                  href={link.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className={styles.pivotLink}
                  title={`Look up on ${link.platform}`}
                >
                  {link.platform}
                </a>
              ))}
            </div>
            {!readOnly && (
              <div className={styles.entityBtns}>
                <EntityActionMenu entity={{ id: actor.id, type: "threat_actor", value: actor.name, entryId }} />
                <UnlinkArticleButton entryId={entryId} entityId={actor.id} entityType="threat_actor" />
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

/* ─── Malware List ─── */

function MalwareList({ malware, entryId, hasExtracted, readOnly }: { malware: MalwareFamily[]; entryId: string; hasExtracted: boolean; readOnly?: boolean }) {
  const navigate = useNavigate();
  if (!malware.length)
    return (
      <div className={styles.placeholder}>
        {hasExtracted ? "No malware identified." : "No extraction run yet."}
      </div>
    );

  return (
    <div className={styles.cardList}>
      {malware.map((m) => (
        <div
          key={m.id}
          className={`${styles.entityCard} ${styles.entityCardMalware} ${!readOnly ? styles.entityCardClickable : ""}`}
          onClick={readOnly ? undefined : () => navigate(`/workbench/malware/${m.id}`)}
        >
          <div className={styles.entityCardRow}>
            <span className={styles.entityName}>{m.name}</span>
            {m.malware_type && <Chip className={styles.typeBadge} truncate>{m.malware_type}</Chip>}
            <span onClick={(e) => e.stopPropagation()}><CopyButton value={m.name} /></span>
          </div>
          <div className={styles.entityCardMeta}>
            {m.aliases?.length > 0 && (
              <span className={styles.aliasTag}>aka {m.aliases.slice(0, 2).join(", ")}</span>
            )}
            <HistoryBadge firstSeen={m.first_seen_at} articleCount={m.article_count} searchValue={readOnly ? undefined : m.name} />
          </div>
          <div className={styles.entityCardActions} onClick={(e) => e.stopPropagation()}>
            <div className={styles.pivotLinks}>
              {getPivotLinks("malware", m.name).slice(0, 3).map((link) => (
                <a
                  key={link.platform}
                  href={link.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className={styles.pivotLink}
                  title={`Look up on ${link.platform}`}
                >
                  {link.platform}
                </a>
              ))}
            </div>
            {!readOnly && (
              <div className={styles.entityBtns}>
                <EntityActionMenu entity={{ id: m.id, type: "malware", value: m.name, entryId }} />
                <UnlinkArticleButton entryId={entryId} entityId={m.id} entityType="malware" />
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

/* ─── Sector List ─── */

/** The industries this article describes as targeted — the AI's judgment,
 *  never a word match, so there is no "wrong match" affordance here. */
function SectorList({ sectors, entryId, hasExtracted, readOnly }: { sectors: EntrySector[]; entryId: string; hasExtracted: boolean; readOnly?: boolean }) {
  const navigate = useNavigate();
  if (!sectors.length)
    return (
      <div className={styles.placeholder}>
        {hasExtracted ? "No targeted sectors identified." : "No extraction run yet."}
      </div>
    );

  return (
    <div className={styles.cardList}>
      {sectors.map((sector) => (
        <div
          key={sector.id}
          className={`${styles.entityCard} ${styles.entityCardSector} ${!readOnly ? styles.entityCardClickable : ""}`}
          onClick={readOnly ? undefined : () => navigate(`/workbench/sector/${sector.id}`)}
        >
          <div className={styles.entityCardRow}>
            <span className={styles.entityName}>{sector.name}</span>
            {sector.confidence && <span className={styles.tacticTag}>{sector.confidence}</span>}
          </div>
          {!readOnly && (
            <div className={styles.entityCardActions} onClick={(e) => e.stopPropagation()}>
              <div className={styles.entityBtns}>
                <UnlinkArticleButton entryId={entryId} entityId={sector.id} entityType="sector" />
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

/* ─── Country List ─── */

function CountryList({ countries, entryId, hasExtracted, readOnly }: { countries: Country[]; entryId: string; hasExtracted: boolean; readOnly?: boolean }) {
  const navigate = useNavigate();
  if (!countries.length)
    return (
      <div className={styles.placeholder}>
        {hasExtracted ? "No countries identified." : "No extraction run yet."}
      </div>
    );

  return (
    <div className={styles.cardList}>
      {countries.map((country) => (
        <div
          key={country.id}
          className={`${styles.entityCard} ${styles.entityCardCountry} ${!readOnly ? styles.entityCardClickable : ""}`}
          onClick={readOnly ? undefined : () => navigate(`/workbench/country/${country.id}`)}
        >
          <div className={styles.entityCardRow}>
            {country.iso_code && <Chip className={styles.typeBadge}>{country.iso_code}</Chip>}
            <span className={styles.entityName}>{country.name}</span>
            {country.region && <span className={styles.tacticTag}>{country.region}</span>}
          </div>
          <div className={styles.entityCardMeta}>
            <HistoryBadge firstSeen={country.first_seen_at} articleCount={country.article_count} searchValue={readOnly ? undefined : country.name} />
          </div>
          <div className={styles.entityCardActions} onClick={(e) => e.stopPropagation()}>
            <div className={styles.pivotLinks}>
              {getPivotLinks("country", country.name).slice(0, 2).map((link) => (
                <a
                  key={link.platform}
                  href={link.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className={styles.pivotLink}
                  title={`Look up on ${link.platform}`}
                >
                  {link.platform}
                </a>
              ))}
            </div>
            {!readOnly && (
              <div className={styles.entityBtns}>
                <EntityActionMenu entity={{ id: country.id, type: "country", value: country.name, entryId }} />
                <UnlinkArticleButton entryId={entryId} entityId={country.id} entityType="country" />
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

/* ─── Mitigation List ─── */

function MitigationList({ mitigations, entryId, hasExtracted, readOnly }: { mitigations: Mitigation[]; entryId: string; hasExtracted: boolean; readOnly?: boolean }) {
  if (!mitigations.length)
    return (
      <div className={styles.placeholder}>
        {hasExtracted ? "No mitigations identified." : "No extraction run yet."}
      </div>
    );

  return (
    <div className={styles.cardList}>
      {mitigations.map((m) => (
        <div key={m.id} className={`${styles.entityCard} ${styles.entityCardMitigation}`}>
          <div className={styles.entityCardRow}>
            {m.mitre_id && <Chip className={styles.typeBadge}>{m.mitre_id}</Chip>}
            <span className={styles.entityName}>{m.name}</span>
          </div>
          {m.description && (
            <div className={styles.entityCardDesc}>
              {m.description.length > 150 ? m.description.slice(0, 150) + "..." : m.description}
            </div>
          )}
          <div className={styles.entityCardMeta}>
            {m.mitre_url && (
              <a
                href={m.mitre_url}
                target="_blank"
                rel="noopener noreferrer"
                className={styles.pivotLink}
                onClick={(e) => e.stopPropagation()}
              >
                ATT&CK
              </a>
            )}
            {m.cis_controls?.length > 0 && (
              <span className={styles.tacticTag}>CIS: {m.cis_controls.slice(0, 2).join(", ")}</span>
            )}
            {m.nist_controls?.length > 0 && (
              <span className={styles.tacticTag}>NIST: {m.nist_controls.slice(0, 2).join(", ")}</span>
            )}
            {!readOnly && (
              <span className={styles.entityBtns} onClick={(e) => e.stopPropagation()}>
                <EntityActionMenu entity={{ id: m.id, type: "mitigation", value: m.name, entryId }} />
                <UnlinkArticleButton entryId={entryId} entityId={m.id} entityType="mitigation" />
              </span>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

/* ─── Tool List ─── */

function ToolList({ tools, entryId, hasExtracted, readOnly }: { tools: OffensiveTool[]; entryId: string; hasExtracted: boolean; readOnly?: boolean }) {
  const navigate = useNavigate();
  if (!tools.length)
    return (
      <div className={styles.placeholder}>
        {hasExtracted ? "No tools identified." : "No extraction run yet."}
      </div>
    );

  return (
    <div className={styles.cardList}>
      {tools.map((tool) => (
        <div
          key={tool.id}
          className={`${styles.entityCard} ${styles.entityCardTool} ${!readOnly ? styles.entityCardClickable : ""}`}
          onClick={readOnly ? undefined : () => navigate(`/workbench/tool/${tool.id}`)}
        >
          <div className={styles.entityCardRow}>
            <span className={styles.entityName}>{tool.name}</span>
            {tool.tool_type && <Chip className={styles.typeBadge} truncate>{tool.tool_type}</Chip>}
          </div>
          {tool.aliases?.length > 0 && (
            <div className={styles.entityCardMeta}>
              <span className={styles.aliasTag}>aka {tool.aliases.slice(0, 2).join(", ")}</span>
            </div>
          )}
          {!readOnly && (
            <div className={styles.entityCardMeta} onClick={(e) => e.stopPropagation()}>
              <div className={styles.entityBtns}>
                <EntityActionMenu entity={{ id: tool.id, type: "tool", value: tool.name, entryId }} />
                <UnlinkArticleButton entryId={entryId} entityId={tool.id} entityType="tool" />
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}


/* ─── Vendor List ─── */

function VendorList({ vendors, entryId, hasExtracted, readOnly }: { vendors: Vendor[]; entryId: string; hasExtracted: boolean; readOnly?: boolean }) {
  const navigate = useNavigate();
  if (!vendors.length)
    return (
      <div className={styles.placeholder}>
        {hasExtracted ? "No vendors identified." : "No extraction run yet."}
      </div>
    );

  return (
    <div className={styles.cardList}>
      {vendors.map((v) => (
        <div
          key={v.id}
          className={`${styles.entityCard} ${styles.entityCardVendor} ${!readOnly ? styles.entityCardClickable : ""}`}
          onClick={readOnly ? undefined : () => navigate(`/workbench/vendor/${v.id}`)}
        >
          <div className={styles.entityCardRow}>
            <span className={styles.entityName}>{v.name}</span>
            {v.vendor_type && <Chip className={styles.typeBadge} truncate>{v.vendor_type}</Chip>}
          </div>
          {v.aliases?.length > 0 && (
            <div className={styles.entityCardMeta}>
              <span className={styles.aliasTag}>aka {v.aliases.slice(0, 2).join(", ")}</span>
            </div>
          )}
          {!readOnly && (
            <div className={styles.entityCardMeta} onClick={(e) => e.stopPropagation()}>
              <div className={styles.entityBtns}>
                <EntityActionMenu entity={{ id: v.id, type: "vendor", value: v.name, entryId }} />
                <UnlinkArticleButton entryId={entryId} entityId={v.id} entityType="vendor" />
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}


/* ─── Product List ─── */

function ProductList({ products, entryId, hasExtracted, readOnly }: { products: Product[]; entryId: string; hasExtracted: boolean; readOnly?: boolean }) {
  const navigate = useNavigate();
  if (!products.length)
    return (
      <div className={styles.placeholder}>
        {hasExtracted ? "No products identified." : "No extraction run yet."}
      </div>
    );

  return (
    <div className={styles.cardList}>
      {products.map((p) => (
        <div
          key={p.id}
          className={`${styles.entityCard} ${styles.entityCardProduct} ${!readOnly ? styles.entityCardClickable : ""}`}
          onClick={readOnly ? undefined : () => navigate(`/workbench/product/${p.id}`)}
        >
          <div className={styles.entityCardRow}>
            <span className={styles.entityName}>{p.name}</span>
            {p.product_type && <Chip className={styles.typeBadge} truncate>{p.product_type}</Chip>}
          </div>
          {(p.vendor_name || p.aliases?.length > 0) && (
            <div className={styles.entityCardMeta}>
              {p.vendor_name && <span className={styles.tacticTag}>{p.vendor_name}</span>}
              {p.aliases?.length > 0 && (
                <span className={styles.aliasTag}>aka {p.aliases.slice(0, 2).join(", ")}</span>
              )}
            </div>
          )}
          {!readOnly && (
            <div className={styles.entityCardMeta} onClick={(e) => e.stopPropagation()}>
              <div className={styles.entityBtns}>
                <EntityActionMenu entity={{ id: p.id, type: "product", value: p.name, entryId }} />
                <UnlinkArticleButton entryId={entryId} entityId={p.id} entityType="product" />
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}


/* ─── Detection Rules ─── */

function RuleList({
  rules,
  hasExtracted,
  hasEntities,
  readOnly,
}: {
  rules: (DetectionRule | DetectionRuleListItem)[];
  hasExtracted: boolean;
  hasEntities: boolean;
  readOnly?: boolean;
}) {
  const navigate = useNavigate();
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editContent, setEditContent] = useState("");
  const [editTitle, setEditTitle] = useState("");
  const updateRule = useUpdateDetectionRule();
  const deleteRule = useDeleteDetectionRule();
  const undoableDelete = useUndoableDelete();
  const [copied, setCopied] = useState<string | null>(null);
  // The list rows are lightweight (no rule_content); fetch the full rule lazily
  // when a row is expanded in the authed panel. In readOnly mode the preloaded
  // rules already carry rule_content.
  const { data: expandedRule } = useDetectionRule(!readOnly && expandedId ? expandedId : undefined);
  const contentOf = (rule: DetectionRule | DetectionRuleListItem): string =>
    ("rule_content" in rule && rule.rule_content) || (expandedRule?.id === rule.id ? expandedRule.rule_content : "") || "";

  if (!rules.length)
    return (
      <div className={styles.placeholder}>
        {hasEntities
          ? "No detection rules yet. Use \"Gen Rules\" above."
          : hasExtracted
            ? "No entities to generate rules from."
            : "Extract intelligence first, then generate detection rules."}
      </div>
    );

  const ruleTypeLabels: Record<string, string> = {
    sigma: "SIGMA", splunk_spl: "Splunk SPL", crowdstrike_ql: "CrowdStrike",
    elastic_ql: "Elastic", kql: "KQL",
  };

  const handleCopy = (ruleId: string, content: string) => {
    navigator.clipboard.writeText(content);
    setCopied(ruleId);
    setTimeout(() => setCopied(null), 2000);
  };

  const handleEdit = (rule: DetectionRule | DetectionRuleListItem) => {
    setEditingId(rule.id);
    setEditContent(contentOf(rule));
    setEditTitle(rule.title);
    setExpandedId(rule.id);
  };

  const handleSave = (ruleId: string) => {
    updateRule.mutate(
      { id: ruleId, rule_content: editContent, title: editTitle },
      { onSuccess: () => setEditingId(null) }
    );
  };

  const handleDelete = (ruleId: string) => {
    undoableDelete({
      label: "Detection rule",
      key: `rule-${ruleId}`,
      onDelete: () => deleteRule.mutate(ruleId),
    });
  };

  return (
    <div className={styles.ruleList}>
      {rules.map((rule) => (
        <div key={rule.id} className={styles.ruleItem}>
          <div
            className={styles.ruleHeader}
            onClick={() => setExpandedId(expandedId === rule.id ? null : rule.id)}
          >
            <Chip tone="solid" tint="var(--accent)" className={styles.ruleTypeBadge}>
              {ruleTypeLabels[rule.rule_type] || rule.rule_type}
            </Chip>
            {editingId === rule.id ? (
              <input
                className={styles.ruleTitleInput}
                value={editTitle}
                onChange={(e) => setEditTitle(e.target.value)}
                onClick={(e) => e.stopPropagation()}
              />
            ) : (
              <span className={styles.ruleTitle}>{rule.title}</span>
            )}
            {rule.severity && (
              <Chip {...severityChipProps(rule.severity)} className={styles.severityBadge}>
                {rule.severity}
              </Chip>
            )}
            <span className={styles.sectionArrow}>
              {expandedId === rule.id ? "\u25B4" : "\u25BE"}
            </span>
          </div>

          {expandedId === rule.id && (
            <div className={styles.ruleBody}>
              {editingId === rule.id ? (
                <textarea
                  className={styles.ruleEditor}
                  value={editContent}
                  onChange={(e) => setEditContent(e.target.value)}
                  rows={15}
                  spellCheck={false}
                />
              ) : (
                <pre className={styles.ruleCode}>{contentOf(rule)}</pre>
              )}
              <div className={styles.ruleActions}>
                {editingId === rule.id ? (
                  <>
                    <button
                      className={styles.saveBtn}
                      onClick={() => handleSave(rule.id)}
                      disabled={updateRule.isPending}
                    >
                      {updateRule.isPending ? "Saving..." : "Save"}
                    </button>
                    <button className={styles.cancelBtn} onClick={() => setEditingId(null)}>
                      Cancel
                    </button>
                  </>
                ) : (
                  <>
                    {!readOnly && (
                      <button className={styles.ruleActionBtn} onClick={() => navigate(`/workbench/rule/${rule.id}`)}>
                        View
                      </button>
                    )}
                    <button className={styles.ruleActionBtn} onClick={() => handleCopy(rule.id, contentOf(rule))}>
                      {copied === rule.id ? "Copied!" : "Copy"}
                    </button>
                    {!readOnly && (
                      <button className={styles.ruleActionBtn} onClick={() => handleEdit(rule)}>
                        Edit
                      </button>
                    )}
                    {!readOnly && (
                      <button className={styles.ruleDeleteBtn} onClick={() => handleDelete(rule.id)}>
                        Delete
                      </button>
                    )}
                  </>
                )}
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
