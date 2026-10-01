import { useState, useEffect, useCallback, useRef, lazy, Suspense, Fragment } from "react";
import { useNavigate, useLocation, useSearchParams, Outlet } from "react-router-dom";
import { useInfiniteQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { useIsMobile } from "@/hooks/useMediaQuery";
import { useIntelStore, type WorkspaceSection } from "@/stores/intelStore";
import { useAuthStore } from "@/stores/authStore";
import api from "@/api/client";
import type { EntitySearchResult, ThreatActor, MalwareFamily, TTP, CVE, CWEResponse, ObservableResponse, ObservableCandidateRow, Country, Sector, Mitigation, OffensiveTool, Vendor, Product, DetectionRuleListItem, FacetBucket, RuleSearchResponse, IntelReport, IntelligenceRequirement, PaginatedResponse } from "@/api/types";
import { EntityTableSection, type ColumnDef } from "@/components/EntityTableSection";
import { DataTable, type SortDir } from "@/components/table/DataTable";
import { NameCell } from "@/components/table/cells";
import table from "@/components/table/DataTable.module.css";
import { useEntitySearch } from "@/hooks/useCorrelation";
import { useUIStore } from "@/stores/uiStore";
import { useTelemetrySources, useTelemetryCatalog, useSyncTelemetrySources } from "@/hooks/useTelemetrySources";
import type { CatalogItem } from "@/api/types";
import {
  useRequirementCoverage,
  useRequirementMatches,
  useCreateRequirement,
  useUpdateRequirement,
  useDeleteRequirement,
  useFulfillRequirement,
  useRemoveRequirementMatch,
} from "@/hooks/useRequirements";
import { useIntelReports, useIntelReport } from "@/hooks/useIntelReports";
import type { RequirementCreate, RequirementLinkedEntities, LinkedEntityRef } from "@/api/types";
import {
  useBulkUpdateRules,
  useBulkDeleteRules,
  useImportRules,
  useExportRules,
  useRuleTelemetryVocabulary,
} from "@/hooks/useDetectionRules";
import { DetectionWorkbenchPage } from "./DetectionWorkbenchPage";

// Heavy grid view — loaded on demand when the section is opened.
const RansomwareSection = lazy(() =>
  import("@/components/ransomware/RansomwareSection").then((m) => ({ default: m.RansomwareSection }))
);
const AttackMatrixSection = lazy(() =>
  import("@/components/AttackMatrixSection").then((m) => ({ default: m.AttackMatrixSection }))
);
import { CampaignsPage } from "./CampaignsPage";
import { GlossaryPage } from "./GlossaryPage";
import { TelegramMentionsPanel } from "@/components/TelegramMentionsPanel";
import { WatchlistPanel } from "@/components/WatchlistPanel";
import { EntityMergeModal } from "@/components/EntityMergeModal";
import { formatDate } from "@/utils/formatDate";
import { exploitSourcesText } from "@/utils/exploitSources";
import { TLP_COLORS, getTLPColor } from "@/utils/colorSchemes";
import { CreateEntityPanel, isCreatableEntityType } from "@/components/CreateEntityPanel";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import { useRailWidth } from "@/hooks/useRailWidth";
import { ResizeHandle } from "@/components/ResizeHandle";
import { SECTION_KEYS } from "@/components/WorkbenchNav";
import styles from "./WorkbenchPage.module.css";
import lib from "./RuleLibrary.module.css";
import { Chip, FacetSection, PageHeader, RailToggle, Segmented } from "@/components/primitives";
import {
  useDismissObservableCandidate,
  useNeverCaptureObservable,
  useObservableCandidates,
  usePromoteObservable,
} from "@/hooks/useIntelligence";
const DockedThreadReader = lazy(() =>
  import("@/components/ThreadReader").then((m) => ({ default: m.ThreadReader }))
);
const DockedEntryReader = lazy(() =>
  import("@/components/EntryReader").then((m) => ({ default: m.EntryReader }))
);
import { RouteFallback } from "@/components/RouteFallback";
import { alertDialog, confirmDialog } from "@/utils/dialog";

type SortOrder = "asc" | "desc";
type SortState = { field: string; order: SortOrder };

function useSort(
  defaultField: string,
  defaultOrder: SortOrder = "desc"
): [SortState, (field: string) => void, (field: string, order: SortOrder) => void] {
  const [sort, setSort] = useState<SortState>({ field: defaultField, order: defaultOrder });
  const toggle = useCallback((field: string) => {
    setSort((prev) =>
      prev.field === field
        ? { field, order: prev.order === "asc" ? "desc" : "asc" }
        : { field, order: "desc" }
    );
  }, []);
  const set = useCallback((field: string, order: SortOrder) => setSort({ field, order }), []);
  return [sort, toggle, set];
}

function SortableHeader({ field, label, sort, onSort }: {
  field: string;
  label: string;
  sort: SortState;
  onSort: (field: string) => void;
}) {
  const active = sort.field === field;
  return (
    <th>
      <span
        className={`${styles.sortableHeader} ${active ? styles.sortableHeaderActive : ""}`}
        onClick={() => onSort(field)}
      >
        {label}
        <span
          className={`${styles.sortArrow} ${active ? styles.sortArrowActive : ""} ${
            active && sort.order === "asc" ? styles.sortArrowAsc : styles.sortArrowDesc
          }`}
        />
      </span>
    </th>
  );
}


export function WorkbenchLayout() {
  const createEntityOpen = useIntelStore((s) => s.createEntityOpen);
  const createEntityType = useIntelStore((s) => s.createEntityType);
  const closeCreateEntity = useIntelStore((s) => s.closeCreateEntity);
  const readerEntryId = useIntelStore((s) => s.workbenchReaderEntryId);
  // One dock, two possible occupants: an article or the story it belongs to.
  const readerThreadSlug = useIntelStore((s) => s.workbenchReaderThreadSlug);
  const readerOpen = !!readerEntryId || !!readerThreadSlug;
  const closeWorkbenchReader = useIntelStore((s) => s.closeWorkbenchReader);
  const readerRail = useRailWidth("workbench-reader", { default: 560, min: 400, max: 960 });
  const [readerFullscreen, setReaderFullscreen] = useState(false);
  const location = useLocation();

  // The docked reader closes on Escape and whenever the route changes — it is
  // a companion to the surface that opened it, not a global panel.
  useEffect(() => {
    if (!readerOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeWorkbenchReader();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [readerOpen, closeWorkbenchReader]);
  useEffect(() => {
    closeWorkbenchReader();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname]);
  // Detail routes (entity profiles, rule detail, report builder) collapse the
  // sidebar to give the content full width; returning to the index restores
  // it — but only if the auto-collapse is what closed it. A manual toggle
  // clears sidebarAutoCollapsed, so an explicit choice is never overridden.
  // This avoids the failure mode of the earlier blanket auto-collapse, which
  // never restored and made users re-expand the sidebar after every profile.
  // The dashboard and the section browser are full workbench pages, not detail
  // views — keep the nav open there.
  // /workbench/exposure survives only as a redirect into Threats, but keeping
  // it here avoids a one-frame collapse while the redirect resolves.
  const FULL_WORKBENCH_PAGES = [
    "/workbench/dashboard",
    "/workbench/explore",
    "/workbench/threats",
    "/workbench/exposure",
  ];
  const onDetailRoute =
    /^\/workbench\/./.test(location.pathname) && !FULL_WORKBENCH_PAGES.includes(location.pathname);
  // Only detail routes (profiles, rule bench, report builder) auto-fold the
  // nav. The rules library and ransomware sections keep it open even though
  // they carry their own facet rail — the nav is the way back out.
  const foldWorkbenchNav = onDetailRoute;
  const isMobile = useIsMobile();

  useEffect(() => {
    const ui = useUIStore.getState();
    // One rail now, so the fold targets the app sidebar. Restoring is still
    // gated on sidebarAutoCollapsed: a manual toggle clears it, so an explicit
    // choice survives the trip in and back out of a profile.
    if (foldWorkbenchNav) {
      if (!ui.sidebarCollapsed) {
        useUIStore.setState({ sidebarCollapsed: true, sidebarAutoCollapsed: true });
      }
    } else if (ui.sidebarAutoCollapsed) {
      useUIStore.setState({ sidebarCollapsed: false, sidebarAutoCollapsed: false });
    }
  }, [foldWorkbenchNav]);

  // Fullscreen reading: the reader takes the whole workbench, so the nav and
  // the page it was opened from step aside. The page stays mounted (hidden,
  // not unmounted) so its table state survives the round trip.
  const readerExpanded = readerOpen && readerFullscreen && !isMobile;

  return (
    <div className={styles.container}>
      {/* No rail of its own any more: the app sidebar *is* the workbench nav
          while it is in Workbench mode, on both breakpoints. Two stacked navs
          were what forced the old auto-collapse of the app sidebar, which in
          turn buried every non-reader surface. */}
      <div className={`${styles.mainContent} ${readerExpanded ? styles.mainContentHidden : ""}`}>
        {/* One modal for both openers — the entity table's header button
            and the mobile section sheet. */}
        {createEntityOpen && (
          <div className={styles.createEntityOverlay} onClick={closeCreateEntity}>
            <div className={styles.createEntityModal} onClick={(e) => e.stopPropagation()}>
              <CreateEntityPanel
                initialType={isCreatableEntityType(createEntityType) ? createEntityType : undefined}
                onClose={closeCreateEntity}
              />
            </div>
          </div>
        )}
        {/* Nested lazy routes (dashboard, engine, exposure, profiles) get
            their own boundary so the workbench nav survives the swap. */}
        <Suspense fallback={<RouteFallback />}>
          <Outlet />
        </Suspense>
      </div>

      {/* The workbench's docked reader: the page on the left is the entry
          list, the reader rides the right — the same pairing (and the same
          collapse/resize furniture) as every other rail in the app. */}
      {readerOpen && !isMobile && (
        <RailToggle
          side="right"
          collapsed={!readerFullscreen}
          onToggle={() => setReaderFullscreen((v) => !v)}
          label="reader"
          verbs={["Expand", "Restore"]}
        />
      )}
      {readerOpen && !readerExpanded && !isMobile && (
        <ResizeHandle
          label="reader"
          onResize={(delta) => readerRail.handleProps.onResize(-delta)}
          onResizeStart={readerRail.handleProps.onResizeStart}
          onResizeEnd={readerRail.handleProps.onResizeEnd}
          onReset={readerRail.handleProps.onReset}
        />
      )}
      {readerOpen && (
        <aside
          className={`${styles.dockedReader} ${readerExpanded ? styles.dockedReaderExpanded : ""}`}
          style={isMobile || readerExpanded ? undefined : readerRail.style}
        >
          {/* Labelled explicitly: an unlabelled RouteFallback names the *route*,
              so a slow reader chunk read as "Loading Threat Actor Profile…"
              inside the reader pane — which looks like the click did nothing. */}
          <Suspense fallback={<RouteFallback label={readerThreadSlug ? "story" : "article"} />}>
            {readerThreadSlug ? (
              <DockedThreadReader slug={readerThreadSlug} />
            ) : (
              <DockedEntryReader entryId={readerEntryId!} />
            )}
          </Suspense>
        </aside>
      )}
    </div>
  );
}

// Entity types migrated to the unified full-width profile page — they open via
// route instead of the legacy inline panel. (Country still uses the panel.)
const ROUTED_PROFILE_TYPES = new Set<string>([
  "threat_actor", "malware", "cve", "cwe", "ttp", "country", "sector", "tool", "mitigation", "vendor", "product", "observable",
]);

export function WorkbenchPage() {
  const navigate = useNavigate();
  const selectedEntityType = useIntelStore((s) => s.selectedEntityType);
  const selectedEntityId = useIntelStore((s) => s.selectedEntityId);
  const clearSelectedEntity = useIntelStore((s) => s.clearSelectedEntity);
  const activeSection = useIntelStore((s) => s.activeSection);
  const setActiveSection = useIntelStore((s) => s.setActiveSection);
  const [searchParams, setSearchParams] = useSearchParams();

  // ?section=rules deep link (e.g. entity profile "Search library" CTA) —
  // activate the section, then consume the param so it doesn't linger.
  useEffect(() => {
    const section = searchParams.get("section");
    if (section && SECTION_KEYS.has(section)) {
      setActiveSection(section as WorkspaceSection);
      const next = new URLSearchParams(searchParams);
      next.delete("section");
      setSearchParams(next, { replace: true });
    }
  }, [searchParams, setSearchParams, setActiveSection]);

  const routedSlug =
    selectedEntityType && ROUTED_PROFILE_TYPES.has(selectedEntityType)
      ? selectedEntityType
      : undefined;

  // Migrated types open as a full-width route instead of the legacy inline panel.
  useEffect(() => {
    if (routedSlug && selectedEntityId) {
      const id = selectedEntityId;
      clearSelectedEntity();
      navigate(`/workbench/${routedSlug}/${id}`);
    }
  }, [routedSlug, selectedEntityId, clearSelectedEntity, navigate]);

  // Redirecting a selected migrated entity to its full-width page — render nothing this frame.
  if (routedSlug && selectedEntityId) return null;

  return <SectionContent section={activeSection} />;
}

function SectionContent({ section }: { section: WorkspaceSection }) {
  switch (section) {
    case "threat_actors":
      return <ThreatActorsSection />;
    case "malware":
      return <MalwareSection />;
    case "cves":
      return <CVEsSection />;
    case "cwes":
      return <CWEsSection />;
    case "ttps":
      return <TTPsSection />;
    case "countries":
      return <CountriesSection />;
    case "sectors":
      return <SectorsSection />;
    case "mitigations":
      return <MitigationsSection />;
    case "observables":
      return <ObservablesSection />;
    case "tools":
      return <ToolsSection />;
    case "vendors":
      return <VendorsSection />;
    case "products":
      return <ProductsSection />;

    case "rules":
      return <RulesSection />;
    case "campaigns":
      return <CampaignsSection />;
    case "telemetry":
      return <TelemetrySourcesSection />;
    case "attack_matrix":
      return (
        <Suspense fallback={<RouteFallback inline label="ATT&CK matrix" />}>
          <AttackMatrixSection />
        </Suspense>
      );
    case "requirements":
      return <RequirementsSection />;
    case "reports":
      return <ReportsSection />;
    case "glossary":
      return <GlossaryPage />;
    case "telegram_mentions":
      return <TelegramMentionsPanel />;
    case "watchlist":
      return <WatchlistPanel />;
    case "ransomware":
      return (
        <Suspense fallback={<RouteFallback inline label="ransomware tracker" />}>
          <RansomwareSection />
        </Suspense>
      );
    default:
      return <div className={styles.emptyState}><div className={styles.emptyTitle}>Coming soon</div></div>;
  }
}

// --- Shared column renderers ---

function AliasesCell({ aliases }: { aliases: string[] }) {
  if (!aliases || aliases.length === 0) return <span className={styles.entityMeta}>-</span>;
  return (
    <div className={styles.aliasList} title={aliases.join(", ")}>
      {aliases.slice(0, 2).map((a) => (
        <Chip key={a} truncate className={styles.aliasTag}>{a}</Chip>
      ))}
      {aliases.length > 2 && <Chip className={styles.aliasTag}>+{aliases.length - 2}</Chip>}
    </div>
  );
}

/** Render controlled-vocabulary sector slugs (e.g. "financial-services") as readable chips. */
function sectorLabel(slug: string): string {
  return slug.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function SectorsCell({ sectors }: { sectors: string[] | undefined }) {
  if (!sectors || sectors.length === 0) return <span className={styles.entityMeta}>-</span>;
  return (
    <div className={styles.aliasList} title={sectors.map(sectorLabel).join(", ")}>
      {sectors.slice(0, 2).map((s) => (
        <Chip key={s} truncate className={styles.aliasTag}>{sectorLabel(s)}</Chip>
      ))}
      {sectors.length > 2 && <Chip className={styles.aliasTag}>+{sectors.length - 2}</Chip>}
    </div>
  );
}

/** Provenance columns shared by the entity types that record how a row was created.
 *
 * These replace the old "Source" / "Confidence" columns, which read the
 * entry-junction fields on the response schema — always null when the row comes
 * from a catalog list endpoint rather than a per-entry lookup, so the columns
 * could never show anything. `created_via` / `created_confidence` are the real
 * provenance and are populated by the extraction pipeline.
 */
type WithProvenance = { created_via?: string | null; created_confidence?: string | null; needs_review?: boolean };

function PROVENANCE_COLUMNS<T extends WithProvenance>(): ColumnDef<T>[] {
  return [
    {
      key: "created_via", label: "Source", width: 130, minWidth: 90, hideable: true, defaultHidden: true,
      hint: {
        title: "Source",
        body: "What created this row — the autolinker, an AI extraction, or you.",
        aside: "Filter to AI extraction to review what the engine has been adding.",
      },
      textValue: (e) => e.created_via ?? "",
      choices: [
        { value: "all", label: "Any" },
        { value: "ai_extraction", label: "AI extraction" },
        { value: "auto_link", label: "Autolinker" },
        { value: "manual", label: "Manual" },
      ],
      choiceMatch: (e, v) => e.created_via === v,
      render: (e) => <MetaCell value={e.created_via?.replace(/_/g, " ")} />,
    },
    {
      key: "created_confidence", label: "Confidence", width: 100, minWidth: 76, hideable: true, defaultHidden: true,
      hint: {
        title: "Confidence",
        body: "How sure the extractor was when it created this entity.",
        aside: "Anything low is worth a look before you build on it.",
      },
      textValue: (e) => e.created_confidence ?? "",
      render: (e) => <MetaCell value={e.created_confidence} />,
    },
    {
      key: "needs_review", label: "Review", width: 80, minWidth: 64, hideable: true, defaultHidden: true,
      hint: {
        title: "Needs review",
        body: "Flagged by the creation gates — a near-duplicate name, a thin source, or a type the resolver wasn't sure about.",
      },
      sortValue: (e) => (e.needs_review ? 1 : 0),
      choices: [
        { value: "all", label: "Any" },
        { value: "yes", label: "Needs review" },
      ],
      choiceMatch: (e, v) => (v === "yes" ? !!e.needs_review : true),
      render: (e) => e.needs_review
        ? <Chip tone="toned" tint="#ca8a04">review</Chip>
        : <span className={table.zero}>·</span>,
    },
  ];
}

/**
 * CVE severity / risk tier -> the app's theme-managed severity ramp. The old
 * .badge* classes hardcoded a light-mode palette (#dc2626 / #ea580c / #ca8a04 /
 * #16a34a / #2563eb) that sat at 2.4-3.4:1 on the dark ground; --severity-* is
 * the token family that exists for exactly this axis and every theme supplies
 * its own values.
 */
function getSeverityTint(severity: string | null) {
  switch (severity?.toLowerCase()) {
    case "critical": return "var(--severity-critical)";
    case "high": return "var(--severity-high)";
    case "medium": return "var(--severity-medium)";
    case "low": return "var(--severity-low)";
    default: return "var(--severity-info)";
  }
}

function ArticleCount({ count }: { count: number | undefined }) {
  if (count == null) return <span className={styles.articleCount}>-</span>;
  const cls = count >= 10 ? styles.articleCountHot : count >= 3 ? styles.articleCountWarm : styles.articleCountCool;
  return <span className={`${styles.articleCount} ${cls}`}>{count}</span>;
}

/** Activity status derived from last_seen_at: Active (<90d), Dormant (90d-1y), Historical (>1y or never seen). */
export function ActivityBadge({ lastSeenAt }: { lastSeenAt: string | null | undefined }) {
  const DAY_MS = 24 * 60 * 60 * 1000;
  const ageDays = lastSeenAt ? (Date.now() - new Date(lastSeenAt).getTime()) / DAY_MS : null;
  let label = "Historical";
  let dotClass = styles.activityDotHistorical;
  let title = "No sighting in over a year";
  if (ageDays !== null && ageDays < 90) {
    label = "Active";
    dotClass = styles.activityDotActive;
    title = "Seen in the last 90 days";
  } else if (ageDays !== null && ageDays < 365) {
    label = "Dormant";
    dotClass = styles.activityDotDormant;
    title = "Last seen between 90 days and a year ago";
  } else if (ageDays === null) {
    title = "Never seen in feed content";
  }
  return (
    <span className={styles.activityBadge} title={title}>
      <span className={`${styles.activityDot} ${dotClass}`} />
      {label}
    </span>
  );
}

const EXPLOIT_LABELS: Record<string, string> = {
  active_exploitation: "Active",
  weaponized: "Weaponized",
  poc: "PoC",
  none: "None",
};

function ExploitBadge({ availability }: { availability: string | null }) {
  const key = availability || "none";
  const label = EXPLOIT_LABELS[key] || key.replace(/_/g, " ");
  const title = key.replace(/_/g, " ");
  // Exploit availability is its own axis, not a severity — the amber/orange
  // steps stay the literals the old .exploit* classes carried rather than
  // aliasing --severity-*. The red step is the exception: as a toned chip the
  // literal #dc2626 measured 3.66:1, under AA, and --danger is both the
  // semantically correct token and 5.06:1. The ramp is therefore partly themed
  // until an --exploit-* family exists to carry all three steps.
  const tint = availability === "poc" ? "#ca8a04"
    : availability === "weaponized" ? "#ea580c"
    : availability === "active_exploitation" ? "var(--danger)"
    : undefined;
  return (
    <Chip
      tone={tint ? "toned" : "default"}
      tint={tint}
      className={tint ? undefined : styles.exploitNone}
      title={title}
    >
      {label}
    </Chip>
  );
}

// --- Entity section column definitions ---
//
// `serverSort` keys must be accepted by that endpoint's `sort_by` pattern —
// everything else sorts client-side over the loaded rows. The primary
// name/ID column carries `serverText` so its filter box searches the whole
// corpus via `?search=`; the remaining filters narrow the loaded rows (the
// table backfills pages while they're active).

/** Muted, ellipsised text cell — the default for secondary entity fields. */
function MetaCell({ value }: { value: string | null | undefined }) {
  if (!value) return <span className={table.zero}>·</span>;
  return <span className={`${styles.entityMeta} ${table.ellipsis}`} title={value}>{value}</span>;
}

function DateCell({ value }: { value: string | null | undefined }) {
  if (!value) return <span className={table.zero}>·</span>;
  return <span className={table.dateCell} title={new Date(value).toLocaleString()}>{formatDate(value)}</span>;
}

/** External link cell — stops propagation so it doesn't also open the profile. */
function LinkCell({ href, label }: { href: string | null | undefined; label?: string }) {
  if (!href) return <span className={table.zero}>·</span>;
  let text = label;
  if (!text) {
    try {
      text = new URL(href).hostname.replace(/^www\./, "");
    } catch {
      text = href;
    }
  }
  return (
    <a
      className={`${styles.entityLink} ${table.ellipsis}`}
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      title={href}
      onClick={(e) => e.stopPropagation()}
    >
      {text} ↗
    </a>
  );
}

function NumCell({ value, tone }: { value: number | null | undefined; tone?: string }) {
  if (!value) return <span className={table.zero}>·</span>;
  return <span className={`${table.count} ${tone ? table[tone] : ""}`}>{value}</span>;
}

/** CISA KEV remediation deadline, flagged red once it's in the past. */
function KevDueCell({ value }: { value: string | null | undefined }) {
  if (!value) return <span className={table.zero}>·</span>;
  const overdue = new Date(value).getTime() < Date.now();
  return (
    <span
      className={overdue ? `${table.chip} ${table.chipCritical}` : table.dateCell}
      title={overdue ? `KEV remediation deadline passed (${value})` : `KEV remediation due ${value}`}
    >
      {formatDate(value)}
    </span>
  );
}

const listText = (v: string[] | null | undefined) => (v ?? []).join(", ");

const SEVERITY_CHOICES = [
  { value: "all", label: "Any" },
  { value: "CRITICAL", label: "Critical" },
  { value: "HIGH", label: "High" },
  { value: "MEDIUM", label: "Medium" },
  { value: "LOW", label: "Low" },
];

const TACTIC_CHOICES = [
  { value: "all", label: "Any" },
  ...[
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
  ].map((t) => ({ value: t, label: t.replace(/-/g, " ") })),
];

const THREAT_ACTOR_COLUMNS: ColumnDef<ThreatActor>[] = [
  {
    key: "name", label: "Name", width: 200, minWidth: 120, flex: true,
    serverSort: true, serverText: true, serverParam: "search",
    render: (a) => <span className={`${styles.entityName} ${table.ellipsis}`} title={a.name}>{a.name}</span>,
  },
  {
    key: "mitre_id", label: "MITRE", width: 90, minWidth: 70, hideable: true,
    textValue: (a) => a.mitre_id ?? "", sortValue: (a) => a.mitre_id ?? "￿",
    render: (a) => a.mitre_id ? <Chip tone="toned" tint="var(--entity-ttp)" className={styles.mitreId}>{a.mitre_id}</Chip> : <span className={table.zero}>·</span>,
  },
  {
    key: "aliases", label: "Aliases", width: 190, minWidth: 100, hideable: true,
    textValue: (a) => listText(a.aliases),
    render: (a) => <AliasesCell aliases={a.aliases} />,
  },
  {
    key: "country", label: "Country", width: 110, minWidth: 80, hideable: true,
    serverSort: true, textValue: (a) => a.country ?? "",
    render: (a) => <MetaCell value={a.country} />,
  },
  {
    key: "motivation", label: "Motivation", width: 130, minWidth: 90, hideable: true, defaultHidden: true,
    serverSort: true, textValue: (a) => a.motivation ?? "",
    render: (a) => <MetaCell value={a.motivation} />,
  },
  {
    key: "actor_type", label: "Actor Type", width: 120, minWidth: 90, hideable: true, defaultHidden: true,
    textValue: (a) => a.actor_type ?? "",
    render: (a) => <MetaCell value={a.actor_type} />,
  },
  {
    key: "targeted_sectors", label: "Sectors", width: 210, minWidth: 100, hideable: true,
    textValue: (a) => listText(a.targeted_sectors),
    render: (a) => <SectorsCell sectors={a.targeted_sectors} />,
  },
  {
    key: "article_count", label: "Articles", width: 80, minWidth: 64, hideable: true,
    serverSort: true, numValue: (a) => a.article_count ?? 0,
    render: (a) => <ArticleCount count={a.article_count} />,
  },
  {
    key: "activity", label: "Activity", width: 100, minWidth: 80, hideable: true,
    sortValue: (a) => a.last_seen_at ?? "",
    render: (a) => <ActivityBadge lastSeenAt={a.last_seen_at} />,
  },
  {
    key: "first_seen_at", label: "First Seen", width: 120, minWidth: 90, hideable: true, defaultHidden: true,
    sortValue: (a) => a.first_seen_at ?? "",
    render: (a) => <DateCell value={a.first_seen_at} />,
  },
  {
    key: "last_seen_at", label: "Last Seen", width: 120, minWidth: 90, hideable: true,
    serverSort: true,
    render: (a) => <DateCell value={a.last_seen_at} />,
  },
  {
    key: "description", label: "Description", width: 320, minWidth: 140, hideable: true, defaultHidden: true,
    textValue: (a) => a.description ?? "",
    render: (a) => <MetaCell value={a.description} />,
  },
  {
    key: "ttp_count", label: "TTPs", width: 70, minWidth: 56, hideable: true, defaultHidden: true,
    numValue: (a) => a.associated_ttps?.length ?? 0,
    render: (a) => <NumCell value={a.associated_ttps?.length} tone="ttp" />,
  },
  {
    key: "wikipedia_url", label: "Wikipedia", width: 150, minWidth: 90, hideable: true, defaultHidden: true,
    textValue: (a) => a.wikipedia_url ?? "",
    render: (a) => <LinkCell href={a.wikipedia_url} />,
  },
  ...PROVENANCE_COLUMNS<ThreatActor>(),
];

const MALWARE_COLUMNS: ColumnDef<MalwareFamily>[] = [
  {
    key: "name", label: "Name", width: 200, minWidth: 120, flex: true,
    serverSort: true, serverText: true, serverParam: "search",
    render: (m) => <span className={`${styles.entityName} ${table.ellipsis}`} title={m.name}>{m.name}</span>,
  },
  {
    key: "aliases", label: "Aliases", width: 220, minWidth: 100, hideable: true,
    textValue: (m) => listText(m.aliases),
    render: (m) => <AliasesCell aliases={m.aliases} />,
  },
  {
    key: "malware_type", label: "Type", width: 120, minWidth: 80, hideable: true,
    serverSort: true, textValue: (m) => m.malware_type ?? "",
    render: (m) => <Chip truncate>{m.malware_type || "unknown"}</Chip>,
  },
  {
    key: "targeted_sectors", label: "Sectors", width: 210, minWidth: 100, hideable: true,
    textValue: (m) => listText(m.targeted_sectors),
    render: (m) => <SectorsCell sectors={m.targeted_sectors} />,
  },
  {
    key: "mitre_id", label: "MITRE", width: 90, minWidth: 70, hideable: true, defaultHidden: true,
    textValue: (m) => m.mitre_id ?? "", sortValue: (m) => m.mitre_id ?? "\uffff",
    render: (m) => m.mitre_id ? <Chip tone="toned" tint="var(--entity-ttp)" className={styles.mitreId}>{m.mitre_id}</Chip> : <span className={table.zero}>·</span>,
  },
  {
    key: "article_count", label: "Articles", width: 80, minWidth: 64, hideable: true,
    serverSort: true, numValue: (m) => m.article_count ?? 0,
    render: (m) => <ArticleCount count={m.article_count} />,
  },
  {
    key: "first_seen_at", label: "First Seen", width: 120, minWidth: 90, hideable: true,
    sortValue: (m) => m.first_seen_at ?? "",
    render: (m) => <DateCell value={m.first_seen_at} />,
  },
  {
    key: "last_seen_at", label: "Last Seen", width: 120, minWidth: 90, hideable: true,
    serverSort: true,
    render: (m) => <DateCell value={m.last_seen_at} />,
  },
  {
    key: "description", label: "Description", width: 320, minWidth: 140, hideable: true, defaultHidden: true,
    textValue: (m) => m.description ?? "",
    render: (m) => <MetaCell value={m.description} />,
  },
  {
    key: "actor_count", label: "Actors", width: 70, minWidth: 56, hideable: true, defaultHidden: true,
    numValue: (m) => m.associated_actors?.length ?? 0,
    render: (m) => <NumCell value={m.associated_actors?.length} />,
  },
  {
    key: "malpedia_url", label: "Malpedia", width: 150, minWidth: 90, hideable: true, defaultHidden: true,
    textValue: (m) => m.malpedia_url ?? "",
    render: (m) => <LinkCell href={m.malpedia_url} />,
  },
  {
    key: "wikipedia_url", label: "Wikipedia", width: 150, minWidth: 90, hideable: true, defaultHidden: true,
    textValue: (m) => m.wikipedia_url ?? "",
    render: (m) => <LinkCell href={m.wikipedia_url} />,
  },
  ...PROVENANCE_COLUMNS<MalwareFamily>(),
];

const CVE_COLUMNS: ColumnDef<CVE>[] = [
  {
    key: "cve_id", label: "CVE ID", width: 150, minWidth: 120,
    serverSort: true, serverText: true, serverParam: "search",
    render: (c) => <span className={styles.entityName}>{c.cve_id}</span>,
  },
  {
    key: "risk_tier", label: "Risk", width: 90, minWidth: 70, hideable: true,
    serverSort: true,
    choices: [
      { value: "all", label: "Any" },
      { value: "critical", label: "Critical" },
      { value: "high", label: "High" },
      { value: "medium", label: "Medium" },
      { value: "low", label: "Low" },
    ],
    choiceMatch: (c, v) => c.risk_tier === v,
    render: (c) => c.risk_tier
      ? <Chip tone="toned" tint={getSeverityTint(c.risk_tier)}>{c.risk_tier.toUpperCase()}</Chip>
      : <span className={table.zero}>·</span>,
  },
  {
    key: "is_kev", label: "KEV", width: 70, minWidth: 56, hideable: true,
    serverSort: true, serverChoice: true, serverParam: "kev_only",
    choices: [
      { value: "all", label: "Any" },
      { value: "true", label: "KEV" },
    ],
    render: (c) => c.is_kev
      ? <Chip tone="toned" tint="var(--danger)" title={`CISA Known Exploited Vulnerability${c.kev_date_added ? ` — added ${c.kev_date_added}` : ""}`}>KEV</Chip>
      : <span className={table.zero}>·</span>,
  },
  {
    key: "epss_score", label: "EPSS", width: 80, minWidth: 64, hideable: true,
    serverSort: true,
    render: (c) => (
      <span className={table.dateCell} title={c.epss_percentile != null ? `${(Number(c.epss_percentile) * 100).toFixed(0)}th percentile` : undefined}>
        {c.epss_score != null ? `${(Number(c.epss_score) * 100).toFixed(Number(c.epss_score) < 0.1 ? 1 : 0)}%` : "—"}
      </span>
    ),
  },
  {
    key: "severity", label: "Severity", width: 100, minWidth: 76, hideable: true,
    serverSort: true, serverChoice: true, serverParam: "severity", choices: SEVERITY_CHOICES,
    render: (c) => <Chip tone="toned" tint={getSeverityTint(c.severity)}>{c.severity?.toUpperCase() || "N/A"}</Chip>,
  },
  {
    key: "cvss_score", label: "CVSS", width: 70, minWidth: 60, hideable: true,
    serverSort: true,
    render: (c) => <span className={table.dateCell}>{c.cvss_score != null ? Number(c.cvss_score).toFixed(1) : "—"}</span>,
  },
  {
    key: "description", label: "Description", width: 340, minWidth: 160, flex: true, hideable: true,
    textValue: (c) => c.description ?? "",
    render: (c) => <MetaCell value={c.description} />,
  },
  {
    key: "affected_products", label: "Affected", width: 180, minWidth: 100, hideable: true,
    textValue: (c) => (c.affected_products ?? []).map((p) => `${p.vendor || ""} ${p.product || ""}`).join(", "),
    render: (c) => {
      const products = c.affected_products?.slice(0, 3) || [];
      if (!products.length) return <span className={table.zero}>·</span>;
      const label = products.map((p) => String(p.product || p.vendor || "")).filter(Boolean).join(", ");
      const extra = (c.affected_products?.length || 0) - 3;
      return (
        <span className={`${styles.entityMeta} ${table.ellipsis}`} title={c.affected_products?.map((p) => `${p.vendor || ""}/${p.product || ""}`).join(", ")}>
          {label}{extra > 0 ? ` +${extra}` : ""}
        </span>
      );
    },
  },
  {
    key: "exploit_availability", label: "Exploit", width: 100, minWidth: 80, hideable: true,
    serverSort: true, textValue: (c) => c.exploit_availability ?? "",
    render: (c) => <ExploitBadge availability={c.exploit_availability ?? null} />,
  },
  {
    key: "article_count", label: "Articles", width: 90, minWidth: 64, hideable: true,
    serverSort: true, numValue: (c) => c.article_count ?? 0,
    render: (c) => <ArticleCount count={c.article_count} />,
  },
  {
    key: "first_seen_at", label: "First Seen", width: 120, minWidth: 90, hideable: true, defaultHidden: true,
    serverSort: true,
    render: (c) => <DateCell value={c.first_seen_at} />,
  },
  {
    key: "updated_at", label: "Updated", width: 130, minWidth: 90, hideable: true,
    serverSort: true,
    render: (c) => <DateCell value={c.updated_at} />,
  },
  {
    key: "kev_due_date", label: "KEV Due", width: 110, minWidth: 84, hideable: true, defaultHidden: true,
    sortValue: (c) => c.kev_due_date ?? "\uffff",
    render: (c) => <KevDueCell value={c.kev_due_date} />,
  },
  {
    key: "kev_date_added", label: "KEV Added", width: 110, minWidth: 84, hideable: true, defaultHidden: true,
    sortValue: (c) => c.kev_date_added ?? "",
    render: (c) => <DateCell value={c.kev_date_added} />,
  },
  {
    key: "epss_change", label: "EPSS \u0394", width: 90, minWidth: 70, hideable: true, defaultHidden: true,
    numValue: (c) => (c.epss_score != null && c.epss_previous_score != null ? Number(c.epss_score) - Number(c.epss_previous_score) : 0),
    render: (c) => {
      if (c.epss_score == null || c.epss_previous_score == null) return <span className={table.zero}>·</span>;
      const delta = (Number(c.epss_score) - Number(c.epss_previous_score)) * 100;
      if (Math.abs(delta) < 0.05) return <span className={table.zero}>·</span>;
      return (
        <span className={table.dateCell} title={c.epss_changed_at ? `Changed ${c.epss_changed_at.slice(0, 10)}` : undefined}>
          {delta > 0 ? "+" : ""}{delta.toFixed(1)}pp
        </span>
      );
    },
  },
  {
    key: "epss_percentile", label: "EPSS %ile", width: 90, minWidth: 70, hideable: true, defaultHidden: true,
    numValue: (c) => Number(c.epss_percentile ?? 0),
    render: (c) => c.epss_percentile != null
      ? <span className={table.dateCell}>{(Number(c.epss_percentile) * 100).toFixed(0)}th</span>
      : <span className={table.zero}>·</span>,
  },
  {
    key: "exploit_status", label: "Exploit Status", width: 130, minWidth: 90, hideable: true, defaultHidden: true,
    textValue: (c) => c.exploit_status ?? "",
    render: (c) => <MetaCell value={c.exploit_status} />,
  },
  {
    key: "exploit_sources", label: "Exploit Src", width: 160, minWidth: 90, hideable: true, defaultHidden: true,
    textValue: (c) => exploitSourcesText(c.exploit_sources),
    render: (c) => <MetaCell value={exploitSourcesText(c.exploit_sources)} />,
  },
  {
    key: "priority", label: "Priority", width: 90, minWidth: 70, hideable: true, defaultHidden: true,
    textValue: (c) => c.priority ?? "",
    render: (c) => <MetaCell value={c.priority} />,
  },
  {
    key: "github_poc_count", label: "PoCs", width: 70, minWidth: 56, hideable: true, defaultHidden: true,
    numValue: (c) => c.github_poc_count ?? 0,
    render: (c) => (
      <span title={c.github_poc_urls?.slice(0, 8).join("\n")}>
        <NumCell value={c.github_poc_count} tone="cve" />
      </span>
    ),
  },
  {
    key: "metasploit_module", label: "MSF", width: 150, minWidth: 80, hideable: true, defaultHidden: true,
    textValue: (c) => c.metasploit_module ?? "",
    render: (c) => <MetaCell value={c.metasploit_module} />,
  },
  {
    key: "references", label: "Refs", width: 70, minWidth: 56, hideable: true, defaultHidden: true,
    numValue: (c) => c.references_?.length ?? 0,
    render: (c) => <NumCell value={c.references_?.length} />,
  },
];

const TTP_COLUMNS: ColumnDef<TTP>[] = [
  {
    key: "technique_id", label: "ID", width: 130, minWidth: 100,
    serverSort: true, serverText: true, serverParam: "search",
    render: (t) => (
      <span className={styles.entityName}>
        {t.technique_id}
        {t.is_subtechnique && <span className={styles.subtechIndicator}> (sub)</span>}
      </span>
    ),
  },
  {
    key: "technique_name", label: "Name", width: 260, minWidth: 140, flex: true,
    serverSort: true, textValue: (t) => t.technique_name ?? "",
    render: (t) => (
      <span className={`${styles.entityMeta} ${table.ellipsis}`} title={t.technique_name}>
        {/* Un-hydrated stubs mirror the ID as the name — show a dash instead */}
        {t.technique_name && t.technique_name !== t.technique_id ? t.technique_name : "—"}
        {t.is_deprecated && <span className={styles.subtechIndicator}> (deprecated)</span>}
      </span>
    ),
  },
  {
    key: "tactic", label: "Tactic", width: 150, minWidth: 100, hideable: true,
    serverSort: true, serverChoice: true, serverParam: "tactic", choices: TACTIC_CHOICES,
    render: (t) => <Chip truncate>{t.tactic || "-"}</Chip>,
  },
  {
    key: "platforms", label: "Platforms", width: 160, minWidth: 90, hideable: true, defaultHidden: true,
    textValue: (t) => listText(t.platforms),
    render: (t) => <MetaCell value={listText(t.platforms)} />,
  },
  {
    key: "data_sources", label: "Data Sources", width: 200, minWidth: 100, hideable: true, defaultHidden: true,
    textValue: (t) => listText(t.data_sources),
    render: (t) => <MetaCell value={listText(t.data_sources)} />,
  },
  {
    key: "article_count", label: "Articles", width: 80, minWidth: 64, hideable: true,
    serverSort: true, numValue: (t) => t.article_count ?? 0,
    render: (t) => <ArticleCount count={t.article_count} />,
  },
  {
    key: "first_seen_at", label: "First Seen", width: 120, minWidth: 90, hideable: true,
    serverSort: true,
    render: (t) => <DateCell value={t.first_seen_at} />,
  },
  {
    key: "last_seen_at", label: "Last Seen", width: 120, minWidth: 90, hideable: true,
    serverSort: true,
    render: (t) => <DateCell value={t.last_seen_at} />,
  },
  {
    key: "matrix_domain", label: "Domain", width: 110, minWidth: 80, hideable: true, defaultHidden: true,
    textValue: (t) => t.matrix_domain ?? "",
    render: (t) => t.matrix_domain
      ? <Chip truncate>{t.matrix_domain}</Chip>
      : <span className={table.zero}>·</span>,
  },
  {
    key: "is_subtechnique", label: "Sub", width: 70, minWidth: 56, hideable: true, defaultHidden: true,
    sortValue: (t) => (t.is_subtechnique ? 1 : 0),
    choices: [
      { value: "all", label: "Any" },
      { value: "yes", label: "Sub only" },
      { value: "no", label: "Parents only" },
    ],
    choiceMatch: (t, v) => (v === "yes" ? !!t.is_subtechnique : !t.is_subtechnique),
    render: (t) => t.is_subtechnique
      ? <Chip>sub</Chip>
      : <span className={table.zero}>·</span>,
  },
  {
    key: "parent_technique_id", label: "Parent", width: 100, minWidth: 76, hideable: true, defaultHidden: true,
    textValue: (t) => t.parent_technique_id ?? "",
    render: (t) => <MetaCell value={t.parent_technique_id} />,
  },
  {
    key: "tactics", label: "All Tactics", width: 200, minWidth: 100, hideable: true, defaultHidden: true,
    textValue: (t) => listText(t.tactics),
    render: (t) => <MetaCell value={listText(t.tactics)} />,
  },
  {
    key: "detection", label: "Detection", width: 320, minWidth: 140, hideable: true, defaultHidden: true,
    textValue: (t) => t.detection ?? "",
    render: (t) => <MetaCell value={t.detection} />,
  },
  {
    key: "description", label: "Description", width: 320, minWidth: 140, hideable: true, defaultHidden: true,
    textValue: (t) => t.description ?? "",
    render: (t) => <MetaCell value={t.description} />,
  },
  {
    key: "mitre_url", label: "MITRE Link", width: 140, minWidth: 90, hideable: true, defaultHidden: true,
    textValue: (t) => t.mitre_url ?? "",
    render: (t) => <LinkCell href={t.mitre_url} label="attack.mitre.org" />,
  },
];

const COUNTRY_COLUMNS: ColumnDef<Country>[] = [
  {
    key: "name", label: "Name", width: 200, minWidth: 120, flex: true,
    serverSort: true, serverText: true, serverParam: "search",
    render: (c) => <span className={`${styles.entityName} ${table.ellipsis}`} title={c.name}>{c.name}</span>,
  },
  {
    key: "iso_code", label: "ISO", width: 80, minWidth: 60, hideable: true,
    serverSort: true, textValue: (c) => c.iso_code ?? "",
    render: (c) => <Chip>{c.iso_code}</Chip>,
  },
  {
    key: "region", label: "Region", width: 140, minWidth: 90, hideable: true,
    serverSort: true, textValue: (c) => c.region ?? "",
    render: (c) => <MetaCell value={c.region} />,
  },
  {
    key: "targeting_actor_count", label: "Targeted By", width: 110, minWidth: 80, hideable: true,
    numValue: (c) => c.targeting_actor_count ?? 0,
    render: (c) => c.targeting_actor_count
      ? <span className={styles.entityMeta}>{c.targeting_actor_count} actor{c.targeting_actor_count === 1 ? "" : "s"}</span>
      : <span className={table.zero}>·</span>,
  },
  {
    key: "aliases", label: "Aliases", width: 180, minWidth: 100, hideable: true,
    textValue: (c) => listText(c.aliases),
    render: (c) => <AliasesCell aliases={c.aliases} />,
  },
  {
    key: "article_count", label: "Articles", width: 80, minWidth: 64, hideable: true,
    serverSort: true, numValue: (c) => c.article_count ?? 0,
    render: (c) => <ArticleCount count={c.article_count} />,
  },
  {
    key: "last_seen_at", label: "Last Seen", width: 120, minWidth: 90, hideable: true,
    serverSort: true,
    render: (c) => <DateCell value={c.last_seen_at} />,
  },
  {
    key: "first_seen_at", label: "First Seen", width: 120, minWidth: 90, hideable: true, defaultHidden: true,
    sortValue: (c) => c.first_seen_at ?? "",
    render: (c) => <DateCell value={c.first_seen_at} />,
  },
  {
    key: "description", label: "Description", width: 320, minWidth: 140, hideable: true, defaultHidden: true,
    textValue: (c) => c.description ?? "",
    render: (c) => <MetaCell value={c.description} />,
  },
];

const SECTOR_COLUMNS: ColumnDef<Sector>[] = [
  {
    key: "name", label: "Name", width: 200, minWidth: 120, flex: true,
    serverSort: true, serverText: true, serverParam: "search",
    render: (s) => <span className={`${styles.entityName} ${table.ellipsis}`} title={s.name}>{s.name}</span>,
  },
  {
    key: "targeting_actor_count", label: "Targeted By", width: 120, minWidth: 90, hideable: true,
    serverSort: true, numValue: (s) => s.targeting_actor_count ?? 0,
    render: (s) => s.targeting_actor_count
      ? <span className={styles.entityMeta}>{s.targeting_actor_count} actor{s.targeting_actor_count === 1 ? "" : "s"}</span>
      : <span className={table.zero}>·</span>,
  },
  {
    key: "targeting_malware_count", label: "Malware", width: 110, minWidth: 80, hideable: true,
    numValue: (s) => s.targeting_malware_count ?? 0,
    render: (s) => s.targeting_malware_count
      ? <span className={styles.entityMeta}>{s.targeting_malware_count} famil{s.targeting_malware_count === 1 ? "y" : "ies"}</span>
      : <span className={table.zero}>·</span>,
  },
  {
    key: "victim_count", label: "Victims (90d)", width: 120, minWidth: 90, hideable: true,
    serverSort: true, numValue: (s) => s.victim_count ?? 0,
    render: (s) => s.victim_count
      ? <span className={styles.entityMeta}>{s.victim_count}</span>
      : <span className={table.zero}>·</span>,
  },
  {
    key: "article_count", label: "Articles", width: 80, minWidth: 64, hideable: true,
    serverSort: true, numValue: (s) => s.article_count ?? 0,
    render: (s) => <ArticleCount count={s.article_count} />,
  },
  {
    key: "last_seen_at", label: "Last Seen", width: 120, minWidth: 90, hideable: true,
    serverSort: true,
    render: (s) => <DateCell value={s.last_seen_at} />,
  },
  {
    key: "aliases", label: "Aliases", width: 220, minWidth: 100, hideable: true, defaultHidden: true,
    textValue: (s) => listText(s.aliases),
    render: (s) => <AliasesCell aliases={s.aliases} />,
  },
  {
    key: "slug", label: "Slug", width: 160, minWidth: 100, hideable: true, defaultHidden: true,
    textValue: (s) => s.slug,
    render: (s) => <Chip>{s.slug}</Chip>,
  },
  {
    key: "description", label: "Description", width: 320, minWidth: 140, hideable: true, defaultHidden: true,
    textValue: (s) => s.description ?? "",
    render: (s) => <MetaCell value={s.description} />,
  },
];

const MITIGATION_COLUMNS: ColumnDef<Mitigation>[] = [
  {
    key: "name", label: "Name", width: 220, minWidth: 120, flex: true,
    serverSort: true, serverText: true, serverParam: "search",
    render: (m) => <span className={`${styles.entityName} ${table.ellipsis}`} title={m.name}>{m.name}</span>,
  },
  {
    key: "mitre_id", label: "M-ID", width: 90, minWidth: 70, hideable: true,
    serverSort: true,
    render: (m) => m.mitre_id ? <Chip tone="toned" tint="var(--entity-ttp)" className={styles.mitreId}>{m.mitre_id}</Chip> : <span className={table.zero}>·</span>,
  },
  {
    key: "cis_controls", label: "CIS", width: 140, minWidth: 80, hideable: true,
    textValue: (m) => listText(m.cis_controls),
    render: (m) => <MetaCell value={m.cis_controls?.slice(0, 3).join(", ")} />,
  },
  {
    key: "nist_controls", label: "NIST", width: 140, minWidth: 80, hideable: true,
    textValue: (m) => listText(m.nist_controls),
    render: (m) => <MetaCell value={m.nist_controls?.slice(0, 3).join(", ")} />,
  },
  {
    key: "article_count", label: "Articles", width: 80, minWidth: 64, hideable: true,
    serverSort: true, numValue: (m) => m.article_count ?? 0,
    render: (m) => <ArticleCount count={m.article_count} />,
  },
  {
    key: "last_seen_at", label: "Last Seen", width: 120, minWidth: 90, hideable: true,
    sortValue: (m) => m.last_seen_at ?? "",
    render: (m) => <DateCell value={m.last_seen_at} />,
  },
  {
    key: "description", label: "Description", width: 320, minWidth: 140, hideable: true, defaultHidden: true,
    textValue: (m) => m.description ?? "",
    render: (m) => <MetaCell value={m.description} />,
  },
  {
    key: "first_seen_at", label: "First Seen", width: 120, minWidth: 90, hideable: true, defaultHidden: true,
    sortValue: (m) => m.first_seen_at ?? "",
    render: (m) => <DateCell value={m.first_seen_at} />,
  },
  {
    key: "source", label: "Source", width: 120, minWidth: 80, hideable: true, defaultHidden: true,
    textValue: (m) => m.source ?? "",
    render: (m) => <MetaCell value={m.source} />,
  },
  {
    key: "confidence", label: "Confidence", width: 100, minWidth: 76, hideable: true, defaultHidden: true,
    textValue: (m) => m.confidence ?? "",
    render: (m) => <MetaCell value={m.confidence} />,
  },
  {
    key: "mitre_url", label: "MITRE Link", width: 140, minWidth: 90, hideable: true, defaultHidden: true,
    textValue: (m) => m.mitre_url ?? "",
    render: (m) => <LinkCell href={m.mitre_url} label="attack.mitre.org" />,
  },
];

const TOOL_COLUMNS: ColumnDef<OffensiveTool>[] = [
  {
    key: "name", label: "Name", width: 200, minWidth: 120, flex: true,
    serverSort: true, serverText: true, serverParam: "search",
    render: (t) => <span className={`${styles.entityName} ${table.ellipsis}`} title={t.name}>{t.name}</span>,
  },
  {
    key: "tool_type", label: "Type", width: 130, minWidth: 90, hideable: true,
    serverSort: true, textValue: (t) => t.tool_type ?? "",
    render: (t) => <Chip truncate>{t.tool_type?.replace(/_/g, " ") || "unknown"}</Chip>,
  },
  {
    key: "aliases", label: "Aliases", width: 200, minWidth: 100, hideable: true,
    textValue: (t) => listText(t.aliases),
    render: (t) => <AliasesCell aliases={t.aliases} />,
  },
  {
    key: "platforms", label: "Platforms", width: 150, minWidth: 90, hideable: true,
    textValue: (t) => listText(t.platforms),
    render: (t) => <MetaCell value={listText(t.platforms)} />,
  },
  {
    key: "article_count", label: "Articles", width: 80, minWidth: 64, hideable: true,
    serverSort: true, numValue: (t) => t.article_count ?? 0,
    render: (t) => <ArticleCount count={t.article_count} />,
  },
  {
    key: "first_seen_at", label: "First Seen", width: 120, minWidth: 90, hideable: true, defaultHidden: true,
    serverSort: true,
    render: (t) => <DateCell value={t.first_seen_at} />,
  },
  {
    key: "last_seen_at", label: "Last Seen", width: 120, minWidth: 90, hideable: true,
    serverSort: true,
    render: (t) => <DateCell value={t.last_seen_at} />,
  },
  {
    key: "github_url", label: "GitHub", width: 160, minWidth: 90, hideable: true, defaultHidden: true,
    textValue: (t) => t.github_url ?? "",
    render: (t) => <LinkCell href={t.github_url} />,
  },
  {
    key: "malpedia_url", label: "Malpedia", width: 150, minWidth: 90, hideable: true, defaultHidden: true,
    textValue: (t) => t.malpedia_url ?? "",
    render: (t) => <LinkCell href={t.malpedia_url} />,
  },
  {
    key: "detection_artifacts", label: "Artifacts", width: 90, minWidth: 70, hideable: true, defaultHidden: true,
    numValue: (t) => Object.keys(t.detection_artifacts ?? {}).length,
    render: (t) => {
      const keys = Object.keys(t.detection_artifacts ?? {});
      if (!keys.length) return <span className={table.zero}>·</span>;
      return <span className={table.count} title={keys.join(", ")}>{keys.length}</span>;
    },
  },
  {
    key: "description", label: "Description", width: 320, minWidth: 140, hideable: true, defaultHidden: true,
    textValue: (t) => t.description ?? "",
    render: (t) => <MetaCell value={t.description} />,
  },
  {
    key: "mitre_id", label: "MITRE", width: 90, minWidth: 70, hideable: true, defaultHidden: true,
    textValue: (t) => t.mitre_id ?? "", sortValue: (t) => t.mitre_id ?? "\uffff",
    render: (t) => t.mitre_id ? <Chip tone="toned" tint="var(--entity-ttp)" className={styles.mitreId}>{t.mitre_id}</Chip> : <span className={table.zero}>·</span>,
  },
  {
    key: "wikipedia_url", label: "Wikipedia", width: 150, minWidth: 90, hideable: true, defaultHidden: true,
    textValue: (t) => t.wikipedia_url ?? "",
    render: (t) => <LinkCell href={t.wikipedia_url} />,
  },
  ...PROVENANCE_COLUMNS<OffensiveTool>(),
];

const VENDOR_COLUMNS: ColumnDef<Vendor>[] = [
  {
    key: "name", label: "Name", width: 200, minWidth: 120, flex: true,
    serverSort: true, serverText: true, serverParam: "search",
    render: (v) => <span className={`${styles.entityName} ${table.ellipsis}`} title={v.name}>{v.name}</span>,
  },
  {
    key: "vendor_type", label: "Type", width: 140, minWidth: 90, hideable: true,
    serverSort: true, textValue: (v) => v.vendor_type ?? "",
    render: (v) => <Chip truncate>{v.vendor_type?.replace(/_/g, " ") || "unknown"}</Chip>,
  },
  {
    key: "website", label: "Website", width: 200, minWidth: 100, hideable: true, defaultHidden: true,
    textValue: (v) => v.website ?? "",
    render: (v) => <LinkCell href={v.website} />,
  },
  {
    key: "article_count", label: "Articles", width: 80, minWidth: 64, hideable: true,
    serverSort: true, numValue: (v) => v.article_count ?? 0,
    render: (v) => <ArticleCount count={v.article_count} />,
  },
  {
    key: "first_seen_at", label: "First Seen", width: 120, minWidth: 90, hideable: true,
    serverSort: true,
    render: (v) => <DateCell value={v.first_seen_at} />,
  },
  {
    key: "last_seen_at", label: "Last Seen", width: 120, minWidth: 90, hideable: true,
    serverSort: true,
    render: (v) => <DateCell value={v.last_seen_at} />,
  },
  {
    key: "aliases", label: "Aliases", width: 200, minWidth: 100, hideable: true, defaultHidden: true,
    textValue: (v) => listText(v.aliases),
    render: (v) => <AliasesCell aliases={v.aliases} />,
  },
  {
    key: "description", label: "Description", width: 320, minWidth: 140, hideable: true, defaultHidden: true,
    textValue: (v) => v.description ?? "",
    render: (v) => <MetaCell value={v.description} />,
  },
];

const PRODUCT_COLUMNS: ColumnDef<Product>[] = [
  {
    key: "name", label: "Name", width: 200, minWidth: 120, flex: true,
    serverSort: true, serverText: true, serverParam: "search",
    render: (p) => <span className={`${styles.entityName} ${table.ellipsis}`} title={p.name}>{p.name}</span>,
  },
  {
    key: "product_type", label: "Type", width: 140, minWidth: 90, hideable: true,
    serverSort: true, textValue: (p) => p.product_type ?? "",
    render: (p) => <Chip truncate>{p.product_type?.replace(/_/g, " ") || "unknown"}</Chip>,
  },
  {
    key: "vendor_name", label: "Vendor", width: 160, minWidth: 90, hideable: true,
    textValue: (p) => p.vendor_name ?? "", sortValue: (p) => (p.vendor_name ?? "￿").toLowerCase(),
    render: (p) => <MetaCell value={p.vendor_name} />,
  },
  {
    key: "article_count", label: "Articles", width: 80, minWidth: 64, hideable: true,
    serverSort: true, numValue: (p) => p.article_count ?? 0,
    render: (p) => <ArticleCount count={p.article_count} />,
  },
  {
    key: "first_seen_at", label: "First Seen", width: 120, minWidth: 90, hideable: true,
    serverSort: true,
    render: (p) => <DateCell value={p.first_seen_at} />,
  },
  {
    key: "last_seen_at", label: "Last Seen", width: 120, minWidth: 90, hideable: true,
    serverSort: true,
    render: (p) => <DateCell value={p.last_seen_at} />,
  },
  {
    key: "aliases", label: "Aliases", width: 200, minWidth: 100, hideable: true, defaultHidden: true,
    textValue: (p) => listText(p.aliases),
    render: (p) => <AliasesCell aliases={p.aliases} />,
  },
  {
    key: "website", label: "Website", width: 180, minWidth: 100, hideable: true, defaultHidden: true,
    textValue: (p) => p.website ?? "",
    render: (p) => <LinkCell href={p.website} />,
  },
  {
    key: "description", label: "Description", width: 320, minWidth: 140, hideable: true, defaultHidden: true,
    textValue: (p) => p.description ?? "",
    render: (p) => <MetaCell value={p.description} />,
  },
];


// --- Entity sections (using EntityTableSection) ---

function FindDuplicatesButton({ entityType }: { entityType: string }) {
  const [showModal, setShowModal] = useState(false);
  // Merging is admin-only on the backend.
  const isAdmin = useAuthStore((s) => s.user?.role === "admin");
  if (!isAdmin) return null;
  return (
    <>
      <button className={styles.btn} onClick={() => setShowModal(true)} title="Find and merge duplicate entities">
        Find Duplicates
      </button>
      {showModal && <EntityMergeModal entityType={entityType} onClose={() => setShowModal(false)} />}
    </>
  );
}

function ThreatActorsSection() {
  return (
    <EntityTableSection<ThreatActor>
      title="Threat Actors"
      entityType="threat_actor"
      columns={THREAT_ACTOR_COLUMNS}
      queryKey="threat-actors"
      endpoint="/threat-actors"
      defaultSort={{ key: "name", dir: "asc" }}
      emptyTitle="No threat actors yet"
      emptyDesc="Extract intelligence from articles to populate threat actors."
      getId={(a) => a.id}
      getLabel={(a) => a.name}
      noun="actor"
      filters={<FindDuplicatesButton entityType="threat_actor" />}
    />
  );
}

function MalwareSection() {
  return (
    <EntityTableSection<MalwareFamily>
      title="Malware"
      entityType="malware"
      columns={MALWARE_COLUMNS}
      queryKey="malware"
      endpoint="/malware"
      defaultSort={{ key: "name", dir: "asc" }}
      emptyTitle="No malware families yet"
      emptyDesc="Extract intelligence from articles to populate malware families."
      getId={(m) => m.id}
      getLabel={(m) => m.name}
      noun="family"
      nounPlural="families"
      filters={<FindDuplicatesButton entityType="malware" />}
    />
  );
}

function CVEsSection() {
  return (
    <EntityTableSection<CVE>
      title="CVEs"
      entityType="cve"
      columns={CVE_COLUMNS}
      queryKey="cves"
      endpoint="/cves"
      defaultSort={{ key: "first_seen_at", dir: "desc" }}
      emptyTitle="No CVEs tracked"
      emptyDesc="CVEs are extracted from articles automatically."
      getId={(c) => c.id}
      getLabel={(c) => c.cve_id}
      noun="CVE"
    />
  );
}

const OBSERVABLE_KIND_CHOICES = [
  { value: "all", label: "Any" },
  ...[
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "uri_path",
    "ja3",
    "ja4",
    "cert_fingerprint",
    "md5",
    "sha1",
    "sha256",
    "email",
    "cmdline",
    "registry",
    "path",
    "mutex",
    "named_pipe",
    "service_name",
    "user_agent",
    "script",
  ].map((v) => ({ value: v, label: v })),
];

const OBSERVABLE_STATUS_CHOICES = [
  { value: "all", label: "Any" },
  ...["active", "aging", "expired"].map((v) => ({ value: v, label: v })),
];

const OBSERVABLE_VIA_CHOICES = [
  { value: "all", label: "Any" },
  { value: "ai_extraction", label: "analysis ai" },
  { value: "ttp_observable", label: "ttp observable" },
  { value: "ioc_list", label: "ioc_list feed" },
  { value: "manual", label: "analyst" },
];

const OBSERVABLE_INFRA_CHOICES = [
  { value: "all", label: "Any" },
  { value: "none", label: "indicators only" },
  { value: "any", label: "any infra" },
  ...["vpn", "proxy", "tor", "rmm", "kvm", "scanner", "phish_sim"].map((v) => ({
    value: v,
    label: v.replace(/_/g, " "),
  })),
];

const OBSERVABLE_COLUMNS: ColumnDef<ObservableResponse>[] = [
  {
    key: "value", label: "Value", width: 300, minWidth: 180, flex: true,
    serverSort: true, serverText: true, serverParam: "search", textValue: (o) => o.value,
    render: (o) => (
      <span
        className={table.ellipsis}
        style={{ fontFamily: "var(--font-mono)", fontSize: "12px" }}
        title={o.label ? `${o.label} — ${o.value}` : o.value}
      >
        {o.kind === "script" && o.label ? `“${o.label}” · ` : ""}
        {o.value}
      </span>
    ),
  },
  {
    key: "kind", label: "Kind", width: 110, minWidth: 80,
    serverSort: true, serverChoice: true, serverParam: "kind", choices: OBSERVABLE_KIND_CHOICES,
    render: (o) => <Chip truncate tone="toned" tint="var(--entity-ioc)">{o.kind}</Chip>,
  },
  {
    // Dual-use infrastructure: kept in the ledger as context, never published.
    key: "infra_tag", label: "Infra", width: 96, minWidth: 72, hideable: true,
    serverChoice: true, serverParam: "infra_tag", choices: OBSERVABLE_INFRA_CHOICES,
    render: (o) =>
      o.infra_tag
        ? <Chip truncate tone="toned" tint="var(--warning)" title="Dual-use infrastructure — excluded from publishing">{o.infra_tag.replace(/_/g, " ")}</Chip>
        : <span className={table.zero}>·</span>,
  },
  {
    // The decayed number, not the base: what the value is worth today.
    key: "current_confidence", label: "Confidence", width: 128, minWidth: 100,
    serverSort: true, numValue: (o) => o.current_confidence,
    render: (o) => {
      const pct = Math.round(o.current_confidence * 100);
      const tone = pct >= 50 ? "var(--success)" : pct >= 15 ? "var(--warning)" : "var(--danger)";
      const decay = o.confidence_pinned
        ? "Confidence pinned"
        : o.decay_half_life_days
          ? `${o.decay_half_life_days}d half-life${o.expires_at ? ` · expires ~${new Date(o.expires_at).toLocaleDateString()} unless re-sighted` : ""}`
          : "Never decays — behavior persists";
      return (
        <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }} title={decay}>
          <span style={{ width: 44, height: 5, borderRadius: 999, background: "var(--bg-tertiary)", overflow: "hidden", flex: "none" }}>
            <span style={{ display: "block", width: `${pct}%`, height: "100%", background: tone }} />
          </span>
          <span className={table.count}>
            {pct}%{o.confidence_pinned ? " ⚲" : ""}
          </span>
          {!o.confidence_pinned && o.decay_half_life_days ? (
            <span className={table.muted} style={{ fontSize: 10 }}>↓{o.decay_half_life_days}d</span>
          ) : null}
        </span>
      );
    },
  },
  {
    // article_count stays off the column list: sightings count the same
    // junction today, and "Linked" (the shared claims column every entity
    // table gets) is the design mock's linked count.
    key: "sighting_count", label: "Sightings", width: 90, minWidth: 70,
    serverSort: true, numValue: (o) => o.sighting_count,
    render: (o) => <NumCell value={o.sighting_count} />,
  },
  {
    key: "role", label: "Role", width: 96, minWidth: 70, hideable: true,
    serverChoice: true, serverParam: "role",
    choices: [
      { value: "all", label: "Any" },
      ...["c2", "delivery", "payload", "phishing", "exfil", "exploit", "scanning"].map((v) => ({ value: v, label: v })),
    ],
    render: (o) => (o.role ? <Chip truncate>{o.role}</Chip> : <span className={table.zero}>·</span>),
  },
  {
    key: "created_via", label: "Captured by", width: 130, minWidth: 100, hideable: true,
    serverChoice: true, serverParam: "created_via", choices: OBSERVABLE_VIA_CHOICES,
    render: (o) => (
      <span className={table.muted}>
        {OBSERVABLE_VIA_CHOICES.find((c) => c.value === o.created_via)?.label ?? o.created_via ?? "·"}
      </span>
    ),
  },
  {
    key: "status", label: "Status", width: 92, minWidth: 72, hideable: true,
    serverSort: true, serverChoice: true, serverParam: "status", choices: OBSERVABLE_STATUS_CHOICES,
    render: (o) =>
      o.status === "active"
        ? <Chip truncate tone="toned" tint="var(--success)">active</Chip>
        : o.status === "aging"
          ? <Chip truncate tone="toned" tint="var(--warning)">aging</Chip>
          : <Chip truncate>expired</Chip>,
  },
  {
    key: "first_seen_at", label: "First Seen", width: 110, minWidth: 90, hideable: true, defaultHidden: true,
    serverSort: true,
    render: (o) => <DateCell value={o.first_seen_at} />,
  },
  {
    key: "last_seen_at", label: "Last Seen", width: 110, minWidth: 90,
    serverSort: true,
    render: (o) => <DateCell value={o.last_seen_at} />,
  },
];

const CWE_ABSTRACTION_CHOICES = [
  { value: "all", label: "Any" },
  ...["Pillar", "Class", "Base", "Variant", "Compound"].map((v) => ({ value: v, label: v })),
];

const CWE_USAGE_CHOICES = [
  { value: "all", label: "Any" },
  ...["Allowed", "Allowed-with-Review", "Discouraged", "Prohibited"].map((v) => ({ value: v, label: v })),
];

const CWE_COLUMNS: ColumnDef<CWEResponse>[] = [
  {
    key: "cwe_id", label: "ID", width: 110, minWidth: 90,
    serverSort: true, serverText: true, serverParam: "search",
    render: (c) => (
      <span className={styles.entityName}>
        {c.cwe_id}
        {c.kind === "category" && <span className={styles.subtechIndicator}> (cat)</span>}
      </span>
    ),
  },
  {
    key: "name", label: "Name", width: 300, minWidth: 160, flex: true,
    serverSort: true, textValue: (c) => c.name,
    render: (c) => (
      <span className={`${styles.entityMeta} ${table.ellipsis}`} title={c.name}>
        {c.name}
        {c.is_deprecated && <span className={styles.subtechIndicator}> (retired)</span>}
      </span>
    ),
  },
  {
    key: "abstraction", label: "Abstraction", width: 120, minWidth: 90, hideable: true,
    serverSort: true, serverChoice: true, serverParam: "abstraction", choices: CWE_ABSTRACTION_CHOICES,
    render: (c) => <Chip truncate>{c.abstraction || "-"}</Chip>,
  },
  {
    // The headline number: NVD tags a CVE wherever the analyst chose on the
    // ladder, so a Class or Pillar's direct count reads as near-zero until the
    // subtree is folded in.
    key: "cve_count_rolled", label: "CVEs", width: 90, minWidth: 70,
    serverSort: true, numValue: (c) => c.cve_count_rolled ?? c.cve_count,
    render: (c) => (
      <NumCell value={c.cve_count_rolled ?? c.cve_count} tone="cve" />
    ),
  },
  {
    key: "cve_count", label: "Direct", width: 84, minWidth: 64, hideable: true, defaultHidden: true,
    serverSort: true, numValue: (c) => c.cve_count,
    render: (c) => <NumCell value={c.cve_count} />,
  },
  {
    // Rolled, to match the CVEs column: a rolled CVE count beside a direct KEV
    // count reads as a near-zero exploitation rate on exactly the Class and
    // Pillar rows where the rollup is the point.
    key: "kev_count_rolled", label: "KEV", width: 78, minWidth: 60, hideable: true,
    serverSort: true, numValue: (c) => c.kev_count_rolled ?? c.kev_count,
    render: (c) => <NumCell value={c.kev_count_rolled ?? c.kev_count} tone="critical" />,
  },
  {
    key: "kev_count", label: "KEV direct", width: 90, minWidth: 70, hideable: true, defaultHidden: true,
    serverSort: true, numValue: (c) => c.kev_count,
    render: (c) => <NumCell value={c.kev_count} />,
  },
  {
    key: "article_count", label: "Articles", width: 80, minWidth: 64, hideable: true,
    serverSort: true, numValue: (c) => c.article_count ?? 0,
    render: (c) => <ArticleCount count={c.article_count} />,
  },
  {
    // MITRE's own verdict on whether a CVE should carry this id. Anything other
    // than Allowed means the tagging is imprecise, and roughly a sixth of the
    // corpus's links are.
    key: "mapping_usage", label: "Mapping", width: 150, minWidth: 100, hideable: true,
    serverSort: true, serverChoice: true, serverParam: "mapping_usage", choices: CWE_USAGE_CHOICES,
    render: (c) =>
      c.mapping_usage
        ? (
          <Chip
            truncate
            tone={c.mapping_usage === "Allowed" ? "default" : "toned"}
            tint={c.mapping_usage === "Allowed" ? undefined : "var(--warning)"}
            title={
              c.mapping_usage === "Allowed"
                ? "MITRE accepts this id as a CVE mapping target"
                : `MITRE mapping guidance: ${c.mapping_usage} — tagging a CVE with this id is imprecise`
            }
          >
            {c.mapping_usage}
          </Chip>
        )
        : <span className={table.zero}>·</span>,
  },
  {
    // Derived through cve_affected, so it's blank where the CPE strings never
    // resolved — which is most of the long tail, not a bug.
    key: "top_vendor", label: "Top vendor", width: 150, minWidth: 110, hideable: true,
    textValue: (c) => c.top_vendor ?? "",
    render: (c) =>
      c.top_vendor ? (
        <span className={table.ellipsis}>
          <Chip truncate tone="toned" tint="var(--entity-vendor)">{c.top_vendor}</Chip>
          <span className={styles.entityMeta}> {c.top_vendor_count}</span>
        </span>
      ) : (
        <span className={table.zero}>·</span>
      ),
  },
  {
    key: "parent_cwe_id", label: "Parent", width: 110, minWidth: 90, hideable: true, defaultHidden: true,
    serverSort: true, textValue: (c) => c.parent_cwe_id ?? "",
    render: (c) => <MetaCell value={c.parent_cwe_id} />,
  },
  {
    key: "likelihood_of_exploit", label: "Likelihood", width: 110, minWidth: 90, hideable: true, defaultHidden: true,
    textValue: (c) => c.likelihood_of_exploit ?? "",
    render: (c) => <MetaCell value={c.likelihood_of_exploit} />,
  },
  {
    key: "status", label: "Status", width: 110, minWidth: 80, hideable: true, defaultHidden: true,
    textValue: (c) => c.status ?? "",
    render: (c) => <MetaCell value={c.status} />,
  },
  {
    key: "last_seen_at", label: "Last Seen", width: 120, minWidth: 90, hideable: true, defaultHidden: true,
    serverSort: true,
    render: (c) => <DateCell value={c.last_seen_at} />,
  },
];

function ObservableCandidatesQueue() {
  const { data: candidates, isLoading } = useObservableCandidates(true);
  const promote = usePromoteObservable();
  const dismissCandidate = useDismissObservableCandidate();
  const neverCapture = useNeverCaptureObservable();
  const isAdmin = useAuthStore((s) => s.user?.role === "admin");
  const [handled, setHandled] = useState<Set<string>>(new Set());
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [bulkBusy, setBulkBusy] = useState(false);

  const keyOf = (c: ObservableCandidateRow) => `${c.kind}:${c.value}`;
  const rows = (candidates ?? []).filter((c) => !handled.has(keyOf(c)));
  const markHandled = (c: ObservableCandidateRow) => {
    setHandled((prev) => new Set(prev).add(keyOf(c)));
    setChecked((prev) => {
      const next = new Set(prev);
      next.delete(keyOf(c));
      return next;
    });
  };
  const toggleChecked = (c: ObservableCandidateRow) =>
    setChecked((prev) => {
      const next = new Set(prev);
      const k = keyOf(c);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });
  const allChecked = rows.length > 0 && checked.size === rows.length;
  const selectedRows = rows.filter((c) => checked.has(keyOf(c)));

  const runBulk = async (
    action: (c: ObservableCandidateRow) => Promise<unknown>,
    doneWord: string,
  ) => {
    if (!selectedRows.length) return;
    setBulkBusy(true);
    let ok = 0;
    for (const c of selectedRows) {
      try {
        await action(c);
        markHandled(c);
        ok += 1;
      } catch {
        /* row stays; per-hook onError already toasts */
      }
    }
    setBulkBusy(false);
    if (ok) toast.success(`${doneWord} ${ok} candidate${ok === 1 ? "" : "s"}`);
  };

  return (
    <div className={styles.candQueue}>
      <div className={styles.candQueueHead}>
        Candidates · {rows.length} — pattern nominations no judgment door has confirmed. Promote turns one into a
        ledger row; dismiss drops it from its latest article; never-capture (admin) tombstones it everywhere.
      </div>
      {rows.length > 0 && (
        <div className={styles.candBulkBar}>
          <label className={styles.candBulkAll}>
            <input
              type="checkbox"
              checked={allChecked}
              onChange={() => setChecked(allChecked ? new Set() : new Set(rows.map(keyOf)))}
            />
            {checked.size ? `${checked.size} selected` : "select all"}
          </label>
          <button
            className={styles.candPromote}
            disabled={bulkBusy || !selectedRows.length}
            onClick={() =>
              runBulk(
                (c) =>
                  promote.mutateAsync({
                    entryId: c.latest_entry_id!,
                    kind: c.kind,
                    value: c.value,
                    surfaceForm: c.sample_surface ?? undefined,
                  }),
                "Promoted",
              )
            }
          >
            promote selected
          </button>
          <button
            className={styles.candPromote}
            disabled={bulkBusy || !selectedRows.length}
            onClick={() =>
              runBulk(
                (c) => dismissCandidate.mutateAsync({ entryId: c.latest_entry_id!, kind: c.kind, value: c.value }),
                "Dismissed",
              )
            }
            title="Entry-local: drops each candidate from its latest article"
          >
            dismiss selected
          </button>
          {isAdmin && (
            <button
              className={styles.candNever}
              disabled={bulkBusy || !selectedRows.length}
              onClick={async () => {
                if (
                  !(await confirmDialog({
                    title: "Tombstone values",
                    message: `Tombstone ${selectedRows.length} value${selectedRows.length === 1 ? "" : "s"}? No door will capture them again.`,
                    confirmLabel: "Tombstone",
                    destructive: true,
                  }))
                )
                  return;
                void runBulk((c) => neverCapture.mutateAsync({ kind: c.kind, value: c.value }), "Tombstoned");
              }}
            >
              never selected
            </button>
          )}
        </div>
      )}
      {isLoading && <div className={styles.candQueueEmpty}>Loading…</div>}
      {!isLoading && rows.length === 0 && (
        <div className={styles.candQueueEmpty}>Queue is clear — nothing nominated and unjudged.</div>
      )}
      {rows.map((c) => (
        <div key={keyOf(c)} className={styles.candRow}>
          <input
            type="checkbox"
            checked={checked.has(keyOf(c))}
            onChange={() => toggleChecked(c)}
            aria-label={`Select ${c.value}`}
          />
          <Chip tone="toned" tint="var(--entity-ioc)">{c.kind}</Chip>
          <span
            className={styles.candValue}
            title={c.sample_surface && c.sample_surface !== c.value ? `${c.value} — seen as ${c.sample_surface}` : c.value}
          >
            {c.value}
          </span>
          {c.was_defanged && (
            <span className={styles.candMark} title="Author defanged it — strong indicator signal">defanged</span>
          )}
          <span className={styles.candMeta}>
            {c.entry_count} article{c.entry_count === 1 ? "" : "s"}
            {c.latest_entry_title ? ` · ${c.latest_entry_title.slice(0, 48)}` : ""}
          </span>
          <button
            className={styles.candPromote}
            disabled={promote.isPending || !c.latest_entry_id}
            onClick={() =>
              promote.mutate(
                {
                  entryId: c.latest_entry_id!,
                  kind: c.kind,
                  value: c.value,
                  surfaceForm: c.sample_surface ?? undefined,
                },
                { onSuccess: () => markHandled(c) },
              )
            }
          >
            promote
          </button>
          <button
            className={styles.candPromote}
            disabled={dismissCandidate.isPending || !c.latest_entry_id}
            onClick={() =>
              dismissCandidate.mutate(
                { entryId: c.latest_entry_id!, kind: c.kind, value: c.value },
                { onSuccess: () => markHandled(c) },
              )
            }
            title={
              c.entry_count > 1
                ? `Drops it from the latest article; it still rides ${c.entry_count - 1} other${c.entry_count === 2 ? "" : "s"}`
                : "Drops it from its article"
            }
          >
            dismiss
          </button>
          {isAdmin && (
            <button
              className={styles.candNever}
              disabled={neverCapture.isPending}
              onClick={() =>
                neverCapture.mutate({ kind: c.kind, value: c.value }, { onSuccess: () => markHandled(c) })
              }
              title="Tombstone: never capture or export this value"
            >
              never
            </button>
          )}
        </div>
      ))}
    </div>
  );
}

function ObservablesSection() {
  // ?queue=1 deep-links straight into the candidates queue (the Engine
  // console's attention chip lands here).
  const [searchParams] = useSearchParams();
  const [queueOpen, setQueueOpen] = useState(searchParams.get("queue") === "1");
  const { data: queueRows } = useObservableCandidates(true);

  return (
    <>
      {queueOpen && <ObservableCandidatesQueue />}
      <EntityTableSection<ObservableResponse>
        title="Observables"
        entityType="observable"
        columns={OBSERVABLE_COLUMNS}
        queryKey="observables"
        endpoint="/observables"
        defaultSort={{ key: "last_seen_at", dir: "desc" }}
        emptyTitle="No observables yet"
        emptyDesc="Ledger rows come from judgment: the one-pass analysis, curated ioc_list feeds, TTP observables, or promoting a candidate from an article's intel panel. Run scripts/maintenance/backfill_observables.py to fill from existing extractions."
        getId={(o) => o.id}
        getLabel={(o) => o.label || o.value}
        noun="observable"
        nounPlural="observables"
        filters={
          <button
            className={`${styles.candToggle} ${queueOpen ? styles.candToggleOn : ""}`}
            onClick={() => setQueueOpen(!queueOpen)}
          >
            Candidates{queueRows?.length ? ` · ${queueRows.length}` : ""}
          </button>
        }
      />
    </>
  );
}

function CWEsSection() {
  return (
    <EntityTableSection<CWEResponse>
      title="Weaknesses"
      entityType="cwe"
      columns={CWE_COLUMNS}
      queryKey="cwes"
      endpoint="/cwes"
      defaultSort={{ key: "cve_count_rolled", dir: "desc" }}
      emptyTitle="No weakness catalog"
      emptyDesc="Run scripts/seed/seed_cwe_catalog.py to load the MITRE CWE catalog."
      getId={(c) => c.id}
      getLabel={(c) => `${c.cwe_id} ${c.name}`}
      noun="weakness"
      nounPlural="weaknesses"
    />
  );
}

function TTPsSection() {
  return (
    <EntityTableSection<TTP>
      title="TTPs"
      entityType="ttp"
      columns={TTP_COLUMNS}
      queryKey="ttps"
      endpoint="/ttps"
      defaultSort={{ key: "technique_id", dir: "asc" }}
      emptyTitle="No TTPs extracted"
      emptyDesc="TTPs are extracted from articles using AI analysis."
      getId={(t) => t.id}
      getLabel={(t) => t.technique_id || t.technique_name}
      noun="technique"
    />
  );
}

function CountriesSection() {
  return (
    <EntityTableSection<Country>
      title="Countries"
      entityType="country"
      columns={COUNTRY_COLUMNS}
      queryKey="countries"
      endpoint="/countries"
      defaultSort={{ key: "name", dir: "asc" }}
      emptyTitle="No countries yet"
      emptyDesc="Run the seed script or extract intelligence from articles to populate countries."
      getId={(c) => c.id}
      getLabel={(c) => c.name}
      noun="country"
      nounPlural="countries"
      filters={<FindDuplicatesButton entityType="country" />}
    />
  );
}

function SectorsSection() {
  return (
    <EntityTableSection<Sector>
      title="Sectors"
      entityType="sector"
      columns={SECTOR_COLUMNS}
      queryKey="sectors"
      endpoint="/sectors"
      defaultSort={{ key: "article_count", dir: "desc" }}
      emptyTitle="No sectors yet"
      emptyDesc="Sectors are a seeded vocabulary — run scripts/seed/seed_sectors.py to populate them."
      getId={(s) => s.id}
      getLabel={(s) => s.name}
      noun="sector"
      nounPlural="sectors"
    />
  );
}

function MitigationsSection() {
  return (
    <EntityTableSection<Mitigation>
      title="Mitigations"
      entityType="mitigation"
      columns={MITIGATION_COLUMNS}
      queryKey="mitigations"
      endpoint="/mitigations"
      defaultSort={{ key: "name", dir: "asc" }}
      emptyTitle="No mitigations extracted yet"
      emptyDesc="Extract intelligence from articles to populate mitigations (M-IDs and hardening recommendations)."
      getId={(m) => m.id}
      getLabel={(m) => m.name}
      noun="mitigation"
    />
  );
}

function ToolsSection() {
  return (
    <EntityTableSection<OffensiveTool>
      title="Tools"
      entityType="tool"
      columns={TOOL_COLUMNS}
      queryKey="tools"
      endpoint="/tools"
      defaultSort={{ key: "name", dir: "asc" }}
      emptyTitle="No tools extracted yet"
      emptyDesc="Extract intelligence from articles to identify tools (Cobalt Strike, Mimikatz, AnyDesk, etc.)."
      getId={(t) => t.id}
      getLabel={(t) => t.name}
      noun="tool"
      filters={<FindDuplicatesButton entityType="tool" />}
    />
  );
}

function VendorsSection() {
  return (
    <EntityTableSection<Vendor>
      title="Vendors"
      entityType="vendor"
      columns={VENDOR_COLUMNS}
      queryKey="vendors"
      endpoint="/vendors"
      defaultSort={{ key: "name", dir: "asc" }}
      emptyTitle="No vendors yet"
      emptyDesc="Extract intelligence from articles to identify software and hardware vendors."
      getId={(v) => v.id}
      getLabel={(v) => v.name}
      noun="vendor"
      filters={<FindDuplicatesButton entityType="vendor" />}
    />
  );
}

function ProductsSection() {
  return (
    <EntityTableSection<Product>
      title="Products"
      entityType="product"
      columns={PRODUCT_COLUMNS}
      queryKey="products"
      endpoint="/products"
      defaultSort={{ key: "name", dir: "asc" }}
      emptyTitle="No products yet"
      emptyDesc="Extract intelligence from articles to identify software and hardware products."
      getId={(p) => p.id}
      getLabel={(p) => p.name}
      noun="product"
      filters={<FindDuplicatesButton entityType="product" />}
    />
  );
}

// --- Detection Rules ---
// Compact per-format label for the rule row badge.
const RULE_FORMAT_LABELS: Record<string, string> = {
  sigma: "sigma", splunk_spl: "spl", kql: "kql", elastic_ql: "eql",
  crowdstrike_ql: "cql", snort_suricata: "snort", yara: "yara",
  nuclei: "nuclei", panther: "panther",
};

type RuleLens = "flat" | "technique" | "repo" | "product";
/** Which indexed attributes the library's search box looks at. */
type RuleSearchScope = "both" | "metadata" | "content";
/** One-click selections over the rail's Telemetry group. */
type RuleTelemetryFilter = "any" | "covered" | "missing";

// Saved research views — client presets that set filter/sort state.
const RULE_SAVED_VIEWS: { key: string; label: string }[] = [
  { key: "all", label: "All rules" },
  { key: "new_week", label: "New this week" },
  { key: "updated_upstream", label: "Recently updated upstream" },
  { key: "my_drafts", label: "My drafts" },
];

function ruleTechniques(rule: DetectionRuleListItem): string[] {
  const out: string[] = [];
  for (const t of rule.source_ttps || []) {
    if (typeof t === "string") out.push(t);
    else if (t && typeof t === "object") {
      const v = (t as Record<string, unknown>).technique_id ?? (t as Record<string, unknown>).id;
      if (v) out.push(String(v));
    }
  }
  return [...new Set(out)];
}
function ruleCve(rule: DetectionRuleListItem): string | null {
  const c = rule.source_cves?.[0];
  if (!c) return null;
  if (typeof c === "string") return c;
  if (typeof c === "object") {
    const v = (c as Record<string, unknown>).cve_id ?? (c as Record<string, unknown>).id;
    return v ? String(v) : null;
  }
  return null;
}
function ruleProducts(rule: DetectionRuleListItem): string[] {
  return (rule.source_products || []).filter((p): p is string => typeof p === "string");
}
function isRecent(iso: string | null): boolean {
  return !!iso && Date.now() - new Date(iso).getTime() < 7 * 24 * 3600 * 1000;
}
/** A rule's required telemetry, missing sources first so a truncated row still
 *  shows the one that blocks it. */
function telemetrySources(tel: { required: string[]; missing: string[] }): { name: string; have: boolean }[] {
  const missing = new Set(tel.missing);
  return tel.required
    .map((name) => ({ name, have: !missing.has(name) }))
    .sort((a, b) => Number(a.have) - Number(b.have));
}
function telColor(p: number): string {
  return p >= 0.8 ? "var(--success)" : p >= 0.5 ? "var(--warning)" : "var(--danger)";
}
// Always-short relative age so the Added column never overflows (e.g. 12h, 3d, 8mo, 1y).
function shortAge(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime();
  const min = ms / 60000;
  if (min < 1) return "now";
  if (min < 60) return `${Math.round(min)}m`;
  const hr = min / 60;
  if (hr < 24) return `${Math.round(hr)}h`;
  const day = hr / 24;
  if (day < 7) return `${Math.round(day)}d`;
  if (day < 31) return `${Math.round(day / 7)}w`;
  if (day < 365) return `${Math.round(day / 30)}mo`;
  return `${Math.round(day / 365)}y`;
}

function RulesSection() {
  const [searchParams, setSearchParams] = useSearchParams();
  // Bulk delete hits an admin-only endpoint.
  const isAdmin = useAuthStore((s) => s.user?.role === "admin");
  const ruleFacetsCollapsed = useUIStore((s) => s.ruleFacetsCollapsed);
  const setRuleFacetsCollapsed = useUIStore((s) => s.setRuleFacetsCollapsed);
  const facetRailWidth = useRailWidth("rule-facets", { default: 210, min: 170, max: 420 });
  // Seeded from the persisted snapshot so opening a rule and coming back
  // restores the list, rather than resetting to "all rules, no filters".
  const saved = useRef(useIntelStore.getState().ruleLibrary).current;
  const [draftFilter, setDraftFilter] = useState<boolean | undefined>(saved.draftFilter);
  // One map keyed by the index attribute rather than ten scalars: every group is
  // multi-select now, and the keys are the same names the endpoint takes.
  const [facetSel, setFacetSel] = useState<Record<string, string[]>>(saved.facetSel);
  const toggleFacet = useCallback((key: string, value: string) => {
    setFacetSel((prev) => {
      const cur = prev[key] ?? [];
      const next = cur.includes(value) ? cur.filter((v) => v !== value) : [...cur, value];
      const out = { ...prev };
      if (next.length) out[key] = next;
      else delete out[key];
      return out;
    });
  }, []);
  const [authoredLocal, setAuthoredLocal] = useState<boolean | undefined>(saved.authoredLocal);
  const [createdAfter, setCreatedAfter] = useState<string | undefined>(saved.createdAfter);
  const [activeView, setActiveView] = useState(saved.activeView);
  const [lens, setLens] = useState<RuleLens>(saved.lens);
  // Which attributes the box searches. Content is indexed after the metadata
  // fields, so "both" still ranks a title match above a body match.
  const [searchScope, setSearchScope] = useState<RuleSearchScope>(saved.scope);
  // Which rail values the enabled telemetry inventory answers. The match is
  // tiered and fuzzy, so only the server can say — see the endpoint.
  const { data: telemetryVocab } = useRuleTelemetryVocabulary();
  // ?rules_q= deep link (entity profile "Search library" CTA) seeds the search box.
  // A ?rules_q= deep link is an explicit request and outranks the snapshot.
  const [search, setSearch] = useState(() => searchParams.get("rules_q") || saved.search);
  const [debouncedSearch, setDebouncedSearch] = useState(search.trim());
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [showImport, setShowImport] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);
  const [actionsOpen, setActionsOpen] = useState(false);
  const isMobile = useIsMobile();
  const [sort, toggleSort, setSort] = useSort(saved.sortField, saved.sortOrder);
  const sentinelRef = useRef<HTMLDivElement>(null);
  const RULES_PAGE_SIZE = 100;


  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(search.trim()), 300);
    return () => clearTimeout(timer);
  }, [search]);

  // Consume the ?rules_q= param on mount so it doesn't linger
  useEffect(() => {
    if (searchParams.get("rules_q")) {
      const next = new URLSearchParams(searchParams);
      next.delete("rules_q");
      setSearchParams(next, { replace: true });
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const applyView = (key: string) => {
    setActiveView(key);
    // reset the facet filters a view owns, then apply the preset
    setCreatedAfter(undefined);
    setAuthoredLocal(undefined);
    setDraftFilter(undefined);
    if (key === "new_week") {
      const since = new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString();
      setCreatedAfter(since);
      setSort("created_at", "desc");
    } else if (key === "updated_upstream") {
      setSort("upstream_updated_at", "desc");
    } else if (key === "my_drafts") {
      setAuthoredLocal(true);
      setDraftFilter(true);
      setSort("created_at", "desc");
    } else {
      setSort("created_at", "desc");
    }
  };

  // Write the filter set back on every change so it survives the unmount that
  // navigating to a rule causes. One effect rather than a setter on each
  // control, so no control can be added later and silently not persist.
  useEffect(() => {
    useIntelStore.getState().setRuleLibrary({
      search,
      scope: searchScope,
      facetSel,
      lens,
      activeView,
      draftFilter,
      authoredLocal,
      createdAfter,
      sortField: sort.field,
      sortOrder: sort.order,
    });
  }, [search, searchScope, facetSel, lens, activeView, draftFilter, authoredLocal, createdAfter, sort]);

  const extraParams = {
    rule_type: facetSel.rule_type,
    is_draft: draftFilter,
    source_repo: facetSel.source_repo,
    tactic: facetSel.mitre_tactics,
    product: facetSel.products,
    vendor: facetSel.vendors,
    tool: facetSel.tools,
    severity: facetSel.severity,
    telemetry_token: facetSel.telemetry_tokens,
    license: facetSel.license,
    actor: facetSel.actors,
    malware: facetSel.malware,
    technique: facetSel.techniques,
    tag: facetSel.tags,
    authored_local: authoredLocal,
    created_after: createdAfter,
    q: debouncedSearch || undefined,
    scope: debouncedSearch ? searchScope : undefined,
    // A text query has relevance to rank by; without one, fall back to the
    // column the sort header is on.
    sort_by: debouncedSearch ? "relevance" : sort.field,
    sort_order: sort.order,
  };
  // Rows and facet counts arrive together from Meilisearch, so the rail narrows
  // with the list instead of showing library-wide totals.
  const { data: infiniteData, isLoading, fetchNextPage, hasNextPage, isFetchingNextPage } = useInfiniteQuery({
    queryKey: ["detection-rule-search", extraParams],
    queryFn: async ({ pageParam = 0 }) => {
      const { data } = await api.get<RuleSearchResponse>("/detection-rules/search", {
        params: { limit: RULES_PAGE_SIZE, offset: pageParam, ...extraParams },
        // repeat array params as ?rule_type=sigma&rule_type=yara
        paramsSerializer: { indexes: null },
      });
      return data;
    },
    initialPageParam: 0,
    getNextPageParam: (lastPage) => lastPage.has_more ? lastPage.offset + lastPage.limit : undefined,
  });
  const items = infiniteData?.pages.flatMap((p) => p.items) ?? [];
  const total = infiniteData?.pages[0]?.total ?? 0;
  const facets = infiniteData?.pages[0]?.facets;
  const navigate = useNavigate();

  const bulkUpdate = useBulkUpdateRules();
  const bulkDelete = useBulkDeleteRules();
  const undoableDelete = useUndoableDelete();
  const importRules = useImportRules();
  const exportRules = useExportRules();

  // IntersectionObserver to trigger loading more when sentinel is visible.
  // The rows scroll inside the .main column, so the observer root must be that
  // container (not the viewport) or the sentinel never intersects and paging stalls.
  useEffect(() => {
    const el = sentinelRef.current;
    if (!el) return;
    const root = el.closest(`.${lib.main}`) as HTMLElement | null;
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting && hasNextPage && !isFetchingNextPage) {
          fetchNextPage();
        }
      },
      { root, rootMargin: "300px" }
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [hasNextPage, isFetchingNextPage, fetchNextPage]);

  const handleNewRule = () => {
    navigate("/workbench/rule/new");
  };

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (!items.length) return;
    if (selectedIds.size === items.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(items.map((r) => r.id)));
    }
  };

  const handleBulkAction = (action: "publish" | "unpublish" | "delete") => {
    const ids = Array.from(selectedIds);
    if (!ids.length) return;
    if (action === "delete") {
      undoableDelete({
        label: `${ids.length} detection rule(s)`,
        key: `bulk-rules-${ids.join(",")}`,
        onDelete: () => bulkDelete.mutate(ids, { onSuccess: () => setSelectedIds(new Set()) }),
      });
      return;
    } else {
      bulkUpdate.mutate(
        { rule_ids: ids, is_draft: action === "unpublish" },
        { onSuccess: () => setSelectedIds(new Set()) }
      );
    }
  };

  const handleImportFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    importRules.mutate(file, {
      onSuccess: (result) => {
        setShowImport(false);
        void alertDialog({
          title: "Import finished",
          message: `Imported: ${result.imported}, Skipped: ${result.skipped}${result.errors.length ? `\n\nErrors:\n${result.errors.map((e: { file: string; error: string }) => `${e.file}: ${e.error}`).join("\n")}` : ""}`,
        });
      },
    });
  };

  const anyFacet = Object.keys(facetSel).length > 0;
  const clearFacets = () => setFacetSel({});

  // The Telemetry switch is a bulk-select over the rail's Telemetry group, not a
  // filter of its own: clicking it ticks the boxes, and the boxes do the
  // filtering. So the list can never disagree with what the rail shows, and any
  // tick stays adjustable afterwards.
  const telemetrySel = facetSel.telemetry_tokens ?? [];
  const sameSet = (a: string[], b: string[] | undefined) =>
    !!b && b.length > 0 && a.length === b.length && new Set(a).size === new Set([...a, ...b]).size;
  // "" when the ticks are a hand-edited subset: no segment lights up rather than
  // one claiming a preset that is no longer what's selected.
  const telemetryPreset: RuleTelemetryFilter | "" = !telemetrySel.length
    ? "any"
    : sameSet(telemetrySel, telemetryVocab?.collected)
      ? "covered"
      : sameSet(telemetrySel, telemetryVocab?.missing)
        ? "missing"
        : "";
  const applyTelemetryPreset = (preset: RuleTelemetryFilter) => {
    const values =
      preset === "covered" ? telemetryVocab?.collected : preset === "missing" ? telemetryVocab?.missing : [];
    setFacetSel((prev) => {
      const next = { ...prev };
      if (values?.length) next.telemetry_tokens = values;
      else delete next.telemetry_tokens;
      return next;
    });
  };

  // Client-side regroup of the loaded rows (the "lens").
  const groups: [string, DetectionRuleListItem[]][] | null = (() => {
    if (lens === "flat") return null;
    const m = new Map<string, DetectionRuleListItem[]>();
    for (const rule of items) {
      let keys: string[] = [];
      if (lens === "technique") keys = ruleTechniques(rule);
      else if (lens === "repo") keys = [rule.is_authored_local ? "Authored here" : rule.source_repo || "—"];
      else if (lens === "product") keys = ruleProducts(rule);
      if (!keys.length) keys = ["(none)"];
      for (const k of keys) {
        if (!m.has(k)) m.set(k, []);
        m.get(k)!.push(rule);
      }
    }
    return Array.from(m.entries()).sort((a, b) => b[1].length - a[1].length);
  })();

  const severityColor = (s: string | null): string | undefined =>
    s === "critical" ? "#ff7b72" : s === "high" ? "#ffa657" : s === "medium" ? "var(--warning)" : undefined;
  const stripeColor = (s: string | null): string =>
    s === "critical" ? "#ff7b72" : s === "high" ? "#ffa657" : s === "medium" ? "var(--warning)" : s === "low" ? "#6e7681" : "transparent";

  const renderRuleRow = (rule: DetectionRuleListItem) => {
    const techs = ruleTechniques(rule);
    const cve = ruleCve(rule);
    const go = () => navigate(`/workbench/rule/${rule.id}`);
    return (
      <tr key={rule.id}>
        <td className={lib.sevStripe} style={{ background: stripeColor(rule.severity) }} />
        <td className={styles.checkboxCol} onClick={(e) => e.stopPropagation()}>
          <input type="checkbox" checked={selectedIds.has(rule.id)} onChange={() => toggleSelect(rule.id)} />
        </td>
        <td className={lib.cRule} onClick={go}>
          <div className={lib.ruleCell}>
            <span className={lib.ruleTitle}>{rule.title}</span>
            <span className={lib.ruleMeta}>
              <span className={`${lib.fmt} ${lib[`fmt_${rule.rule_type}`] || ""}`}>{RULE_FORMAT_LABELS[rule.rule_type] || rule.rule_type}</span>
              {rule.severity && <span style={{ color: severityColor(rule.severity) }}>{rule.severity}</span>}
              {cve && <span className={lib.rid}>{cve}</span>}
              {rule.linked_entry_count > 0 && (
                <span className={lib.linkInline}>{rule.linked_entry_count} {rule.linked_entry_count === 1 ? "entry" : "entries"}</span>
              )}
            </span>
          </div>
        </td>
        <td className={lib.cSource} onClick={go}>
          {rule.is_authored_local ? (
            <span className={lib.authoredLocal}>✎ authored here</span>
          ) : (
            <div className={lib.source}>
              <span className={lib.sourceRepo}>
                <svg className={lib.gh} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.76-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
                <span className={lib.repoName}>{rule.source_repo || "—"}</span>
              </span>
              {(rule.source_author || rule.license) && (
                <span className={lib.sourceAuthor}>
                  {rule.source_author}
                  {rule.license && <span className={lib.license}>{rule.license}</span>}
                </span>
              )}
            </div>
          )}
        </td>
        <td className={lib.cAttck} onClick={go}>
          <div className={lib.attck}>
            {techs.slice(0, 3).map((t) => <span key={t} className={lib.tech}>{t}</span>)}
            {techs.length > 3 && <span className={`${lib.tech} ${lib.techMore}`}>+{techs.length - 3}</span>}
          </div>
        </td>
        <td className={lib.cTel} onClick={go}>
          {rule.telemetry && rule.telemetry.coverage_pct !== null ? (
            <span
              className={lib.telemetry}
              title={`Required: ${rule.telemetry.required.join(", ")}${rule.telemetry.missing.length ? ` — missing ${rule.telemetry.missing.join(", ")}` : ""}`}
            >
              <span
                className={lib.telRing}
                style={{ "--p": Math.round(rule.telemetry.coverage_pct * 100), "--c": telColor(rule.telemetry.coverage_pct) } as React.CSSProperties}
              />
              {/* The ring already says how much is covered, so the text says
                  *what* instead of repeating the ratio. Every source is listed
                  — a "+2" in this column hides exactly the thing the column
                  exists to answer. Gaps sort first so they lead the cell. */}
              <span className={lib.telSources}>
                {telemetrySources(rule.telemetry).map(({ name, have }) => (
                  <span key={name} className={`${lib.ds} ${have ? lib.dsHave : lib.dsMissing}`} title={name}>
                    {name}
                  </span>
                ))}
              </span>
            </span>
          ) : (
            <span className={`${lib.telemetry} ${lib.telemetryNone}`}>—</span>
          )}
        </td>
        <td className={lib.cAdded} onClick={go}>
          <span className={`${lib.added} ${isRecent(rule.created_at) ? lib.addedNew : ""}`} title={formatDate(rule.created_at)}>{shortAge(rule.created_at)}</span>
        </td>
      </tr>
    );
  };

  /** Bind one facet group to the selection map. `cap`/`searchable` mirror the
   *  search rail: wide groups (techniques, tags, actors) get a filter box and a
   *  fold rather than being cut off at eight with no way to reach the rest. */
  const facetGroup = (
    label: string,
    key: string,
    buckets: FacetBucket[] | undefined,
    format?: (v: string) => string,
    titleAccessory?: React.ReactNode,
  ) => {
    const selected = facetSel[key] ?? [];
    const rows = (buckets ?? []).map((b) => ({
      value: b.value,
      label: format ? format(b.value) : b.value,
      count: b.count,
    }));
    // A value can drop out of the distribution once other facets narrow past it;
    // keep it listed so it stays untickable-from-the-rail.
    for (const v of selected) {
      if (!rows.some((r) => r.value === v)) rows.push({ value: v, label: format ? format(v) : v, count: 0 });
    }
    return (
      <FacetSection
        label={label}
        rows={rows}
        active={new Set(selected.map((v) => v.toLowerCase()))}
        onToggle={(value) => toggleFacet(key, value)}
        cap={8}
        searchable
        titleAccessory={titleAccessory}
      />
    );
  };

  const facetRail = (
    <>
      <aside
        className={`${lib.rail} ${ruleFacetsCollapsed ? lib.railCollapsed : ""}`}
        style={ruleFacetsCollapsed ? undefined : facetRailWidth.style}
      >
        <div className={lib.railGroup}>
          <div className={lib.railLabel}>Research Views</div>
          {RULE_SAVED_VIEWS.map((v) => (
            <button
              key={v.key}
              className={`${lib.savedView} ${activeView === v.key ? lib.savedViewActive : ""}`}
              onClick={() => applyView(v.key)}
            >
              {v.label}
            </button>
          ))}
        </div>
        {facetGroup("Rule format", "rule_type", facets?.rule_type, (v) => RULE_FORMAT_LABELS[v] || v)}
        {facetGroup("Severity", "severity", facets?.severity)}
        {facetGroup("Source repo", "source_repo", facets?.source_repo)}
        {facetGroup("ATT&CK tactic", "mitre_tactics", facets?.mitre_tactics, (v) => v.replace(/_/g, " "))}
        {facetGroup("Technique", "techniques", facets?.techniques)}
        {facetGroup("Threat actor", "actors", facets?.actors)}
        {facetGroup("Malware", "malware", facets?.malware)}
        {facetGroup("Tool", "tools", facets?.tools)}
        {facetGroup("Vendor", "vendors", facets?.vendors)}
        {facetGroup("Product", "products", facets?.products)}
        {facetGroup(
          "Telemetry",
          "telemetry_tokens",
          facets?.telemetry_tokens,
          undefined,
          // Same action as the header switch, at the group it fills — this is
          // where you look when you want to see or adjust what got ticked.
          telemetryVocab?.collected.length ? (
            <button
              className={lib.facetSelectMine}
              onClick={() => applyTelemetryPreset(telemetrySel.length ? "any" : "covered")}
              title={`${telemetrySel.length ? "Clear" : "Tick"} the ${telemetryVocab.collected.length} sources you collect`}
            >
              {telemetrySel.length ? "clear" : "select mine"}
            </button>
          ) : undefined,
        )}
        {facetGroup("Tags", "tags", facets?.tags)}
        {facetGroup("License", "license", facets?.license)}
        {anyFacet && (
          <div className={lib.railGroup}>
            <button className={lib.clearFacet} onClick={clearFacets}>× Clear facets</button>
          </div>
        )}
      </aside>

      {!ruleFacetsCollapsed && (
        <ResizeHandle
          label="rule filters"
          className={lib.railResizer}
          {...facetRailWidth.handleProps}
        />
      )}

      <RailToggle
        side="left"
        collapsed={ruleFacetsCollapsed}
        onToggle={() => setRuleFacetsCollapsed(!ruleFacetsCollapsed)}
        label="rule filters"
        verbs={["Show", "Hide"]}
        className={lib.railToggle}
      />
    </>
  );

  return (
    /* The facet rail is a full-height column: it sits beside the page header
       rather than under it, the same way the search page's rail does. */
    <div className={lib.shell}>
      {facetRail}
      <div className={lib.shellMain}>
      <PageHeader
        title="Rules Library"
        count={total}
        actions={
          // Four buttons wrap onto a second line on a phone and cost a third of
          // the screen, so all but the primary action fold behind ⋯ — the same
          // treatment the entity tables use.
          isMobile ? (
            <>
              <button className={`${styles.btn} ${styles.btnPrimary}`} onClick={handleNewRule}>+ New</button>
              <button
                className={styles.headerActionsBtn}
                onClick={() => setActionsOpen((v) => !v)}
                aria-label="Rules Library actions"
                aria-expanded={actionsOpen}
              >
                ⋯
              </button>
              {actionsOpen && (
                <>
                  <div className={styles.headerActionsBackdrop} onClick={() => setActionsOpen(false)} />
                  <div className={styles.headerActionsMenu}>
                    <button className={styles.btn} onClick={() => { setActionsOpen(false); setShowImport(true); }}>
                      Import
                    </button>
                    <button
                      className={styles.btn}
                      onClick={() => { setActionsOpen(false); exportRules.mutate({ format: "zip" }); }}
                    >
                      Export
                    </button>
                    <button
                      className={styles.btn}
                      onClick={() => { setActionsOpen(false); setShowGenerator((v) => !v); }}
                    >
                      {showGenerator ? "Hide Generator" : "Generate Rules"}
                    </button>
                  </div>
                </>
              )}
            </>
          ) : (
            <>
              <button className={styles.btn} onClick={() => setShowImport(true)}>Import</button>
              <button className={styles.btn} onClick={() => exportRules.mutate({ format: "zip" })}>Export</button>
              <button
                className={`${styles.btn} ${showGenerator ? styles.btnPrimary : ""}`}
                onClick={() => setShowGenerator((v) => !v)}
              >
                {showGenerator ? "Hide Generator" : "Generate Rules"}
              </button>
              <button className={`${styles.btn} ${styles.btnPrimary}`} onClick={handleNewRule}>+ New Rule</button>
            </>
          )
        }
        controls={
          <div className={lib.controlsRow}>
            {(
              <>
                <input
                  className={`${styles.searchInput} ${lib.ruleSearch}`}
                  placeholder="Search rules..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
                <Segmented<RuleSearchScope>
                  label="Search in"
                  size="sm"
                  className={lib.lensSegmented}
                  value={searchScope}
                  onChange={setSearchScope}
                  options={[
                    { value: "both", label: "All" },
                    { value: "metadata", label: "Metadata" },
                    { value: "content", label: "Rule body" },
                  ]}
                />
                <Segmented<RuleTelemetryFilter | "">
                  label="Telemetry"
                  size="sm"
                  className={lib.lensSegmented}
                  value={telemetryPreset}
                  onChange={(v) => v && applyTelemetryPreset(v)}
                  options={[
                    { value: "any", label: "All telemetry", title: "Clear the Telemetry group in the rail" },
                    {
                      value: "covered",
                      label: "My telemetry",
                      title: `Tick every source your Telemetry Sources inventory answers${
                        telemetryVocab ? ` (${telemetryVocab.collected.length})` : ""
                      }`,
                      disabled: !telemetryVocab?.collected.length,
                    },
                    {
                      value: "missing",
                      label: "Gaps",
                      title: `Tick every source you don't collect${
                        telemetryVocab ? ` (${telemetryVocab.missing.length})` : ""
                      }`,
                      disabled: !telemetryVocab?.missing.length,
                    },
                  ]}
                />
                <Segmented<RuleLens>
                  label="Group rules by"
                  size="sm"
                  className={lib.lensSegmented}
                  value={lens}
                  onChange={setLens}
                  options={[
                    { value: "flat", label: "Flat" },
                    { value: "technique", label: "Technique" },
                    { value: "repo", label: "Repo" },
                    { value: "product", label: "Product" },
                  ]}
                />
              </>
            )}
          </div>
        }
      />

      {selectedIds.size > 0 && (
        <div className={styles.bulkBar}>
          <span>{selectedIds.size} selected</span>
          <button onClick={() => handleBulkAction("publish")}>Publish</button>
          <button onClick={() => handleBulkAction("unpublish")}>Unpublish</button>
          <button onClick={() => exportRules.mutate({ rule_ids: Array.from(selectedIds), format: "zip" })}>Export</button>
          {isAdmin && (
            <button className={styles.bulkDelete} onClick={() => handleBulkAction("delete")}>Delete</button>
          )}
          <button onClick={() => setSelectedIds(new Set())}>Clear</button>
        </div>
      )}

      {showImport && (
        <div className={styles.importBar}>
          <span>Import SIGMA rules (.yml, .yaml, or .zip):</span>
          <input type="file" accept=".yml,.yaml,.zip" onChange={handleImportFile} />
          <button onClick={() => setShowImport(false)}>Cancel</button>
        </div>
      )}

      {showGenerator && (
        <div className={styles.generatorPanel}>
          <DetectionWorkbenchPage />
        </div>
      )}

      <div className={styles.contentBody} style={{ padding: 0, display: "flex", minHeight: 0 }}>
        {(
          <div className={lib.main}>
            {isLoading ? (
              <div className={styles.loading}><span className={styles.spinner} /> Loading...</div>
            ) : !items.length ? (
              <div className={styles.emptyState}>
                <div className={styles.emptyTitle}>
                  {debouncedSearch ? `No rules match "${debouncedSearch}"` : "No detection rules"}
                </div>
                <div className={styles.emptyDesc}>
                  {debouncedSearch
                    ? "Try a different search, or clear the facets in the sidebar."
                    : "Generate rules from articles using the AI detection workbench, or import existing rules."}
                </div>
              </div>
            ) : (
              <>
                <table className={`${styles.entityTable} ${lib.rulesTable}`}>
                  {/* The content columns are proportional, not fixed: with
                      pixel widths the one flexible column (Rule) absorbed every
                      spare pixel, so on a wide screen a short title sat in a
                      third of the row of empty space while Telemetry clipped its
                      names at 112px. */}
                  <colgroup>
                    <col style={{ width: 3 }} />
                    <col style={{ width: 30 }} />
                    <col />
                    <col style={{ width: "15%" }} />
                    <col style={{ width: "12%" }} />
                    <col style={{ width: "23%" }} />
                    <col style={{ width: 80 }} />
                  </colgroup>
                  <thead>
                    <tr>
                      <th className={lib.sevStripe} />
                      <th className={styles.checkboxCol}>
                        <input
                          type="checkbox"
                          checked={selectedIds.size === items.length && items.length > 0}
                          onChange={toggleSelectAll}
                        />
                      </th>
                      <SortableHeader field="title" label="Rule" sort={sort} onSort={toggleSort} />
                      <th>Source</th>
                      <th>ATT&CK</th>
                      <th>Telemetry</th>
                      <SortableHeader field="created_at" label="Added" sort={sort} onSort={toggleSort} />
                    </tr>
                  </thead>
                  <tbody>
                    {groups
                      ? groups.map(([name, rules]) => (
                          <Fragment key={name}>
                            <tr className={lib.groupRow}>
                              <td colSpan={7} className={lib.groupHeader}>
                                {name.replace(/_/g, " ")}<span className={lib.gcount}>{rules.length}</span>
                              </td>
                            </tr>
                            {rules.map(renderRuleRow)}
                          </Fragment>
                        ))
                      : items.map(renderRuleRow)}
                  </tbody>
                </table>
                <div ref={sentinelRef} />
                {isFetchingNextPage && (
                  <div className={styles.loading}>
                    <span className={styles.spinner} /> Loading more...
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>
      </div>
    </div>
  );
}

// --- Campaigns (embeds CampaignsPage) ---
function CampaignsSection() {
  return (
    <div className={styles.contentBody} style={{ padding: 0 }}>
      <CampaignsPage />
    </div>
  );
}

// --- Telemetry Sources ---

const CATEGORY_LABELS: Record<string, string> = {
  endpoint_edr: "Endpoint Detection & Response",
  windows_events: "Windows Event Logs",
  linux_macos: "Linux / macOS Logs",
  network_security: "Firewalls",
  ndr: "Network Detection & Response",
  ids_ips: "IDS / IPS",
  dns_security: "DNS Security",
  web_proxy: "Web Proxy / Secure Web Gateway",
  email: "Email Security",
  identity: "Identity & Access Management",
  cloud: "Cloud Platforms",
  saas: "SaaS / Collaboration",
  container: "Container & Kubernetes",
  siem: "SIEM / Security Analytics",
  vuln_management: "Vulnerability Management",
  waf_appsec: "WAF / Application Security",
  vpn_remote_access: "VPN & Remote Access",
  database: "Database Activity Monitoring",
  endpoint_mgmt: "Endpoint Management / Asset",
  dlp: "DLP / Data Security",
  threat_intel: "Threat Intelligence Platforms",
  physical_iot: "Physical Security / IoT",
};

function TelemetrySourcesSection() {
  // Catalog sync is admin-only; single-source CRUD stays open.
  const isAdmin = useAuthStore((s) => s.user?.role === "admin");
  const { data: catalog, isLoading: catalogLoading } = useTelemetryCatalog();
  const { data: existing, isLoading: existingLoading } = useTelemetrySources({ limit: 500, enabled: true });
  const syncMutation = useSyncTelemetrySources();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [initialized, setInitialized] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [dirty, setDirty] = useState(false);

  // Initialize selected set from existing enabled sources
  useEffect(() => {
    if (existing?.items && !initialized) {
      setSelected(new Set(existing.items.map((s) => s.name)));
      setInitialized(true);
    }
  }, [existing, initialized]);

  const isLoading = catalogLoading || existingLoading;

  const toggle = useCallback((name: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
    setDirty(true);
  }, []);

  const toggleCategory = useCallback((items: CatalogItem[]) => {
    setSelected((prev) => {
      const next = new Set(prev);
      const allChecked = items.every((i) => next.has(i.name));
      for (const i of items) {
        if (allChecked) next.delete(i.name);
        else next.add(i.name);
      }
      return next;
    });
    setDirty(true);
  }, []);

  const handleSave = useCallback(() => {
    syncMutation.mutate(Array.from(selected), {
      onSuccess: () => setDirty(false),
    });
  }, [selected, syncMutation]);

  // Group catalog by category
  const grouped = (catalog || []).reduce<Record<string, CatalogItem[]>>((acc, item) => {
    (acc[item.category] ??= []).push(item);
    return acc;
  }, {});

  // Filter categories and items
  const filteredGroups = Object.entries(grouped)
    .filter(([cat]) => !categoryFilter || cat === categoryFilter)
    .map(([cat, items]) => {
      const filtered = searchQuery
        ? items.filter((i) =>
            i.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
            i.vendor.toLowerCase().includes(searchQuery.toLowerCase()) ||
            i.product.toLowerCase().includes(searchQuery.toLowerCase())
          )
        : items;
      return [cat, filtered] as const;
    })
    .filter(([, items]) => items.length > 0);

  const categories = Object.keys(grouped).sort();

  return (
    <>
      <PageHeader
        title="Telemetry Sources"
        count={`${selected.size} enabled`}
        actions={
          !isAdmin ? (
            <span className={styles.adminOnlyNote}>Managed by admins</span>
          ) : dirty ? (
            <button
              className={`${styles.btn} ${styles.btnPrimary}`}
              onClick={handleSave}
              disabled={syncMutation.isPending}
            >
              {syncMutation.isPending ? "Saving..." : `Save (${selected.size} selected)`}
            </button>
          ) : undefined
        }
        controls={
          <>
            <input
              type="text"
              className={styles.searchInput}
              placeholder="Search sources..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            <select
              className={styles.filterSelect}
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
            >
              <option value="">All Categories</option>
              {categories.map((c) => (
                <option key={c} value={c}>{CATEGORY_LABELS[c] || c}</option>
              ))}
            </select>
          </>
        }
      />
      <div className={styles.contentBody} style={{ overflowY: "auto" }}>
        {isLoading ? (
          <div className={styles.loading}><span className={styles.spinner} /> Loading catalog...</div>
        ) : (
          <div className={styles.telemetryCatalog}>
            {filteredGroups.map(([cat, items]) => {
              const allChecked = items.every((i) => selected.has(i.name));
              const someChecked = items.some((i) => selected.has(i.name));
              return (
                <div key={cat} className={styles.telemetryCategory}>
                  <div className={styles.telemetryCategoryHeader}>
                    <label className={styles.telemetryCategoryLabel}>
                      <input
                        type="checkbox"
                        checked={allChecked}
                        ref={(el) => { if (el) el.indeterminate = someChecked && !allChecked; }}
                        onChange={() => toggleCategory(items)}
                      />
                      <span className={styles.telemetryCategoryName}>{CATEGORY_LABELS[cat] || cat}</span>
                      <span className={styles.telemetryCategoryCount}>
                        {items.filter((i) => selected.has(i.name)).length}/{items.length}
                      </span>
                    </label>
                  </div>
                  <div className={styles.telemetryItems}>
                    {items.map((item) => (
                      <label key={item.name} className={styles.telemetryItem} title={item.log_types.join(", ")}>
                        <input
                          type="checkbox"
                          checked={selected.has(item.name)}
                          onChange={() => toggle(item.name)}
                        />
                        <div className={styles.telemetryItemInfo}>
                          <span className={styles.telemetryItemName}>{item.name}</span>
                          <span className={styles.telemetryItemMeta}>
                            {item.vendor}{item.product && item.product !== item.vendor ? ` / ${item.product}` : ""}
                            {item.log_types.length > 0 && ` \u00B7 ${item.log_types.length} log types`}
                          </span>
                        </div>
                      </label>
                    ))}
                  </div>
                </div>
              );
            })}
            {filteredGroups.length === 0 && (
              <div className={styles.emptyState}>
                <div className={styles.emptyTitle}>No matching data sources</div>
                <div className={styles.emptyDesc}>Try adjusting your search or category filter.</div>
              </div>
            )}
          </div>
        )}
      </div>
    </>
  );
}

// --- Intelligence Reports ---
const REPORT_COLUMNS: ColumnDef<IntelReport>[] = [
  {
    key: "title", label: "Title", width: 320, minWidth: 170, flex: true,
    serverSort: true, textValue: (r) => r.title,
    render: (r) => <NameCell value={r.title} />,
  },
  {
    key: "template_type", label: "Template", width: 150, minWidth: 100,
    serverSort: true, sortValue: (r) => r.template_type,
    render: (r) => <Chip truncate>{r.template_type.replace(/_/g, " ")}</Chip>,
  },
  {
    key: "tlp_marking", label: "TLP", width: 130, minWidth: 100,
    serverSort: true, sortValue: (r) => r.tlp_marking,
    render: (r) => (
      <span
        className={styles.badge}
        style={{ color: getTLPColor(r.tlp_marking, "inherit"), borderColor: TLP_COLORS[r.tlp_marking] }}
      >
        {r.tlp_marking}
      </span>
    ),
  },
  {
    key: "status", label: "Status", width: 120, minWidth: 90,
    serverSort: true, serverChoice: true,
    choices: [
      { value: "all", label: "Any status" },
      { value: "draft", label: "Draft" },
      { value: "published", label: "Published" },
      { value: "archived", label: "Archived" },
    ],
    choiceMatch: (r, v) => r.status === v,
    render: (r) => (
      <Chip
        tone={r.status === "published" ? "toned" : "default"}
        tint={r.status === "published" ? "var(--success)" : undefined}
        className={r.status === "archived" ? styles.badgeMuted : undefined}
      >
        {r.status}
      </Chip>
    ),
  },
  {
    key: "version", label: "Version", width: 90, minWidth: 70, hideable: true,
    serverSort: true,
    render: (r) => <MetaCell value={`v${r.version}`} />,
  },
  {
    key: "updated_at", label: "Updated", width: 110, minWidth: 90,
    serverSort: true,
    render: (r) => <DateCell value={r.updated_at} />,
  },
  {
    key: "created_at", label: "Created", width: 110, minWidth: 90, hideable: true, defaultHidden: true,
    serverSort: true,
    render: (r) => <DateCell value={r.created_at} />,
  },
];

function ReportsSection() {
  const navigate = useNavigate();
  const [sort, setSort] = useState<{ key: string; dir: SortDir }>({ key: "updated_at", dir: "desc" });
  // Status is the table's own serverChoice column filter now.
  const [reportServerFilters, setReportServerFilters] = useState<Record<string, string>>({});
  const onReportServerFiltersChange = useCallback(
    (f: Record<string, string>) => setReportServerFilters(f),
    [],
  );
  const REPORTS_PAGE_SIZE = 100;
  const reportsExtraParams = { sort_by: sort.key, sort_order: sort.dir, ...reportServerFilters };
  const { data: infiniteData, isLoading, fetchNextPage, hasNextPage, isFetchingNextPage } = useInfiniteQuery({
    queryKey: ["intel-reports", reportsExtraParams],
    queryFn: async ({ pageParam = 0 }) => {
      const { data } = await api.get<PaginatedResponse<IntelReport>>("/intel-reports", {
        params: { limit: REPORTS_PAGE_SIZE, offset: pageParam, ...reportsExtraParams },
      });
      return data;
    },
    initialPageParam: 0,
    getNextPageParam: (lastPage) => lastPage.has_more ? lastPage.offset + lastPage.limit : undefined,
  });
  const items = infiniteData?.pages.flatMap((p) => p.items) ?? [];
  const total = infiniteData?.pages[0]?.total ?? 0;

  return (
    <>
      <PageHeader
        title="Reports"
        count={total}
        actions={
          <>
            <button
              className={styles.btn}
              onClick={() => {
                useUIStore.getState().openReportWizard({
                  sourceType: "search",
                  searchQuery: "",
                });
              }}
            >
              AI Report
            </button>
            <button
              className={`${styles.btn} ${styles.btnPrimary}`}
              onClick={() => navigate("/workbench/report/new")}
            >
              + New Report
            </button>
          </>
        }
      />
      <div className={styles.recipeRow}>
        <button className={styles.recipeCard} onClick={() => navigate("/workbench/report/exposure")}>
          <span className={styles.recipeQ}>Who&rsquo;s targeting a sector or region?</span>
          <span className={styles.recipeMaps}>
            Exposure Report — pick verticals &times; regions, or reuse a saved intel profile
          </span>
        </button>
        <button
          className={styles.recipeCard}
          onClick={() =>
            useUIStore.getState().openReportWizard({
              sourceType: "search",
              searchQuery: "",
              templateType: "landscape_report",
            })
          }
        >
          <span className={styles.recipeQ}>What happened this week?</span>
          <span className={styles.recipeMaps}>Landscape Report — trends and sector impact from a search or saved search</span>
        </button>
        <button
          className={styles.recipeCard}
          onClick={() =>
            useUIStore.getState().openReportWizard({
              sourceType: "search",
              searchQuery: "",
              templateType: "flash_alert",
            })
          }
        >
          <span className={styles.recipeQ}>Brief the SOC on one threat</span>
          <span className={styles.recipeMaps}>Flash Alert — pick the articles, get IOCs and actions in one page</span>
        </button>
        <button
          className={styles.recipeCard}
          onClick={() =>
            useUIStore.getState().openReportWizard({
              sourceType: "search",
              searchQuery: "",
              templateType: "actor_profile",
            })
          }
        >
          <span className={styles.recipeQ}>Profile an actor or campaign</span>
          <span className={styles.recipeMaps}>Actor Profile / Campaign Tracker — or start from any entity&rsquo;s actions menu</span>
        </button>
        <button
          className={styles.recipeCard}
          onClick={() =>
            useUIStore.getState().openReportWizard({
              sourceType: "search",
              searchQuery: "",
              templateType: "detection_report",
            })
          }
        >
          <span className={styles.recipeQ}>Can we detect it?</span>
          <span className={styles.recipeMaps}>Detection Report — TTPs to rules, coverage gaps, log source requirements</span>
        </button>
      </div>
      <DataTable<IntelReport>
        tableId="intel-reports"
        columns={REPORT_COLUMNS}
        rows={items}
        getRowId={(r) => r.id}
        onRowClick={(r) => navigate(`/workbench/report/${r.id}`)}
        sort={sort}
        onSortChange={setSort}
        onServerFiltersChange={onReportServerFiltersChange}
        isLoading={isLoading}
        hasNextPage={hasNextPage}
        isFetchingNextPage={isFetchingNextPage}
        fetchNextPage={fetchNextPage}
        totalCount={total}
        noun="report"
        emptyMessage="No intelligence reports yet — create one to document findings and campaigns."
      />
    </>
  );
}

// --- Intelligence Requirements ---
const PRIORITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const PRIORITY_COLORS: Record<string, string> = {
  critical: "var(--danger)",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "var(--accent-blue)",
};
const REQ_CATEGORIES = ["strategic", "operational", "tactical", "technical"];

const REQUIREMENT_COLUMNS: ColumnDef<IntelligenceRequirement>[] = [
  {
    key: "title", label: "Title", width: 300, minWidth: 160, flex: true,
    textValue: (r) => r.title, sortValue: (r) => r.title.toLowerCase(),
    render: (r) => <NameCell value={r.title} />,
  },
  {
    key: "priority", label: "Priority", width: 100, minWidth: 80,
    // Ranked, not alphabetical — "critical" must sort above "high".
    sortValue: (r) => PRIORITY_ORDER[r.priority] ?? 9,
    // serverChoice: narrows the whole result set, not just loaded rows — this
    // is the filter that used to live as a select in the page header.
    serverChoice: true,
    choices: [
      { value: "all", label: "Any priority" },
      ...Object.keys(PRIORITY_ORDER).map((p) => ({ value: p, label: p })),
    ],
    choiceMatch: (r, v) => r.priority === v,
    render: (r) => (
      <span className={styles.reqPriorityBadge} style={{ color: PRIORITY_COLORS[r.priority] }}>
        {r.priority}
      </span>
    ),
  },
  {
    key: "status", label: "Status", width: 110, minWidth: 90,
    sortValue: (r) => r.status,
    serverChoice: true,
    choices: [
      { value: "all", label: "Any status" },
      { value: "active", label: "Active" },
      { value: "fulfilled", label: "Fulfilled" },
      { value: "expired", label: "Expired" },
      { value: "draft", label: "Draft" },
    ],
    choiceMatch: (r, v) => r.status === v,
    render: (r) => (
      <Chip
        tone={r.status === "active" ? "toned" : "default"}
        tint={r.status === "active" ? "var(--success)" : undefined}
        className={r.status === "expired" ? styles.badgeMuted : undefined}
      >
        {r.status}
      </Chip>
    ),
  },
  {
    key: "category", label: "Category", width: 120, minWidth: 90,
    sortValue: (r) => r.category,
    choices: [
      { value: "all", label: "Any category" },
      ...REQ_CATEGORIES.map((c) => ({ value: c, label: c })),
    ],
    choiceMatch: (r, v) => r.category === v,
    render: (r) => <MetaCell value={r.category} />,
  },
  {
    key: "keywords", label: "Keywords", width: 200, minWidth: 110, hideable: true, defaultHidden: true,
    textValue: (r) => r.keywords.join(", "),
    render: (r) => <MetaCell value={r.keywords.join(", ")} />,
  },
  {
    key: "match_count", label: "Matches", width: 90, minWidth: 70,
    numValue: (r) => r.match_count,
    render: (r) => <NumCell value={r.match_count} />,
  },
  {
    key: "last_matched_at", label: "Last Matched", width: 120, minWidth: 96,
    sortValue: (r) => r.last_matched_at ?? "",
    render: (r) => <DateCell value={r.last_matched_at} />,
  },
  {
    key: "expires_at", label: "Expires", width: 110, minWidth: 90, hideable: true, defaultHidden: true,
    sortValue: (r) => r.expires_at ?? "",
    render: (r) => <DateCell value={r.expires_at} />,
  },
  {
    key: "created_at", label: "Created", width: 110, minWidth: 90, hideable: true, defaultHidden: true,
    sortValue: (r) => r.created_at,
    render: (r) => <DateCell value={r.created_at} />,
  },
];

// Maps entity-search result types to linked_entities keys
const REQ_ENTITY_TYPE_TO_KEY: Record<string, string> = {
  threat_actor: "threat_actors",
  malware: "malware",
  cve: "cves",
  ttp: "ttps",
};
const REQ_ENTITY_KEY_LABELS: Record<string, string> = {
  threat_actors: "Actor",
  malware: "Malware",
  cves: "CVE",
  ttps: "TTP",
};

function useDebounce<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(t);
  }, [value, delayMs]);
  return debounced;
}

function reqEntityDisplayName(item: EntitySearchResult): string {
  if (item.type === "ttp") {
    return [item.technique_id, item.technique_name].filter(Boolean).join(" ");
  }
  if (item.type === "cve") return item.cve_id || item.name || "";
  return item.name || "";
}

/** Picker for entities (actors/malware/CVEs/TTPs) a PIR should auto-match on. */
function LinkedEntitiesEditor({
  value,
  onChange,
}: {
  value: RequirementLinkedEntities;
  onChange: (next: RequirementLinkedEntities) => void;
}) {
  const [query, setQuery] = useState("");
  const debouncedQuery = useDebounce(query, 250);
  const { data: searchData, isFetching } = useEntitySearch(
    debouncedQuery,
    10,
    "threat_actor,malware,cve,ttp"
  );

  const linkedIds = new Set(
    Object.values(value).flatMap((refs) => refs.map((r) => r.id))
  );
  const results = (searchData?.results ?? []).filter(
    (item) => REQ_ENTITY_TYPE_TO_KEY[item.type] && !linkedIds.has(item.id)
  );

  const addEntity = (item: EntitySearchResult) => {
    const key = REQ_ENTITY_TYPE_TO_KEY[item.type];
    const ref: LinkedEntityRef = { id: item.id, name: reqEntityDisplayName(item) };
    onChange({ ...value, [key]: [...(value[key] ?? []), ref] });
    setQuery("");
  };

  const removeEntity = (key: string, id: string) => {
    onChange({ ...value, [key]: (value[key] ?? []).filter((r) => r.id !== id) });
  };

  const chips = Object.entries(value).flatMap(([key, refs]) =>
    (refs ?? []).map((ref) => ({ key, ref }))
  );

  return (
    <div className={styles.reqEntityEditor}>
      {chips.length > 0 && (
        <div className={styles.expandedKeywords}>
          {chips.map(({ key, ref }) => (
            <span key={`${key}-${ref.id}`} className={styles.reqEntityChip} data-entity-key={key}>
              <span className={styles.reqEntityChipType}>{REQ_ENTITY_KEY_LABELS[key]}</span>
              {ref.name}
              <button
                type="button"
                className={styles.reqEntityChipRemove}
                onClick={() => removeEntity(key, ref.id)}
                title="Remove entity"
              >
                &times;
              </button>
            </span>
          ))}
        </div>
      )}
      <input
        type="text"
        className={styles.formInput}
        placeholder="Search actors, malware, CVEs, TTPs..."
        value={query}
        onChange={(e) => setQuery(e.target.value)}
      />
      {debouncedQuery && (results.length > 0 || isFetching) && (
        <div className={styles.reqEntityResults}>
          {isFetching && !results.length ? (
            <span className={styles.entityMeta}>Searching...</span>
          ) : (
            results.slice(0, 8).map((item) => (
              <button
                type="button"
                key={item.id}
                className={styles.reqEntityResult}
                onClick={() => addEntity(item)}
              >
                <span className={styles.reqEntityChipType}>
                  {REQ_ENTITY_KEY_LABELS[REQ_ENTITY_TYPE_TO_KEY[item.type]]}
                </span>
                {reqEntityDisplayName(item)}
              </button>
            ))
          )}
        </div>
      )}
    </div>
  );
}

function RequirementsSection() {
  const navigate = useNavigate();
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const detailPane = useRailWidth("requirements-detail", { default: 420, min: 320, max: 700 });
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const [reviewBannerDismissed, setReviewBannerDismissed] = useState(false);
  const [reqSort, setReqSort] = useState<{ key: string; dir: SortDir }>({ key: "priority", dir: "desc" });
  const REQ_PAGE_SIZE = 100;
  // Fed by the table's own priority/status column filters (serverChoice).
  const [reqServerFilters, setReqServerFilters] = useState<Record<string, string>>({});
  const onReqServerFiltersChange = useCallback((f: Record<string, string>) => setReqServerFilters(f), []);
  const reqExtraParams = reqServerFilters;
  const { data: infiniteReqData, isLoading, fetchNextPage: fetchNextReqPage, hasNextPage: hasNextReqPage, isFetchingNextPage: isFetchingNextReqPage } = useInfiniteQuery({
    queryKey: ["requirements", reqExtraParams],
    queryFn: async ({ pageParam = 0 }) => {
      const { data } = await api.get<PaginatedResponse<IntelligenceRequirement>>("/requirements", {
        params: { limit: REQ_PAGE_SIZE, offset: pageParam, ...reqExtraParams },
      });
      return data;
    },
    initialPageParam: 0,
    getNextPageParam: (lastPage) => lastPage.has_more ? lastPage.offset + lastPage.limit : undefined,
  });
  const reqItems = infiniteReqData?.pages.flatMap((p) => p.items) ?? [];
  const reqTotal = infiniteReqData?.pages[0]?.total ?? 0;

  const { data: coverage } = useRequirementCoverage();
  const createMutation = useCreateRequirement();
  const updateMutation = useUpdateRequirement();
  const deleteMutation = useDeleteRequirement();
  const undoableDeleteReq = useUndoableDelete();

  // Create form state
  const [formTitle, setFormTitle] = useState("");
  const [formDesc, setFormDesc] = useState("");
  const [formPriority, setFormPriority] = useState("medium");
  const [formCategory, setFormCategory] = useState("operational");
  const [formKeywords, setFormKeywords] = useState("");
  const [formExpiry, setFormExpiry] = useState("");
  const [formMinRelevance, setFormMinRelevance] = useState("");
  const [formEntities, setFormEntities] = useState<RequirementLinkedEntities>({});

  // Edit form state
  const [editTitle, setEditTitle] = useState("");
  const [editDesc, setEditDesc] = useState("");
  const [editPriority, setEditPriority] = useState("");
  const [editCategory, setEditCategory] = useState("");
  const [editKeywords, setEditKeywords] = useState("");
  const [editExpiry, setEditExpiry] = useState("");
  const [editStatus, setEditStatus] = useState("");
  const [editMinRelevance, setEditMinRelevance] = useState("");
  const [editEntities, setEditEntities] = useState<RequirementLinkedEntities>({});

  const resetCreateForm = () => {
    setFormTitle("");
    setFormDesc("");
    setFormPriority("medium");
    setFormCategory("operational");
    setFormKeywords("");
    setFormExpiry("");
    setFormMinRelevance("");
    setFormEntities({});
  };

  const handleCreate = () => {
    if (!formTitle.trim()) return;
    const body: RequirementCreate = {
      title: formTitle.trim(),
      priority: formPriority,
      category: formCategory,
    };
    if (formDesc.trim()) body.description = formDesc.trim();
    const kw = formKeywords.split(",").map((k) => k.trim()).filter(Boolean);
    if (kw.length) body.keywords = kw;
    if (formExpiry) body.expires_at = formExpiry;
    if (formMinRelevance) body.min_relevance = formMinRelevance;
    if (Object.values(formEntities).some((refs) => refs.length > 0)) {
      body.linked_entities = formEntities;
    }
    createMutation.mutate(body, {
      onSuccess: () => {
        resetCreateForm();
        setShowCreateForm(false);
      },
    });
  };

  const selectedReq = reqItems.find((r) => r.id === selectedId);

  const startEdit = () => {
    if (!selectedReq) return;
    setEditingId(selectedReq.id);
    setEditTitle(selectedReq.title);
    setEditDesc(selectedReq.description || "");
    setEditPriority(selectedReq.priority);
    setEditCategory(selectedReq.category);
    setEditKeywords(selectedReq.keywords.join(", "));
    setEditExpiry(selectedReq.expires_at ? selectedReq.expires_at.slice(0, 10) : "");
    setEditStatus(selectedReq.status);
    setEditMinRelevance(selectedReq.min_relevance || "");
    setEditEntities(selectedReq.linked_entities || {});
  };

  const handleUpdate = () => {
    if (!editingId || !editTitle.trim()) return;
    const kw = editKeywords.split(",").map((k) => k.trim()).filter(Boolean);
    updateMutation.mutate(
      {
        id: editingId,
        title: editTitle.trim(),
        description: editDesc.trim() || undefined,
        priority: editPriority,
        category: editCategory,
        status: editStatus,
        keywords: kw.length ? kw : undefined,
        expires_at: editExpiry || undefined,
        min_relevance: editMinRelevance || null,
        linked_entities: editEntities,
      },
      { onSuccess: () => setEditingId(null) }
    );
  };

  const handleDelete = (id: string) => {
    setDeleteConfirmId(null);
    undoableDeleteReq({
      label: "Requirement",
      key: `req-${id}`,
      onDelete: () => deleteMutation.mutate(id, {
        onSuccess: () => {
          if (selectedId === id) setSelectedId(null);
        },
      }),
    });
  };

  return (
    <>
      <PageHeader
        title="Requirements"
        count={reqTotal}
        subtitle="Priority intelligence requirements — the questions collection is meant to answer."
        actions={
          <button
            className={`${styles.btn} ${styles.btnPrimary}`}
            onClick={() => setShowCreateForm((v) => !v)}
          >
            {showCreateForm ? "Cancel" : "+ New Requirement"}
          </button>
        }
      />

      {/* Periodic review reminder — active PIRs untouched for 90+ days */}
      {coverage && coverage.needs_review?.length > 0 && !reviewBannerDismissed && (
        <div className={styles.reqReviewBanner}>
          <span className={styles.reqReviewBannerText}>
            {coverage.needs_review.length} active requirement{coverage.needs_review.length !== 1 ? "s" : ""} not
            reviewed in 90+ days:
          </span>
          {coverage.needs_review.slice(0, 5).map((r) => (
            <button
              key={r.id}
              type="button"
              className={styles.reqReviewBannerItem}
              onClick={() => { setSelectedId(r.id); setEditingId(null); setDeleteConfirmId(null); }}
            >
              {r.title}
            </button>
          ))}
          {coverage.needs_review.length > 5 && (
            <span className={styles.reqReviewBannerText}>+{coverage.needs_review.length - 5} more</span>
          )}
          <button
            type="button"
            className={styles.reqReviewBannerDismiss}
            onClick={() => setReviewBannerDismissed(true)}
            title="Dismiss reminder"
          >
            &times;
          </button>
        </div>
      )}

      {/* Coverage Summary */}
      {coverage && (
        <div className={styles.coverageSummary}>
          <div className={styles.coverageStat}>
            <span className={`${styles.coverageCount} ${styles.coverageCountActive}`}>{coverage.active}</span>
            <span>Active</span>
          </div>
          <div className={styles.coverageDivider} />
          <div className={styles.coverageStat}>
            <span className={`${styles.coverageCount} ${styles.coverageCountFulfilled}`}>{coverage.fulfilled}</span>
            <span>Fulfilled</span>
          </div>
          <div className={styles.coverageDivider} />
          <div className={styles.coverageStat}>
            <span className={`${styles.coverageCount} ${styles.coverageCountExpired}`}>{coverage.expired}</span>
            <span>Expired</span>
          </div>
          <div className={styles.coverageDivider} />
          <div className={styles.coverageStat}>
            <span className={`${styles.coverageCount} ${styles.coverageCountStale}`}>{coverage.stale}</span>
            <span>Stale</span>
          </div>
          <div className={styles.coverageDivider} />
          <div className={styles.coverageStat}>
            <span className={styles.coverageCount}>{coverage.with_recent_matches}</span>
            <span>Recent Matches</span>
          </div>
        </div>
      )}

      {/* Create Form */}
      {showCreateForm && (
        <div className={styles.createForm}>
          <div className={styles.createFormTitle}>New Intelligence Requirement</div>
          <div className={styles.formGrid}>
            <div className={`${styles.formRow} ${styles.formRowFull}`}>
              <label className={styles.formLabel}>Title *</label>
              <input
                type="text"
                className={styles.formInput}
                placeholder="e.g. Track APT29 activity and indicators"
                value={formTitle}
                onChange={(e) => setFormTitle(e.target.value)}
              />
            </div>
            <div className={`${styles.formRow} ${styles.formRowFull}`}>
              <label className={styles.formLabel}>Description</label>
              <textarea
                className={styles.formTextarea}
                placeholder="Detailed description of what intelligence is needed..."
                value={formDesc}
                onChange={(e) => setFormDesc(e.target.value)}
              />
            </div>
            <div className={styles.formRow}>
              <label className={styles.formLabel}>Priority</label>
              <select className={styles.formSelect} value={formPriority} onChange={(e) => setFormPriority(e.target.value)}>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div className={styles.formRow}>
              <label className={styles.formLabel}>Category</label>
              <select className={styles.formSelect} value={formCategory} onChange={(e) => setFormCategory(e.target.value)}>
                {REQ_CATEGORIES.map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            </div>
            <div className={`${styles.formRow} ${styles.formRowFull}`}>
              <label className={styles.formLabel}>Keywords (comma-separated)</label>
              <input
                type="text"
                className={styles.formInput}
                placeholder="e.g. apt29, cozy bear, nobelium"
                value={formKeywords}
                onChange={(e) => setFormKeywords(e.target.value)}
              />
            </div>
            <div className={`${styles.formRow} ${styles.formRowFull}`}>
              <label className={styles.formLabel}>Linked Entities (auto-match on extracted entities)</label>
              <LinkedEntitiesEditor value={formEntities} onChange={setFormEntities} />
            </div>
            <div className={styles.formRow}>
              <label className={styles.formLabel}>Minimum Match Relevance</label>
              <select
                className={styles.formSelect}
                value={formMinRelevance}
                onChange={(e) => setFormMinRelevance(e.target.value)}
              >
                <option value="">Keep all matches</option>
                <option value="medium">Medium+ (title keyword, entity, multi-keyword)</option>
                <option value="high">High only (title keyword or entity)</option>
              </select>
            </div>
            <div className={styles.formRow}>
              <label className={styles.formLabel}>Expiry Date (optional)</label>
              <input
                type="date"
                className={styles.formInput}
                value={formExpiry}
                onChange={(e) => setFormExpiry(e.target.value)}
              />
            </div>
            <div className={styles.formActions}>
              <button className={styles.btn} onClick={() => { resetCreateForm(); setShowCreateForm(false); }}>Cancel</button>
              <button
                className={`${styles.btn} ${styles.btnPrimary}`}
                onClick={handleCreate}
                disabled={!formTitle.trim() || createMutation.isPending}
              >
                {createMutation.isPending ? "Creating..." : "Create Requirement"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* The pane's width rides a custom property so the narrow-screen rules
          can still cap it, and stack it full-width below 768px. */}
      <div
        className={styles.reqLayout}
        style={{ "--req-detail-w": `${detailPane.width}px` } as React.CSSProperties}
      >
        {/* Left: Requirements Table */}
        <div className={styles.reqTablePane}>
          <DataTable<IntelligenceRequirement>
            tableId="requirements"
            columns={REQUIREMENT_COLUMNS}
            rows={reqItems}
            getRowId={(r) => r.id}
            activeRowId={selectedId}
            onRowClick={(req) => {
              setSelectedId(selectedId === req.id ? null : req.id);
              setEditingId(null);
              setDeleteConfirmId(null);
            }}
            sort={reqSort}
            onSortChange={setReqSort}
            onServerFiltersChange={onReqServerFiltersChange}
            isLoading={isLoading}
            hasNextPage={hasNextReqPage}
            isFetchingNextPage={isFetchingNextReqPage}
            fetchNextPage={fetchNextReqPage}
            totalCount={reqTotal}
            noun="requirement"
            emptyMessage="No intelligence requirements yet — create PIRs to track topics, threats, and gaps."
          />
        </div>

        {/* Right: Detail Panel */}
        {selectedReq && (
          /* The pane sits to the right of the handle, so a drag right has to
             shrink it — the delta is inverted. */
          <ResizeHandle
            label="requirement details"
            onResize={(delta) => detailPane.handleProps.onResize(-delta)}
            onResizeStart={detailPane.handleProps.onResizeStart}
            onResizeEnd={detailPane.handleProps.onResizeEnd}
            onReset={detailPane.handleProps.onReset}
          />
        )}

        {selectedReq && (
          <RequirementDetailPanel
            req={selectedReq}
            isEditing={editingId === selectedReq.id}
            deleteConfirmId={deleteConfirmId}
            editTitle={editTitle}
            editDesc={editDesc}
            editPriority={editPriority}
            editCategory={editCategory}
            editKeywords={editKeywords}
            editExpiry={editExpiry}
            editStatus={editStatus}
            editMinRelevance={editMinRelevance}
            editEntities={editEntities}
            setEditTitle={setEditTitle}
            setEditDesc={setEditDesc}
            setEditPriority={setEditPriority}
            setEditCategory={setEditCategory}
            setEditKeywords={setEditKeywords}
            setEditExpiry={setEditExpiry}
            setEditStatus={setEditStatus}
            setEditMinRelevance={setEditMinRelevance}
            setEditEntities={setEditEntities}
            onStartEdit={startEdit}
            onCancelEdit={() => setEditingId(null)}
            onSaveEdit={handleUpdate}
            onDeleteConfirm={() => setDeleteConfirmId(selectedReq.id)}
            onDeleteCancel={() => setDeleteConfirmId(null)}
            onDelete={() => handleDelete(selectedReq.id)}
            onClose={() => setSelectedId(null)}
            updatePending={updateMutation.isPending}
            deletePending={deleteMutation.isPending}
            navigate={navigate}
          />
        )}
      </div>
    </>
  );
}

// --- Requirement Detail Panel ---
interface RequirementDetailPanelProps {
  req: {
    id: string;
    title: string;
    description: string | null;
    priority: string;
    status: string;
    category: string;
    keywords: string[];
    linked_entities: RequirementLinkedEntities;
    min_relevance: string | null;
    match_count: number;
    last_matched_at: string | null;
    expires_at: string | null;
    fulfilled_by_report_id: string | null;
    auto_match: boolean;
    created_at: string;
  };
  isEditing: boolean;
  deleteConfirmId: string | null;
  editTitle: string;
  editDesc: string;
  editPriority: string;
  editCategory: string;
  editKeywords: string;
  editExpiry: string;
  editStatus: string;
  editMinRelevance: string;
  editEntities: RequirementLinkedEntities;
  setEditTitle: (v: string) => void;
  setEditDesc: (v: string) => void;
  setEditPriority: (v: string) => void;
  setEditCategory: (v: string) => void;
  setEditKeywords: (v: string) => void;
  setEditExpiry: (v: string) => void;
  setEditStatus: (v: string) => void;
  setEditMinRelevance: (v: string) => void;
  setEditEntities: (v: RequirementLinkedEntities) => void;
  onStartEdit: () => void;
  onCancelEdit: () => void;
  onSaveEdit: () => void;
  onDeleteConfirm: () => void;
  onDeleteCancel: () => void;
  onDelete: () => void;
  onClose: () => void;
  updatePending: boolean;
  deletePending: boolean;
  navigate: ReturnType<typeof useNavigate>;
}

function RequirementDetailPanel({
  req,
  isEditing,
  deleteConfirmId,
  editTitle,
  editDesc,
  editPriority,
  editCategory,
  editKeywords,
  editExpiry,
  editStatus,
  editMinRelevance,
  editEntities,
  setEditTitle,
  setEditDesc,
  setEditPriority,
  setEditCategory,
  setEditKeywords,
  setEditExpiry,
  setEditStatus,
  setEditMinRelevance,
  setEditEntities,
  onStartEdit,
  onCancelEdit,
  onSaveEdit,
  onDeleteConfirm,
  onDeleteCancel,
  onDelete,
  onClose,
  updatePending,
  deletePending,
  navigate,
}: RequirementDetailPanelProps) {
  const { data: matchesData, isLoading: matchesLoading } = useRequirementMatches(
    req.id,
    { limit: 500, offset: 0 }
  );
  const removeMutation = useRemoveRequirementMatch();
  const fulfillMutation = useFulfillRequirement();
  const [showFulfill, setShowFulfill] = useState(false);
  const [fulfillReportId, setFulfillReportId] = useState("");
  const { data: reportsData } = useIntelReports({ limit: 100, sort_by: "updated_at", sort_order: "desc" });
  const { data: fulfilledReport } = useIntelReport(req.fulfilled_by_report_id || undefined);

  const handleRemoveMatch = (entryId: string) => {
    removeMutation.mutate({ requirementId: req.id, entryId });
  };

  const handleFulfill = () => {
    fulfillMutation.mutate(
      { id: req.id, reportId: fulfillReportId || null },
      {
        onSuccess: () => {
          setShowFulfill(false);
          setFulfillReportId("");
        },
      }
    );
  };

  const handleReadArticle = (entryId: string) => {
    useUIStore.getState().setSelectedEntry(entryId);
    navigate("/");
  };

  return (
    <div className={styles.reqDetailPane}>
      {/* Panel Header */}
      <div className={styles.reqDetailHeader}>
        <div className={styles.reqDetailHeaderTop}>
          <span
            className={styles.reqPriorityBadge}
            style={{ color: PRIORITY_COLORS[req.priority] }}
          >
            {req.priority}
          </span>
          <Chip
            tone={req.status === "active" ? "toned" : "default"}
            tint={req.status === "active" ? "var(--success)" : undefined}
            className={req.status === "expired" ? styles.badgeMuted : undefined}
          >
            {req.status}
          </Chip>
          <span className={styles.reqDetailCategory}>{req.category}</span>
          <button className={styles.reqCloseBtn} onClick={onClose} title="Close panel">&times;</button>
        </div>
        <h3 className={styles.reqDetailTitle}>{req.title}</h3>
        {req.description && <p className={styles.reqDetailDesc}>{req.description}</p>}
      </div>

      {isEditing ? (
        /* Edit Form */
        <div className={styles.reqEditForm}>
          <div className={styles.formRow}>
            <label className={styles.formLabel}>Title</label>
            <input type="text" className={styles.formInput} value={editTitle} onChange={(e) => setEditTitle(e.target.value)} />
          </div>
          <div className={styles.formRow}>
            <label className={styles.formLabel}>Description</label>
            <textarea className={styles.formTextarea} value={editDesc} onChange={(e) => setEditDesc(e.target.value)} />
          </div>
          <div className={styles.reqEditRow}>
            <div className={styles.formRow}>
              <label className={styles.formLabel}>Priority</label>
              <select className={styles.formSelect} value={editPriority} onChange={(e) => setEditPriority(e.target.value)}>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div className={styles.formRow}>
              <label className={styles.formLabel}>Status</label>
              <select className={styles.formSelect} value={editStatus} onChange={(e) => setEditStatus(e.target.value)}>
                <option value="active">Active</option>
                <option value="fulfilled">Fulfilled</option>
                <option value="expired">Expired</option>
                <option value="draft">Draft</option>
              </select>
            </div>
          </div>
          <div className={styles.reqEditRow}>
            <div className={styles.formRow}>
              <label className={styles.formLabel}>Category</label>
              <select className={styles.formSelect} value={editCategory} onChange={(e) => setEditCategory(e.target.value)}>
                {REQ_CATEGORIES.map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            </div>
            <div className={styles.formRow}>
              <label className={styles.formLabel}>Expiry Date</label>
              <input type="date" className={styles.formInput} value={editExpiry} onChange={(e) => setEditExpiry(e.target.value)} />
            </div>
          </div>
          <div className={styles.formRow}>
            <label className={styles.formLabel}>Keywords (comma-separated)</label>
            <input type="text" className={styles.formInput} value={editKeywords} onChange={(e) => setEditKeywords(e.target.value)} />
          </div>
          <div className={styles.formRow}>
            <label className={styles.formLabel}>Linked Entities (auto-match on extracted entities)</label>
            <LinkedEntitiesEditor value={editEntities} onChange={setEditEntities} />
          </div>
          <div className={styles.formRow}>
            <label className={styles.formLabel}>Minimum Match Relevance</label>
            <select
              className={styles.formSelect}
              value={editMinRelevance}
              onChange={(e) => setEditMinRelevance(e.target.value)}
            >
              <option value="">Keep all matches</option>
              <option value="medium">Medium+ (title keyword, entity, multi-keyword)</option>
              <option value="high">High only (title keyword or entity)</option>
            </select>
          </div>
          <div className={styles.formActions}>
            <button className={styles.btn} onClick={onCancelEdit}>Cancel</button>
            <button
              className={`${styles.btn} ${styles.btnPrimary}`}
              onClick={onSaveEdit}
              disabled={!editTitle.trim() || updatePending}
            >
              {updatePending ? "Saving..." : "Save"}
            </button>
          </div>
        </div>
      ) : (
        /* Read-only details */
        <>
          {/* Keywords */}
          <div className={styles.reqSection}>
            <div className={styles.reqSectionLabel}>Keywords ({req.keywords.length})</div>
            {req.keywords.length > 0 ? (
              <div className={styles.expandedKeywords}>
                {req.keywords.map((kw) => (
                  <Chip key={kw} truncate>{kw}</Chip>
                ))}
              </div>
            ) : (
              <span className={styles.entityMeta}>No keywords configured</span>
            )}
          </div>

          {/* Linked entities */}
          {Object.values(req.linked_entities || {}).some((refs) => refs.length > 0) && (
            <div className={styles.reqSection}>
              <div className={styles.reqSectionLabel}>Linked Entities</div>
              <div className={styles.expandedKeywords}>
                {Object.entries(req.linked_entities || {}).flatMap(([key, refs]) =>
                  (refs ?? []).map((ref) => (
                    <span key={`${key}-${ref.id}`} className={styles.reqEntityChip} data-entity-key={key}>
                      <span className={styles.reqEntityChipType}>{REQ_ENTITY_KEY_LABELS[key]}</span>
                      {ref.name}
                    </span>
                  ))
                )}
              </div>
            </div>
          )}

          {/* Metadata */}
          <div className={styles.reqMetaGrid}>
            <span className={styles.reqMetaItem}>
              <span className={styles.expandedMetaLabel}>Auto Match</span>
              <span>{req.auto_match ? "Yes" : "No"}</span>
            </span>
            {req.min_relevance && (
              <span className={styles.reqMetaItem}>
                <span className={styles.expandedMetaLabel}>Min Relevance</span>
                <span>{req.min_relevance}</span>
              </span>
            )}
            <span className={styles.reqMetaItem}>
              <span className={styles.expandedMetaLabel}>Created</span>
              <span>{formatDate(req.created_at)}</span>
            </span>
            {req.expires_at && (
              <span className={styles.reqMetaItem}>
                <span className={styles.expandedMetaLabel}>Expires</span>
                <span>{formatDate(req.expires_at)}</span>
              </span>
            )}
            {req.status === "fulfilled" && req.fulfilled_by_report_id && (
              <span className={styles.reqMetaItem}>
                <span className={styles.expandedMetaLabel}>Fulfilled by</span>
                <span
                  className={styles.reqFulfilledLink}
                  onClick={() => navigate(`/workbench/report/${req.fulfilled_by_report_id}`)}
                  role="link"
                  tabIndex={0}
                  onKeyDown={(e) => { if (e.key === "Enter") navigate(`/workbench/report/${req.fulfilled_by_report_id}`); }}
                >
                  {fulfilledReport?.title || "View report"}
                </span>
              </span>
            )}
          </div>

          {/* Actions bar */}
          <div className={styles.reqActionBar}>
            <button className={styles.btn} onClick={onStartEdit}>Edit</button>
            {req.status === "active" && !showFulfill && (
              <button className={styles.btn} onClick={() => setShowFulfill(true)}>Mark Fulfilled</button>
            )}
            {deleteConfirmId === req.id ? (
              <>
                <span className={styles.deleteConfirmText}>Delete?</span>
                <button
                  className={`${styles.btn} ${styles.btnDanger}`}
                  onClick={onDelete}
                  disabled={deletePending}
                >
                  {deletePending ? "..." : "Yes"}
                </button>
                <button className={styles.btn} onClick={onDeleteCancel}>No</button>
              </>
            ) : (
              <button className={`${styles.btn} ${styles.btnDanger}`} onClick={onDeleteConfirm}>Delete</button>
            )}
          </div>

          {/* Fulfill: optionally link the report that answered this PIR */}
          {showFulfill && (
            <div className={styles.reqFulfillForm}>
              <select
                className={styles.formSelect}
                value={fulfillReportId}
                onChange={(e) => setFulfillReportId(e.target.value)}
              >
                <option value="">No report (just mark fulfilled)</option>
                {(reportsData?.items ?? []).map((r) => (
                  <option key={r.id} value={r.id}>{r.title}</option>
                ))}
              </select>
              <button
                className={`${styles.btn} ${styles.btnPrimary}`}
                onClick={handleFulfill}
                disabled={fulfillMutation.isPending}
              >
                {fulfillMutation.isPending ? "..." : "Fulfill"}
              </button>
              <button className={styles.btn} onClick={() => setShowFulfill(false)}>Cancel</button>
            </div>
          )}

          {/* Matched Articles */}
          <div className={styles.reqSection}>
            <div className={styles.reqMatchHeader}>
              <span className={styles.reqSectionLabel}>
                Matched Articles ({matchesData?.total ?? req.match_count})
              </span>
            </div>

            {matchesLoading ? (
              <div className={styles.loading}><span className={styles.spinner} /> Loading...</div>
            ) : !matchesData?.items.length ? (
              <div className={styles.matchEmpty}>No matches yet. Articles matching your keywords will appear here automatically.</div>
            ) : (
              <>
                <div className={styles.reqMatchList}>
                  {matchesData.items.map((m) => (
                    <div key={m.entry_id} className={styles.reqMatchItem}>
                      <div className={styles.reqMatchContent}>
                        <span
                          className={styles.reqMatchTitle}
                          onClick={() => handleReadArticle(m.entry_id)}
                          title="Click to read article"
                        >
                          {m.entry_title || "Untitled"}
                        </span>
                        <span className={styles.reqMatchMeta}>
                          <span
                            className={styles.reqMatchKeyword}
                            data-match-type={m.match_type}
                            title={`Matched via ${m.match_type}: ${m.matched_on}`}
                          >
                            {m.match_type === "entity" ? "entity" : m.match_type === "manual" ? "manual" : "keyword"}
                            {": "}
                            {m.matched_on}
                          </span>
                          {m.relevance && (
                            <span className={styles.reqMatchRelevance} data-relevance={m.relevance}>
                              {m.relevance}
                            </span>
                          )}
                          <span className={styles.reqMatchDot}>&middot;</span>
                          <span>{formatDate(m.matched_at)}</span>
                          {m.entry_published_at && (
                            <>
                              <span className={styles.reqMatchDot}>&middot;</span>
                              <span>published {formatDate(m.entry_published_at)}</span>
                            </>
                          )}
                        </span>
                      </div>
                      <button
                        className={styles.reqMatchUnlink}
                        onClick={() => handleRemoveMatch(m.entry_id)}
                        title="Unlink this article from requirement"
                        disabled={removeMutation.isPending}
                      >
                        &times;
                      </button>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </>
      )}
    </div>
  );
}
// --- Rule Generator (embeds DetectionWorkbenchPage) ---
