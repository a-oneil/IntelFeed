import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import JobSchedules from "@/components/JobSchedules";
import SystemSettings, { SettingsHighlightContext } from "@/components/SystemSettings";

import {
  type BrowseView,
  EngineMatrix,
  LEGACY_ENTITY_LENS,
  MATRIX_VIEWS,
  type MatrixView,
  REVIEW_LENSES,
  type ReviewLens,
} from "./EngineMatrix";
import type { ReviewEntityStatus } from "./ExtractionTab";
import { EngineStoppedBanner } from "./EngineSwitch";
import { EnrichmentConsole } from "./EnrichmentConsole";
import { MaintenancePanel } from "./MaintenancePanel";
import { PipelinePlans } from "./PipelinePlans";
import { PublishingPanel } from "./PublishingPanel";
import styles from "./EngineSection.module.css";

const BROWSE_TITLES: Record<BrowseView, string> = {
  jobs: "Scheduled jobs",
  plans: "Pipeline plans",
  enrichment: "Enrichment",
  maintenance: "Maintenance",
  publishing: "Publishing",
};

// The statuses ?show= may name on the Entities lens.
const LEGACY_ENTITY_LENS_VALUES: Record<ReviewEntityStatus, true> = { review: true, dupe: true, orphan: true };

interface ConsoleState {
  view?: MatrixView;
  lens?: ReviewLens;
  /** The Entities lens's status (?show=dupe; the old ?lens=duplicates maps here too). */
  entityStatus?: ReviewEntityStatus;
  openStage?: string;
  stage?: string;
  status?: string;
  browse?: BrowseView;
  /** Enrichment source to open on its Jobs tab (`?section=enrichment&source=nvd`). */
  source?: string;
  /** Source whose key to open in Keys (`?section=enrichment&key_for=virustotal`). */
  keyFor?: string;
}

// Deep links: ?view= opens one of the console's tabs (?view=entities; ?view=review&lens=history opens one of Review's lenses, and &lens=entities&show=dupe one status of its Entities lens). Older links still work: the six-tab layout (?tab=), the per-status lenses (?lens=duplicates) and the Settings sections (?section=) are mapped onto the console's states.
function legacyState(params: URLSearchParams): ConsoleState {
  const view = params.get("view");
  if (view && (MATRIX_VIEWS as readonly string[]).includes(view)) {
    const lensParam = params.get("lens") ?? "";
    const legacyStatus = LEGACY_ENTITY_LENS[lensParam];
    const show = params.get("show") ?? "";
    const entityStatus = legacyStatus ?? (show in LEGACY_ENTITY_LENS_VALUES ? (show as ReviewEntityStatus) : undefined);
    return {
      view: view as MatrixView,
      lens: legacyStatus ? "entities" : REVIEW_LENSES.find((l) => l === lensParam),
      entityStatus,
    };
  }
  const tab = params.get("tab");
  const stage = params.get("stage");
  if (tab === "processing")
    return { stage: stage ?? undefined, status: params.get("status") ?? undefined };
  if (tab === "pipeline") {
    if (stage === "feeds") return { view: "feeds" };
    // The enrich stage's settings are the Enrichment page itself.
    if (stage === "enrich") return { browse: "enrichment" };
    if (stage) return { openStage: stage };
    return {};
  }
  if (tab === "autolinking") return { view: "links" };
  if (tab === "extraction") return { view: "entities" };
  if (tab === "jobs") return { browse: "jobs" };
  if (tab === "plans") return { browse: "plans" };
  switch (params.get("section")) {
    case "schedules":
      return { browse: "jobs" };
    case "enrichment":
      return {
        browse: "enrichment",
        source: params.get("source") ?? undefined,
        keyFor: params.get("key_for") ?? undefined,
      };
    case "feed-health":
      return { view: "feeds" };
    case "workbench":
      return { openStage: "autolink" };
  }
  return {};
}

/** Workbench → Engine console. Everything is in one table card (entries matrix, links, relationships, review queue, stage settings); only the browse views (Jobs, Plans, Enrichment, Publishing, Maintenance) open as separate screens with a back button. */
export function EngineSection() {
  const [searchParams] = useSearchParams();
  const [browse, setBrowse] = useState<BrowseView | null>(null);
  const [enrichSource, setEnrichSource] = useState<string | null>(null);
  const [enrichKeyFor, setEnrichKeyFor] = useState<string | null>(null);
  const [initial, setInitial] = useState<ConsoleState>({});
  const [nonce, setNonce] = useState(0);
  // The setting picked in the console's search. It is highlighted wherever it renders, then cleared after 5 seconds so the highlight doesn't reappear on a panel reopened later.
  const [highlight, setHighlight] = useState<{ key: string; nonce: number } | null>(null);
  const hlTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const highlightSetting = useCallback((key: string) => {
    setHighlight((h) => ({ key, nonce: (h?.nonce ?? 0) + 1 }));
    if (hlTimer.current) clearTimeout(hlTimer.current);
    hlTimer.current = setTimeout(() => setHighlight(null), 5000);
  }, []);

  useEffect(() => () => void (hlTimer.current && clearTimeout(hlTimer.current)), []);

  useEffect(() => {
    const s = legacyState(searchParams);
    if (Object.keys(s).length === 0) return;
    if (s.browse) {
      setBrowse(s.browse);
      setEnrichSource(s.source ?? null);
      setEnrichKeyFor(s.keyFor ?? null);
      return;
    }
    setInitial(s);
    setNonce((n) => n + 1);
  }, [searchParams]);

  if (browse) {
    return (
      <SettingsHighlightContext.Provider value={highlight}>
        <div className={styles.wrap}>
          <div className={styles.viewHead}>
            <button
              type="button"
              className={styles.backBtn}
              onClick={() => {
                setBrowse(null);
                setEnrichSource(null);
                setEnrichKeyFor(null);
              }}
            >
              ← Engine
            </button>
            <h2 className={styles.viewTitle}>{BROWSE_TITLES[browse]}</h2>
          </div>
          <EngineStoppedBanner />
          {browse === "jobs" && (
            <JobSchedules
              onOpenEnrichment={(source) => {
                setEnrichSource(source);
                setEnrichKeyFor(null);
                setBrowse("enrichment");
              }}
            />
          )}
          {browse === "plans" && (
            <>
              <PipelinePlans />
              <p className={styles.browseHint}>These settings apply to pipeline plans engine-wide.</p>
              <SystemSettings filterGroups={["plans"]} hideGroupTitle />
            </>
          )}
          {browse === "enrichment" && (
            <EnrichmentConsole
              key={`${enrichSource ?? ""}|${enrichKeyFor ?? ""}`}
              initialSource={enrichSource}
              initialKeyFor={enrichKeyFor}
            />
          )}
          {browse === "publishing" && <PublishingPanel />}
          {browse === "maintenance" && (
            <>
              <p className={styles.browseHint}>These are global sweeps and destructive resets. Run them rarely.</p>
              <MaintenancePanel />
              <p className={styles.browseHint}>
                These settings control actor refresh, assessment backfill and briefing themes.
              </p>
              {/* Two blocks, not one call with both groups: the "Maintenance" group title would repeat this view's own heading, so it is hidden, while Retention needs its title to read as a separate section. */}
              <SystemSettings filterGroups={["maintenance"]} hideGroupTitle />
              <SystemSettings filterGroups={["retention"]} />
            </>
          )}
        </div>
      </SettingsHighlightContext.Provider>
    );
  }

  return (
    <SettingsHighlightContext.Provider value={highlight}>
      <div className={styles.wrap}>
        <EngineStoppedBanner />
        <EngineMatrix
          key={nonce}
          initialView={initial.view}
          initialLens={initial.lens}
          initialEntityStatus={initial.entityStatus}
          initialOpenStage={initial.openStage}
          initialStage={initial.stage}
          initialStatus={initial.status}
          onBrowse={setBrowse}
          onHighlightSetting={highlightSetting}
        />
      </div>
    </SettingsHighlightContext.Provider>
  );
}
