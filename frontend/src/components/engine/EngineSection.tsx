import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import JobSchedules from "@/components/JobSchedules";
import SystemSettings, { SettingsHighlightContext } from "@/components/SystemSettings";

import { type BrowseView, EngineMatrix, type MatrixView } from "./EngineMatrix";
import { MaintenancePanel } from "./MaintenancePanel";
import { PipelinePlans } from "./PipelinePlans";
import { PublishingPanel } from "./PublishingPanel";
import styles from "./EngineSection.module.css";

const BROWSE_TITLES: Record<BrowseView, string> = {
  jobs: "Scheduled jobs",
  plans: "Pipeline plans",
  maintenance: "Maintenance",
  publishing: "Publishing",
};

interface ConsoleState {
  view?: MatrixView;
  openStage?: string;
  stage?: string;
  status?: string;
  browse?: BrowseView;
}

// Legacy deep links from the old six-tab layout (?tab=) and the even older
// Settings sections (?section=) — mapped onto the console's states.
function legacyState(params: URLSearchParams): ConsoleState {
  const tab = params.get("tab");
  const stage = params.get("stage");
  if (tab === "processing")
    return { stage: stage ?? undefined, status: params.get("status") ?? undefined };
  if (tab === "pipeline") {
    if (stage === "feeds") return { view: "feeds" };
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
      return { openStage: "enrich" };
    case "feed-health":
      return { view: "feeds" };
    case "workbench":
      return { openStage: "autolink" };
  }
  return {};
}

/** Workbench → Engine: single-surface console. Everything lives in the one
 *  table card (entries matrix, links, relationships, AI entities, stage
 *  settings); only Jobs / Feeds / Plans open as separate views. */
export function EngineSection() {
  const [searchParams] = useSearchParams();
  const [browse, setBrowse] = useState<BrowseView | null>(null);
  const [initial, setInitial] = useState<ConsoleState>({});
  const [nonce, setNonce] = useState(0);
  // Setting the console's search jumped to — flashed wherever it renders, then
  // dropped so the highlight doesn't linger on a panel reopened later.
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
            <button type="button" className={styles.backBtn} onClick={() => setBrowse(null)}>
              ← Engine
            </button>
            <h2 className={styles.viewTitle}>{BROWSE_TITLES[browse]}</h2>
          </div>
          {browse === "jobs" && <JobSchedules />}
          {browse === "plans" && (
            <>
              <PipelinePlans />
              <p className={styles.browseHint}>Engine-wide switches for plan-based stage composition.</p>
              <SystemSettings filterGroups={["plans"]} hideGroupTitle />
            </>
          )}
          {browse === "publishing" && <PublishingPanel />}
          {browse === "maintenance" && (
            <>
              <p className={styles.browseHint}>Global sweeps and destructive resets — run rarely.</p>
              <MaintenancePanel />
              <p className={styles.browseHint}>
                Link-validation, hygiene-review, assessment-backfill and merge-engine settings.
              </p>
              {/* Two blocks, not one call with both groups: the "Maintenance" group
                  title would just repeat this view's own heading, so it stays
                  hidden — while Retention needs its title to read as a section. */}
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
        <EngineMatrix
          key={nonce}
          initialView={initial.view}
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
