import EnrichmentSettings from "@/components/EnrichmentSettings";
import SystemSettings from "@/components/SystemSettings";
import { usePipelineOverview } from "@/hooks/useEngine";

import { EnrichmentGaps } from "./EnrichmentGaps";

import { ExtractStageConfig } from "./ExtractStageConfig";
import { FpNamesPanel } from "./FpNamesPanel";
import { ScoreStageConfig } from "./ScoreStageConfig";
import { CorrelationTuningPanel } from "./WorkbenchAdminPanel";
import styles from "./StagePanel.module.css";

const KIND_LABELS: Record<string, string> = {
  inline: "in fetch",
  pre: "pre-process",
  parallel: "parallel",
  post: "post-process",
  final: "final",
  side: "side channel",
};

/** Full-width stage settings panel: re-hosts today's per-stage settings
 *  components unchanged (the old Pipeline tab's stage panels), under the new
 *  header-driven console. One panel open at a time. */
export function StagePanel({
  stage,
  onClose,
  onViewErrored,
}: {
  stage: string;
  onClose: () => void;
  onViewErrored: (stage: string) => void;
}) {
  const { data: overview } = usePipelineOverview();
  const info = overview?.stages.find((s) => s.name === stage);

  return (
    <section className={styles.panel}>
      <div className={styles.head}>
        <h3 className={styles.name}>{stage.replace(/_/g, " ")}</h3>
        {info && <span className={styles.kind}>{KIND_LABELS[info.kind] ?? info.kind}</span>}
        <span className={styles.live}>LIVE — affects ingestion</span>
        {info && <span className={styles.desc}>{info.description}</span>}
        {info && info.kind !== "inline" && stage !== "enrich" && (
          <button type="button" className={styles.errLink} onClick={() => onViewErrored(stage)}>
            View {stage.replace(/_/g, " ")} runs below ↓
          </button>
        )}
        <button type="button" className={styles.close} onClick={onClose} title="Close stage settings">
          ✕
        </button>
      </div>
      <div className={styles.body}>
        {stage === "extract" && <ExtractStageConfig />}
        {stage === "score" && <ScoreStageConfig />}
        {stage === "autolink" && (
          <>
            <p className={styles.note}>
              Entity &amp; link cleanup lives in the table: flip the <strong>Proposals</strong> lens on
              the <strong>Links</strong> and <strong>AI entities</strong> tabs to review and apply autolink
              suggestions, or open <strong>Maintenance</strong> (top-right) for global sweeps.
            </p>
            <SystemSettings
              filterGroups={["autolink"]}
              flat
              excludeKeys={["autolinker_false_positive_names", "autolinker_blocked_surface_forms"]}
            />
            {/* Both name lists are comma strings (the curated one runs ~170
                entries) — rendered as tables instead of textareas nobody can read. */}
            <FpNamesPanel />
            <FpNamesPanel list="blocked" />
          </>
        )}
        {stage === "observables" && (
          <>
            <p className={styles.note}>
              The ledger's safety posture. <strong>AI capture mode</strong> is the big one:{" "}
              <strong>shadow</strong> (default) stages every AI-confirmed indicator as an entry
              candidate for review; <strong>capture</strong> lets AI confirmations create ledger
              rows directly. Outbound blocklists/TAXII live under <strong>Publishing</strong>{" "}
              (top-right).
            </p>
            <SystemSettings
              filterGroups={["observables"]}
              flat
              excludeKeys={[
                "observables_publish_enabled",
                "observables_publish_token",
                "observables_publish_min_confidence",
                "observables_publish_max_age_days",
              ]}
            />
          </>
        )}
        {(stage === "cooccurrence" || stage === "correlation") && <CorrelationTuningPanel />}
        {stage === "enrich" && (
          <>
            <EnrichmentSettings />
            {/* Entities missing key fields — one-click AI enrichment, folded onto
                the stage whose job is to fill them in. */}
            <EnrichmentGaps />
            <SystemSettings filterGroups={["enrichment", "api_keys"]} flat />
          </>
        )}
        {stage === "automate" && (
          <p className={styles.note}>
            Automation rules run as the pipeline's side channel — manage them on the{" "}
            <a href="/automation">Automation page</a>.
          </p>
        )}
        {["translate", "telegram_links", "requirements"].includes(stage) && (
          <p className={styles.note}>
            {info?.description ?? ""}
            {stage === "translate" &&
              " Per-feed translation is enabled on each feed's settings; the stage-level setting below is only the fallback target language."}
            {stage === "requirements" &&
              " Intelligence requirements themselves are managed on the Requirements page."}
          </p>
        )}
        {stage === "translate" && <SystemSettings filterGroups={["translation"]} flat hideGroupTitle />}
      </div>
    </section>
  );
}
