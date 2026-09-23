import { useState } from "react";
import { useUIStore } from "@/stores/uiStore";
import type { TTP, CVE, ThreatActor, MalwareFamily, AITask, AIResult } from "@/api/types";
import {
  useEntryTTPs,
  useEntryCVEs,
  useEntryThreatActors,
  useEntryMalware,
  useGenerateDetectionRules,
  useDetectionRules,
} from "@/hooks/useIntelligence";
import { AskAgentPanel } from "./AskAgentPanel";
import { AIResultsDisplay } from "./AIResultsDisplay";
import { AIAnalysisSection } from "./AIAnalysisSection";
import type { RunTaskResult } from "./AIAnalysisSection";
import { CampaignMenuButton } from "./CampaignMenuButton";
import styles from "./WorkbenchPanel.module.css";
import aiStyles from "./EntryAIPanel.module.css";

interface EntryAIPanelProps {
  entryId: string;
  entryTitle: string;
  /** Read-only mode for shared pages — hides copilot/report UI, uses overrides */
  readOnly?: boolean;
  /** AI overrides for shared pages */
  aiTasks?: AITask[];
  aiRunTaskFn?: (taskName: string) => Promise<RunTaskResult>;
  aiCompletedTasks?: Set<string>;
  aiStaticResults?: AIResult[];
  aiAskAgentFn?: (question: string, history: Array<{ role: string; content: string }>) => Promise<{ answer: string }>;
}

/**
 * The reader's AI tab: suggested next actions, one-click AI task rows,
 * the Ask Agent chat, and persisted AI results for this entry.
 */
export default function EntryAIPanel({
  entryId,
  entryTitle,
  readOnly,
  aiTasks,
  aiRunTaskFn,
  aiCompletedTasks,
  aiStaticResults,
  aiAskAgentFn,
}: EntryAIPanelProps) {
  const [newAIResults, setNewAIResults] = useState<AIResult[]>([]);
  // Shared-page (readOnly) only: the slim Ask Agent chat. Authenticated users
  // get the global copilot instead (tool-calling, article pinned as context).
  const [showAskAgent, setShowAskAgent] = useState(false);

  // In readOnly mode, pass empty entryId to hooks so they don't fire (enabled: !!entryId)
  const fetchId = readOnly ? "" : entryId;
  const { data: ttps } = useEntryTTPs(fetchId);
  const { data: cves } = useEntryCVEs(fetchId);
  const { data: actors } = useEntryThreatActors(fetchId);
  const { data: malware } = useEntryMalware(fetchId);
  const { data: rulesData } = useDetectionRules(readOnly ? { entry_id: "" } : { entry_id: entryId });
  const generateRules = useGenerateDetectionRules();

  const ruleCount = rulesData?.items?.length ?? 0;
  const hasDetectionGap = ((ttps?.length ?? 0) > 0 || (cves?.length ?? 0) > 0) && ruleCount === 0;

  const handleGenerateRules = () => {
    generateRules.mutate({ entryId, ruleTypes: ["sigma", "splunk_spl"] });
  };

  return (
    <div className={styles.panel}>
      <div className={styles.actionBarPrimary}>
        <button
          className={styles.actionBtnPrimary}
          onClick={() => {
            if (readOnly) {
              setShowAskAgent((v) => !v);
            } else {
              // Pin the article in the global copilot (content is injected
              // server-side) and let the analyst ask their own question.
              useUIStore.getState().openCopilotWith({
                context: { entry_id: entryId, label: entryTitle },
                lockContext: true,
              });
            }
          }}
        >
          {readOnly ? "Ask Agent" : "Ask Copilot"}
        </button>
        {!readOnly && (
          <button
            className={styles.actionBtn}
            onClick={() => {
              useUIStore.getState().openSendToReport({
                entryIds: [entryId],
                label: entryTitle,
                wizardState: { sourceType: "entry", entryId, entryTitle },
              });
            }}
            title="Add this article to a report draft or start a new report"
          >
            Report
          </button>
        )}
      </div>

      <div className={styles.scrollArea}>
        {/* Suggested next actions — rule-based, derived from existing signals (no AI call) */}
        {!readOnly && (
          <SuggestedActions
            entryId={entryId}
            entryTitle={entryTitle}
            ttps={ttps || []}
            cves={cves || []}
            actors={actors || []}
            malware={malware || []}
            hasDetectionGap={hasDetectionGap}
            onGenerateRules={handleGenerateRules}
            generatingRules={generateRules.isPending}
          />
        )}

        {/* AI task action rows */}
        <AIAnalysisSection
          entryId={entryId}
          tasks={aiTasks}
          runTaskFn={aiRunTaskFn}
          completedTasks={aiCompletedTasks}
          onTaskComplete={readOnly ? (data) => {
            setNewAIResults((prev) => [...prev, {
              id: crypto.randomUUID(),
              entry_id: entryId,
              target_type: "entry",
              target_id: entryId,
              is_current: true,
              task_id: "",
              task_name: data.task_name,
              provider_id: null,
              model_name: data.model_name,
              parsed_result: data.result,
              tokens_input: null,
              tokens_output: null,
              cost_estimate: data.cost_estimate,
              processing_time_ms: null,
              created_at: new Date().toISOString(),
            }]);
          } : undefined}
        />

        {/* Shared-page Ask Agent chat (unauthenticated — no copilot access) */}
        {readOnly && showAskAgent && (
          <AskAgentPanel
            entryId={entryId}
            onClose={() => setShowAskAgent(false)}
            askFn={aiAskAgentFn}
          />
        )}

        {/* Persisted AI Results */}
        <AIResultsDisplay
          targetType="entry"
          targetId={readOnly ? "" : entryId}
          staticResults={readOnly ? [...(aiStaticResults || []), ...newAIResults] : undefined}
          onAskFollowUp={readOnly ? undefined : (context) => {
            // Follow up in the copilot: pin the article and open with the
            // result inline so the thread starts from what was generated.
            useUIStore.getState().openCopilotWith({
              context: { entry_id: entryId, label: entryTitle },
              lockContext: true,
              prompt: `${context}\n\n---\nThat is an AI result generated for the pinned article. What stands out, and what should I dig into next?`,
            });
          }}
        />
      </div>
    </div>
  );
}

/* ─── Suggested Actions ─── */

/**
 * Rule-based "next actions" derived purely from the entry's existing enrichment
 * signals (TTPs, CVEs, actors, malware, linked rules). No per-entry AI call is
 * made to compute these — each suggestion just routes to an existing action
 * (rule generation, the copilot, or the campaign flow). Shows 1–3 suggestions;
 * renders nothing when none apply.
 */
function SuggestedActions({
  entryId,
  entryTitle,
  ttps,
  cves,
  actors,
  malware,
  hasDetectionGap,
  onGenerateRules,
  generatingRules,
}: {
  entryId: string;
  entryTitle: string;
  ttps: TTP[];
  cves: CVE[];
  actors: ThreatActor[];
  malware: MalwareFamily[];
  hasDetectionGap: boolean;
  onGenerateRules: () => void;
  generatingRules: boolean;
}) {
  const openCopilotWith = useUIStore((s) => s.openCopilotWith);

  // Pick the single most notable CVE to anchor a detection question:
  // KEV > highest EPSS > highest CVSS. Only counts if it clears a risk bar.
  const notableCve = (() => {
    const ranked = [...cves]
      .filter((c) => {
        const cvss = c.cvss_score ?? 0;
        const epss = Number(c.epss_score ?? 0);
        return c.is_kev || cvss >= 7.0 || epss >= 0.1;
      })
      .sort((a, b) => {
        if (!!b.is_kev !== !!a.is_kev) return b.is_kev ? 1 : -1;
        const epssDiff = Number(b.epss_score ?? 0) - Number(a.epss_score ?? 0);
        if (epssDiff !== 0) return epssDiff;
        return (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
      });
    return ranked[0];
  })();

  const notableActor = actors[0];

  interface Suggestion {
    key: string;
    label: string;
    /** Short accent-colored action verb rendered on the right (e.g. "Gen Rules"). */
    action: string;
    icon: React.ReactNode;
    onClick: () => void;
    disabled?: boolean;
  }

  const suggestions: Suggestion[] = [];

  // 1. Detection opportunity: has TTPs/CVEs but no linked detection rule.
  if (hasDetectionGap) {
    suggestions.push({
      key: "gen-rules",
      label: ttps.length > 0 ? `${ttps.length} TTP${ttps.length === 1 ? "" : "s"} but no detection rules` : "CVEs but no detection rules",
      action: generatingRules ? "Generating…" : "Gen Rules →",
      icon: ICON_SHIELD,
      onClick: onGenerateRules,
      disabled: generatingRules,
    });
  }

  // 2. High-signal CVE → ask the copilot how to detect exploitation.
  if (notableCve) {
    suggestions.push({
      key: "detect-cve",
      label: `Detect ${notableCve.cve_id} exploitation`,
      action: "Ask →",
      icon: ICON_SPARKLE,
      onClick: () =>
        openCopilotWith({
          context: { entry_id: entryId },
          lockContext: true,
          prompt: `How do I detect exploitation of ${notableCve.cve_id}? Suggest log sources and detection logic based on this article.`,
        }),
    });
  }

  // 3. Notable threat actor → ask the copilot for a briefing.
  if (notableActor) {
    suggestions.push({
      key: "brief-actor",
      label: `Brief me on ${notableActor.name}`,
      action: "Ask →",
      icon: ICON_SPARKLE,
      onClick: () =>
        openCopilotWith({
          context: { entry_id: entryId },
          lockContext: true,
          prompt: `Give me a concise briefing on ${notableActor.name}: known TTPs, targeting, and what this article adds.`,
        }),
    });
  }

  // 4. Fallback: rich intel article with entities but no sharper action above.
  if (suggestions.length === 0 && (ttps.length > 0 || cves.length > 0)) {
    suggestions.push({
      key: "analyze",
      label: "Ask copilot to analyze this",
      action: "Ask →",
      icon: ICON_SPARKLE,
      onClick: () =>
        openCopilotWith({
          context: { entry_id: entryId },
          lockContext: true,
          prompt: `Analyze this article ("${entryTitle}") for me: key threats, TTPs, IOCs, and detection opportunities.`,
        }),
    });
  }

  // Named actors/malware present → offer to track this in a campaign
  // (rendered as its own chip with the campaign dropdown attached).
  const showCampaignChip = actors.length > 0 || malware.length > 0;

  if (suggestions.length === 0 && !showCampaignChip) return null;

  // Keep it unobtrusive — at most three suggestions (campaign chip included).
  const shown = suggestions.slice(0, showCampaignChip ? 2 : 3);

  return (
    <div className={aiStyles.suggested}>
      <div className={aiStyles.suggestedLabel}>Suggested</div>
      {shown.map((s) => (
        <button
          key={s.key}
          className={aiStyles.suggestedRow}
          onClick={s.onClick}
          disabled={s.disabled}
          title={s.label}
        >
          {s.icon}
          <span className={aiStyles.suggestedText}>{s.label}</span>
          <span className={aiStyles.suggestedGo}>{s.action}</span>
        </button>
      ))}
      {showCampaignChip && (
        <CampaignMenuButton entryId={entryId} buttonClassName={aiStyles.suggestedRow} title="Add to a campaign">
          {ICON_FOLDER}
          <span className={aiStyles.suggestedText}>Track this in a campaign</span>
          <span className={aiStyles.suggestedGo}>Add →</span>
        </CampaignMenuButton>
      )}
    </div>
  );
}

const ICON_SPARKLE = (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 3v4M12 17v4M3 12h4M17 12h4M6.3 6.3l2.8 2.8M14.9 14.9l2.8 2.8M17.7 6.3l-2.8 2.8M9.1 14.9l-2.8 2.8" />
  </svg>
);

const ICON_SHIELD = (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 2l8 3v6c0 5-3.4 8.5-8 11-4.6-2.5-8-6-8-11V5l8-3z" />
    <path d="M9 12l2 2 4-4" />
  </svg>
);

const ICON_FOLDER = (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z" />
    <path d="M12 11v4M10 13h4" />
  </svg>
);
