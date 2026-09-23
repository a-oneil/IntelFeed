import { useState } from "react";
import { toast } from "sonner";
import type { AIResult } from "@/api/types";
import { useAIResults, useAIResultHistory, useRunAIOnEntity } from "@/hooks/useAI";
import { useCreateEntryNote } from "@/hooks/useNotes";
import { useUIStore } from "@/stores/uiStore";
import { formatDate } from "@/utils/formatDate";
import { Chip } from "./primitives";
import styles from "./AIResultsDisplay.module.css";
import { AsyncStateLoading } from "@/components/AsyncState";

/** "Turn this AI result into…" actions — each opens the copilot pre-scoped. */
const TURN_INTO_ACTIONS: { key: string; label: string; instruction: string }[] = [
  { key: "campaign", label: "Campaign", instruction: "Propose a campaign to track the activity described above." },
  { key: "report", label: "Report", instruction: "Draft a concise intelligence report (executive summary, key findings, detection guidance) from the analysis above." },
  { key: "rules", label: "Detection rules", instruction: "Draft Sigma detection rules for the techniques in the analysis above, including the log sources required." },
  { key: "note", label: "Note", instruction: "Write a short analyst note capturing the key points above, and save it." },
];

interface AIResultsDisplayProps {
  targetType: string;
  targetId: string;
  staticResults?: AIResult[];
  /**
   * When provided (entry context), each card shows an "Ask a follow-up" button
   * that opens the AskAgentPanel seeded with a summary of that result.
   */
  onAskFollowUp?: (context: string) => void;
}

/** Build a plain-text summary of an AI result to seed a follow-up chat. */
function resultToContext(result: AIResult): string {
  const taskName = result.task_name || "AI result";
  const displayName = taskName.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  const parsed = result.parsed_result || {};
  const parts: string[] = [`**${displayName}**`];

  for (const [key, value] of Object.entries(parsed)) {
    if (key.startsWith("_")) continue;
    if (typeof value === "string" && value.trim()) {
      parts.push(`_${key.replace(/_/g, " ")}:_ ${value}`);
    } else if (Array.isArray(value) && value.every((v) => typeof v === "string")) {
      if (value.length) parts.push(`_${key.replace(/_/g, " ")}:_ ${(value as string[]).join(", ")}`);
    }
  }

  if (parts.length === 1) {
    parts.push("```json\n" + JSON.stringify(parsed, null, 2) + "\n```");
  }

  return parts.join("\n\n");
}

export function AIResultsDisplay({ targetType, targetId, staticResults, onAskFollowUp }: AIResultsDisplayProps) {
  const isStatic = !!staticResults;
  const { data: fetchedResults, isLoading } = useAIResults(
    isStatic ? undefined : targetType,
    isStatic ? undefined : targetId,
  );
  const rerun = useRunAIOnEntity();

  const results = isStatic ? staticResults : fetchedResults;

  if (!isStatic && isLoading) return null;
  if (!results || results.length === 0) return null;

  return (
    <div className={styles.container}>
      {results.map((result) => (
        <AIResultCard
          key={result.id}
          result={result}
          targetType={targetType}
          targetId={targetId}
          isRerunning={rerun.isPending}
          onRerun={() =>
            rerun.mutate({
              targetType,
              targetId,
              taskName: result.task_name || "",
              force: true,
            })
          }
          onAskFollowUp={onAskFollowUp ? () => onAskFollowUp(resultToContext(result)) : undefined}
          hideActions={isStatic}
        />
      ))}
    </div>
  );
}

function AIResultCard({
  result,
  targetType,
  targetId,
  isRerunning,
  onRerun,
  onAskFollowUp,
  hideActions,
}: {
  result: AIResult;
  targetType: string;
  targetId: string;
  isRerunning: boolean;
  onRerun: () => void;
  onAskFollowUp?: () => void;
  hideActions?: boolean;
}) {
  const [collapsed, setCollapsed] = useState(true);
  const [showHistory, setShowHistory] = useState(false);
  const [showTurnInto, setShowTurnInto] = useState(false);
  const openCopilotWith = useUIStore((s) => s.openCopilotWith);
  const createEntryNote = useCreateEntryNote();
  const taskName = result.task_name || "unknown";
  const displayName = taskName.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

  const handleSaveAsNote = () => {
    const parsed = result.parsed_result || {};
    // Plain summaries save as clean prose; richer results keep their structure
    // (minus the leading "**Display Name**" line, which becomes the note title).
    const body =
      typeof parsed.summary === "string" && parsed.summary.trim()
        ? parsed.summary.trim()
        : resultToContext(result).replace(/^\*\*.*?\*\*\n\n/, "");
    createEntryNote.mutate(
      { entryId: targetId, data: { title: displayName.slice(0, 500), content_markdown: body } },
      {
        onSuccess: () => toast.success("Saved as note"),
        onError: () => toast.error("Couldn't save note"),
      },
    );
  };

  const handleTurnInto = (instruction: string) => {
    const context =
      targetType === "entry"
        ? { entry_id: targetId }
        : { entity_type: targetType, entity_id: targetId };
    openCopilotWith({
      context,
      lockContext: true,
      prompt: `Based on this ${displayName}:\n\n${resultToContext(result)}\n\n${instruction}`,
    });
    setShowTurnInto(false);
  };

  return (
    <div className={styles.resultCard}>
      <div className={styles.resultHeader}>
        <button className={styles.resultToggle} onClick={() => setCollapsed(!collapsed)}>
          <strong>{displayName}</strong>
          <span className={styles.resultMeta}>
            {result.model_name && <span>{result.model_name}</span>}
            <span>{formatDate(result.created_at)}</span>
            {result.cost_estimate && <span>${result.cost_estimate}</span>}
          </span>
          <span className={styles.resultArrow}>{collapsed ? "\u25BE" : "\u25B4"}</span>
        </button>
        {!hideActions && (
          <div className={styles.resultActions}>
            <div className={styles.turnIntoWrap}>
              <button
                className={styles.followUpBtn}
                onClick={() => setShowTurnInto((v) => !v)}
                title="Turn this result into a campaign, report, rules, or note via the copilot"
              >
                Turn into &#9662;
              </button>
              {showTurnInto && (
                <>
                  <div
                    className={styles.turnIntoBackdrop}
                    onClick={() => setShowTurnInto(false)}
                  />
                  <div className={styles.turnIntoMenu}>
                    {TURN_INTO_ACTIONS.map((a) => (
                      <button
                        key={a.key}
                        className={styles.turnIntoItem}
                        onClick={() => handleTurnInto(a.instruction)}
                      >
                        {a.label}
                      </button>
                    ))}
                  </div>
                </>
              )}
            </div>
            {targetType === "entry" && (
              <button
                className={styles.followUpBtn}
                onClick={handleSaveAsNote}
                disabled={createEntryNote.isPending}
                title="Save this AI result as a note on the article"
              >
                Save as note
              </button>
            )}
            {onAskFollowUp && (
              <button
                className={styles.followUpBtn}
                onClick={onAskFollowUp}
                title="Ask the agent a follow-up about this result"
              >
                Ask a follow-up
              </button>
            )}
            <button
              className={styles.rerunBtn}
              onClick={onRerun}
              disabled={isRerunning}
              title="Re-run this task"
            >
              {isRerunning ? <span className={styles.spinner} /> : "\u21BB"}
            </button>
            <button
              className={`${styles.historyBtn} ${showHistory ? styles.historyBtnActive : ""}`}
              onClick={() => setShowHistory(!showHistory)}
              title="View history"
            >
              History
            </button>
          </div>
        )}
      </div>
      {!collapsed && result.parsed_result && (
        <ResultContent taskName={taskName} result={result.parsed_result} />
      )}
      {showHistory && (
        <HistoryPanel
          targetType={targetType}
          targetId={targetId}
          taskName={taskName}
        />
      )}
    </div>
  );
}

/**
 * Threat-assessment severity ramp. These are the literal colours the old
 * `.severity_*` classes used; they are deliberately raw hexes rather than the
 * `--entity-*` tokens they happen to resemble, because an AI severity verdict
 * is not an entity type and must not re-colour when entity themes change.
 */
const SEVERITY_TINTS: Record<string, string | undefined> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#22c55e",
};

export function ResultContent({
  taskName,
  result,
}: {
  taskName: string;
  result: Record<string, unknown>;
}) {
  if (result._extraction_status === "provider_error") {
    return <div className={styles.resultError}>{String(result._error || "Provider error")}</div>;
  }

  if (taskName === "article_summary" && result.summary) {
    return <p className={styles.resultText}>{String(result.summary)}</p>;
  }

  if (taskName === "threat_assessment") {
    const r = result as Record<string, string | string[]>;
    return (
      <div className={styles.resultStructured}>
        {r.severity && (
          <Chip
            tone={SEVERITY_TINTS[String(r.severity)] ? "toned" : "default"}
            tint={SEVERITY_TINTS[String(r.severity)]}
            className={styles.severityBadge}
          >
            {String(r.severity)}
          </Chip>
        )}
        {r.what && (
          <div className={styles.resultBlock}>
            <strong>What happened:</strong>
            <p>{String(r.what)}</p>
          </div>
        )}
        {r.so_what && (
          <div className={styles.resultBlock}>
            <strong>So what:</strong>
            <p>{String(r.so_what)}</p>
          </div>
        )}
        {r.executive_briefing && (
          <div className={styles.resultBlock}>
            <strong>Executive briefing:</strong>
            <p>{String(r.executive_briefing)}</p>
          </div>
        )}
        {Array.isArray(r.recommended_actions) && r.recommended_actions.length > 0 && (
          <div className={styles.resultBlock}>
            <strong>Recommended actions:</strong>
            <ul className={styles.resultList}>
              {(r.recommended_actions as string[]).map((action, i) => (
                <li key={i}>{action}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    );
  }

  if (taskName === "video_transcript_summary") {
    const r = result as Record<string, string | string[]>;
    return (
      <div className={styles.resultStructured}>
        {r.summary && (
          <div className={styles.resultBlock}>
            <strong>Summary:</strong>
            <p>{String(r.summary)}</p>
          </div>
        )}
        {Array.isArray(r.key_topics) && r.key_topics.length > 0 && (
          <div className={styles.resultBlock}>
            <strong>Key topics:</strong>
            <div className={styles.resultPills}>
              {(r.key_topics as string[]).map((topic, i) => (
                <Chip key={i} pill>{topic}</Chip>
              ))}
            </div>
          </div>
        )}
        {Array.isArray(r.security_takeaways) && r.security_takeaways.length > 0 && (
          <div className={styles.resultBlock}>
            <strong>Security takeaways:</strong>
            <ul className={styles.resultList}>
              {(r.security_takeaways as string[]).map((t, i) => (
                <li key={i}>{t}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    );
  }

  // If the result has a summary field, render it as text (covers intelligence_briefing etc.)
  if (result.summary && typeof result.summary === "string") {
    return <p className={styles.resultText}>{String(result.summary)}</p>;
  }

  // If the result has a "raw" string field, render it as formatted text
  if (result.raw && typeof result.raw === "string") {
    return <p className={styles.resultText}>{String(result.raw)}</p>;
  }

  // Try to render any result with string values as structured blocks
  const stringEntries = Object.entries(result).filter(
    ([k, v]) => typeof v === "string" && !k.startsWith("_") && v.length > 0
  );
  if (stringEntries.length > 0 && stringEntries.length <= 10) {
    return (
      <div className={styles.resultStructured}>
        {stringEntries.map(([key, value]) => (
          <div key={key} className={styles.resultBlock}>
            <strong>{key.replace(/_/g, " ")}:</strong>
            <p>{String(value)}</p>
          </div>
        ))}
      </div>
    );
  }

  // Generic JSON display as last resort
  return (
    <pre className={styles.resultJson}>
      {JSON.stringify(result, null, 2)}
    </pre>
  );
}

function HistoryPanel({
  targetType,
  targetId,
  taskName,
}: {
  targetType: string;
  targetId: string;
  taskName: string;
}) {
  const { data: history, isLoading } = useAIResultHistory(targetType, targetId, taskName);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (isLoading) return <AsyncStateLoading label="Loading history…" compact />;
  if (!history || history.length <= 1) return <div className={styles.historyList}>No previous runs.</div>;

  return (
    <div className={styles.historyList}>
      {history.map((item) => (
        <div key={item.id}>
          <div
            className={`${styles.historyItem} ${item.is_current ? styles.historyCurrent : ""}`}
            onClick={() => setExpandedId(expandedId === item.id ? null : item.id)}
          >
            {formatDate(item.created_at)}
            {item.model_name && ` — ${item.model_name}`}
            {item.is_current && " (current)"}
          </div>
          {expandedId === item.id && item.parsed_result && (
            <ResultContent taskName={taskName} result={item.parsed_result} />
          )}
        </div>
      ))}
    </div>
  );
}
