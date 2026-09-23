import { useState } from "react";
import type { AIProvider } from "@/api/types";
import { useUpdateAIProvider } from "@/hooks/useAI";
import CopilotAuthCard from "./CopilotAuthCard";
import styles from "./AISettings.module.css";

// CLI knobs the Claude Code provider reads from config. Values are kept as
// strings while editing; empty string = unset (provider default applies).
type CliKnobs = {
  cli_path: string;
  timeout_seconds: string;
  cli_retries: string;
  max_budget_usd: string;
};

function knobsFrom(cfg: Record<string, unknown>): CliKnobs {
  return {
    cli_path: cfg.cli_path != null ? String(cfg.cli_path) : "",
    timeout_seconds: cfg.timeout_seconds != null ? String(cfg.timeout_seconds) : "",
    cli_retries: cfg.cli_retries != null ? String(cfg.cli_retries) : "",
    max_budget_usd: cfg.max_budget_usd != null ? String(cfg.max_budget_usd) : "",
  };
}

export default function ClaudeCodeConfigEditor({
  provider,
  onClose,
}: {
  provider: AIProvider;
  onClose: () => void;
}) {
  const updateProvider = useUpdateAIProvider();
  const cfg = (provider.config || {}) as Record<string, unknown>;
  const [knobs, setKnobs] = useState<CliKnobs>(() => knobsFrom(cfg));

  const setKnob = (key: keyof CliKnobs, value: string) =>
    setKnobs((prev) => ({ ...prev, [key]: value }));

  const handleSave = () => {
    const next: Record<string, unknown> = { ...cfg };
    delete next.cli_path;
    delete next.timeout_seconds;
    delete next.cli_retries;
    delete next.max_budget_usd;
    if (knobs.cli_path.trim()) next.cli_path = knobs.cli_path.trim();
    if (knobs.timeout_seconds.trim()) next.timeout_seconds = parseInt(knobs.timeout_seconds, 10);
    if (knobs.cli_retries.trim()) next.cli_retries = parseInt(knobs.cli_retries, 10);
    if (knobs.max_budget_usd.trim()) next.max_budget_usd = parseFloat(knobs.max_budget_usd);
    updateProvider.mutate({ id: provider.id, config: next }, { onSuccess: onClose });
  };

  return (
    <div className={styles.configPanel}>
      <CopilotAuthCard embedded />
      <table className={styles.configTable}>
        <thead>
          <tr>
            <th title="Path to the claude binary inside the CLI worker container.">CLI path</th>
            <th title="Per-request timeout in seconds. Empty = per-model default.">Timeout (s)</th>
            <th title="Retries on CLI subprocess timeout before failing the task.">Retries</th>
            <th title="Abort a run when the CLI reports spend above this many dollars.">
              Max budget (USD)
            </th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>
              <input
                placeholder="claude"
                value={knobs.cli_path}
                onChange={(e) => setKnob("cli_path", e.target.value)}
              />
            </td>
            <td>
              <input
                type="number"
                placeholder="per-model default"
                value={knobs.timeout_seconds}
                onChange={(e) => setKnob("timeout_seconds", e.target.value)}
              />
            </td>
            <td>
              <input
                type="number"
                placeholder="1"
                value={knobs.cli_retries}
                onChange={(e) => setKnob("cli_retries", e.target.value)}
              />
            </td>
            <td>
              <input
                type="number"
                step="0.1"
                placeholder="1.0"
                value={knobs.max_budget_usd}
                onChange={(e) => setKnob("max_budget_usd", e.target.value)}
              />
            </td>
          </tr>
        </tbody>
      </table>
      <p className={styles.hint}>
        Tool access is configured per task (assignment config), not here — agentic tasks like the
        copilot get their allowed tools from their seeded assignments.
      </p>
      <div className={styles.formActions}>
        <button className={styles.saveBtn} onClick={handleSave} disabled={updateProvider.isPending}>
          {updateProvider.isPending ? "Saving..." : "Save"}
        </button>
        <button className={styles.cancelBtn} onClick={onClose}>
          Cancel
        </button>
      </div>
    </div>
  );
}
