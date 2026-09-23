/**
 * Preset slash commands for the global copilot. Selecting one fills the input
 * with its `prompt` template so the user can tweak before sending — it never
 * auto-sends. Triggered by typing "/" at the start of an otherwise-empty input.
 */
export interface CopilotCommand {
  /** Stable id used for React keys and equality. */
  id: string;
  /** The "/name" shown in the menu and matched while filtering. */
  label: string;
  /** Short one-line description of what the command does. */
  hint: string;
  /** Template inserted into the input when the command is selected. */
  prompt: string;
  /**
   * Backend tool name (from TOOL_DEFINITIONS) this command needs to produce a
   * useful answer. Omitted for commands the model can answer directly from
   * context/conversation without a tool call. Used to hide the command when
   * that tool isn't in the copilot's enabled allowlist (Ollama only).
   */
  requiredTool?: string;
}

export const COPILOT_COMMANDS: CopilotCommand[] = [
  {
    id: "summarize",
    label: "/summarize",
    hint: "Summarize the most important threats for what you're viewing",
    prompt:
      "Summarize the most important threats and developments relevant to what I'm looking at.",
  },
  {
    id: "pivot",
    label: "/pivot",
    hint: "Show related actors, malware, CVEs, campaigns and their links",
    prompt:
      "Show the related threat actors, malware, CVEs, and campaigns, and how they connect.",
    requiredTool: "pivot_entity",
  },
  {
    id: "rules",
    label: "/rules",
    hint: "Draft Sigma detection rules with required log sources",
    prompt:
      "Draft Sigma detection rules for the technique(s) involved, with the log sources required.",
    requiredTool: "generate_detection_rules",
  },
  {
    id: "report",
    label: "/report",
    hint: "Draft a concise intelligence report",
    prompt:
      "Draft a concise intelligence report (executive summary, key findings, detection guidance).",
  },
  {
    id: "campaign",
    label: "/campaign",
    hint: "Propose a campaign to track this activity",
    prompt: "Propose a campaign to track this activity.",
    requiredTool: "create_campaign",
  },
  {
    id: "trending",
    label: "/trending",
    hint: "What's trending across your feeds in the last 24 hours",
    prompt: "What's trending across my feeds in the last 24 hours?",
    requiredTool: "get_trending_entities",
  },
  {
    id: "gaps",
    label: "/gaps",
    hint: "Find detection coverage gaps and what to build next",
    prompt:
      "Where are my detection coverage gaps for this, and what should I build next?",
    requiredTool: "check_detection_gaps",
  },
];

/**
 * Returns the commands whose label matches the text typed after the leading
 * "/". An empty query returns all commands. Matching is case-insensitive and
 * substring-based against the label (sans slash).
 *
 * `enabledTools` is the copilot's effective tool allowlist (null/undefined
 * when the provider is unrestricted, e.g. non-Ollama) — commands whose
 * `requiredTool` isn't in that list are hidden rather than matched.
 */
export function filterCopilotCommands(
  query: string,
  enabledTools?: string[] | null,
): CopilotCommand[] {
  const available = enabledTools
    ? COPILOT_COMMANDS.filter(
        (c) => !c.requiredTool || enabledTools.includes(c.requiredTool),
      )
    : COPILOT_COMMANDS;
  const q = query.trim().toLowerCase();
  if (!q) return available;
  return available.filter((c) => c.label.slice(1).toLowerCase().includes(q));
}
