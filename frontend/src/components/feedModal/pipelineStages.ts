import type { FeedPipeline } from "@/api/types";
import type { FeedFormValues, IntelMode } from "./useFeedForm";

/**
 * The feed's ingest pipeline, described as the stages that actually run.
 * This replaces a five-way preset ("Full", "Selective", "Known entities only", "Manual", "None") mapped onto two columns, because three of those labels were false. The one-pass AI analysis, which does most of the extraction, is gated only on `intel_extraction_mode === "none"`, so a feed set to "Known entities only — match against existing database" or "Manual — only when triggered" still had the AI read every article and create entities. `selective` and `full` differ only in whether *autolinking* applies a relevance pre-filter; the AI pass uses its own global junk threshold either way.
 * Each stage below is a real one and points at the field that drives it.
 * Only settings you can change get a row. The observables ledger scan has no setting of its own (it follows "Analyze this feed"), so it gets no checkbox and is reported in the summary sentence instead.
 * Two things can take a listed stage out of this pane's control, and the row says so when either applies:
 *   - `ai_one_pass_enabled` is off engine-wide; no per-feed setting turns the AI back on.
 *   - a PipelinePlan at global, category or feed scope overrides the stage while `pipeline_engine_enabled` is on. The plan takes priority over the Feed booleans, so a checkbox here would write a value nothing reads.
 */
export type StageId =
  | "master"
  | "autolink"
  | "relevance"
  | "ai"
  | "regex"
  | "rules"
  | "tools";

export type StageScope = "feed" | "global" | "plan";

export interface StageRow {
  id: StageId;
  label: string;
  detail: string;
  on: boolean;
  scope: StageScope;
  /** When scope is "plan", which scope's plan decided it. */
  planScope?: "global" | "category" | "feed";
  disabled: boolean;
  nested?: boolean;
  /** This stage can create entities that did not exist before. */
  writes?: boolean;
}

/** Which plan stage, if any, governs each row here. */
const PLAN_STAGE: Partial<Record<StageId, string>> = {
  autolink: "autolink",
  relevance: "autolink",
  regex: "extract",
  rules: "extract",
};

interface Context {
  aiEnabled: boolean;
  pipeline?: FeedPipeline;
}

function planOverride(id: StageId, ctx: Context): "global" | "category" | "feed" | null {
  const stage = PLAN_STAGE[id];
  if (!stage || !ctx.pipeline?.engine_enabled) return null;
  const by = ctx.pipeline.decided_by[stage];
  return by && by !== "legacy" ? by : null;
}

/**
 * What each stage is called and what it does, kept in one place.
 * Both the feed modal and the category modal describe these settings; sharing the wording keeps them from describing the same pipeline differently. The category modal renders these as bulk selects; the feed modal renders them as checkboxes.
 */
export const STAGE_COPY: Record<StageId, { label: string; detail: string }> = {
  master: {
    label: "Analyze this feed",
    detail:
      "When off, articles still arrive, stay searchable, get a priority score, join story threads and run through your automation rules. Nothing is tagged or created from them: no entities, CVEs, indicators or detection rules, regardless of the switches below.",
  },
  autolink: {
    label: "Tag articles with entities you already track",
    detail:
      "Matches names and aliases from your catalog (actors, malware, vendors, products, tools) plus CVE and ATT&CK IDs. Links what exists, with one exception: a CVE ID you don't have yet becomes a new CVE record.",
  },
  relevance: {
    label: "Skip off-topic articles",
    detail:
      "Scores each article on security keywords, matched as whole words, and skips tagging the ones with no security vocabulary at all: product news, earnings, politics. Off, every article gets tagged. The AI skips those articles either way; the cut-off is the Extraction Junk Gate setting.",
  },
  ai: {
    label: "Let the AI read each article",
    detail:
      "Finds TTPs, actors, malware, sectors, indicators and relationships, and double-checks the tags above. This is what finds entities you do not have yet. With AI off, common-word names aren't tagged.",
  },
  tools: {
    label: "Create records for new tools",
    detail:
      "When off, the AI still tags tools already in your catalog but never adds a new one. Tagging from the catalog runs either way. Turn it off for advisory and rule-repository feeds, which list affected software rather than attacker tooling.",
  },
  regex: {
    label: "Fetch CVE details from NVD",
    detail:
      "Adds the CVSS score, severity, description and affected products for CVEs named here, and picks up MITRE mitigation IDs. Off, a CVE first seen on this feed stays a bare number until a background sweep fills it in. Uses NVD API quota.",
  },
  rules: {
    label: "Save detection rules found in the text",
    detail:
      "Sigma, YARA, Snort/Suricata and Elastic rule files, and SPL, KQL, EQL and ES|QL queries in an article's code blocks, become rules in your library, named after the article.",
  },
};

export function describeStages(values: FeedFormValues, ctx: Context): StageRow[] {
  const { aiEnabled, pipeline } = ctx;
  const mode = values.intel_extraction_mode;
  const processing = mode !== "none";
  const autolink = processing && mode !== "manual";
  const aiRunning = processing && aiEnabled && values.ai_analysis_enabled;

  const rows: StageRow[] = [
    {
      id: "master",
      ...STAGE_COPY.master,
      on: processing,
      scope: "feed",
      disabled: false,
    },
    {
      id: "autolink",
      ...STAGE_COPY.autolink,
      on: autolink,
      scope: "feed",
      disabled: !processing,
    },
    {
      id: "relevance",
      ...STAGE_COPY.relevance,
      on: autolink && mode === "selective",
      scope: "feed",
      disabled: !autolink,
      nested: true,
    },
    {
      id: "ai",
      label: STAGE_COPY.ai.label,
      detail: aiEnabled
        ? STAGE_COPY.ai.detail
        : "Switched off for the whole instance. Turn on “AI one pass” in Engine settings to enable it.",
      on: processing && aiEnabled && values.ai_analysis_enabled,
      scope: aiEnabled ? "feed" : "global",
      disabled: !processing || !aiEnabled,
      writes: true,
    },
    {
      // Not a stage of its own: `extract_tools` is read only inside `store_entry_analysis` (`_tool_mode_for_entry`), so it is a sub-switch of the AI pass and does nothing when that is off.
      id: "tools",
      ...STAGE_COPY.tools,
      on: aiRunning && values.extract_tools,
      scope: "feed",
      disabled: !aiRunning,
      nested: true,
      writes: true,
    },
    {
      id: "regex",
      ...STAGE_COPY.regex,
      on: processing && values.auto_extract_on_ingest,
      scope: "feed",
      disabled: !processing,
      writes: true,
    },
    {
      id: "rules",
      ...STAGE_COPY.rules,
      on: processing && values.extract_detection_rules,
      scope: "feed",
      disabled: !processing,
    },
  ];

  if (!pipeline?.engine_enabled) return rows;

  // A plan takes priority over the Feed booleans, so show its value and disable the checkbox, which would write a value nothing reads. Mode "none" in turn takes priority over the plan: the autolink and extract tasks both check it themselves, so a plan that enables them on a feed that is not analyzed still runs nothing.
  return rows.map((row) => {
    const scope = planOverride(row.id, ctx);
    if (!scope || !processing) return row;
    const stage = PLAN_STAGE[row.id]!;
    const planned = pipeline.stages[stage]?.enabled ?? row.on;
    return {
      ...row,
      scope: "plan" as StageScope,
      planScope: scope,
      on: row.id === "relevance" ? row.on && planned : planned,
      disabled: true,
    };
  });
}

/** The partial form update a stage toggle implies. */
export function toggleStage(
  values: FeedFormValues,
  id: StageId,
  next: boolean
): Partial<FeedFormValues> {
  const mode = values.intel_extraction_mode;

  switch (id) {
    case "master":
      // When turned back on, use the default mode: the mode from before the feed was switched off is not stored anywhere.
      return { intel_extraction_mode: next ? "selective" : "none" };
    case "autolink":
      return { intel_extraction_mode: (next ? "selective" : "manual") as IntelMode };
    case "relevance":
      return { intel_extraction_mode: (next ? "selective" : "full") as IntelMode };
    case "ai":
      return { ai_analysis_enabled: next };
    case "regex":
      return { auto_extract_on_ingest: next };
    case "rules":
      return { extract_detection_rules: next };
    case "tools":
      return { extract_tools: next };
    default:
      return { intel_extraction_mode: mode };
  }
}

/** One sentence describing what a new article from this feed goes through. */
export function summarizeStages(values: FeedFormValues, ctx: Context): string {
  const rows = describeStages(values, ctx);
  const on = (id: StageId) => rows.find((r) => r.id === id)?.on ?? false;

  if (!on("master")) {
    return "Articles still arrive, are cleaned up, stay searchable, get a priority score, join story threads and run through your automation rules. Nothing is pulled out of them: no tagging, no AI, no indicator matching, no CVE lookups or saved rules, and no entity created or linked.";
  }

  const parts: string[] = [];
  if (on("autolink")) {
    parts.push(
      on("relevance")
        ? "tagged with entities you already track, when it looks security-relevant"
        : "tagged with entities you already track"
    );
  }
  if (on("ai")) parts.push("read by the AI");
  if (on("regex")) parts.push("filled in from NVD");

  // The IOC check has no row because it has no switch of its own, but it follows "Analyze this feed", so the sentence only claims it when that is on (the early return above covers the off case).
  parts.push("checked against your IOC list");

  let summary = `Every article is ${joinWords(parts)}.`;
  summary += on("ai")
    ? " The AI can add entities you do not have yet."
    : on("autolink")
      ? " Nothing new is added except CVE records for CVE IDs you don't have yet. Everything else must already be in your catalog."
      : " Nothing new is added. Only what is already in your catalog gets linked.";
  if (on("rules")) summary += " Detection rules written out in the text are saved to your library.";
  return summary;
}

function joinWords(parts: string[]): string {
  if (parts.length <= 1) return parts[0] ?? "";
  if (parts.length === 2) return `${parts[0]} and ${parts[1]}`;
  return `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
}
