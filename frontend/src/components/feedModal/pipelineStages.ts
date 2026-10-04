import type { FeedPipeline } from "@/api/types";
import type { FeedFormValues, IntelMode } from "./useFeedForm";

/**
 * The feed's ingest pipeline, described as what actually runs.
 *
 * The old control was a five-way preset ("Full", "Selective", "Known entities
 * only", "Manual", "None") mapped onto two columns. Three of those labels were
 * false: the one-pass AI analysis that does most of the extraction today gated
 * only on `intel_extraction_mode === "none"`, so a feed set to "Known entities
 * only — match against existing database" or "Manual — only when triggered"
 * still had the AI read every article and create entities. `selective` and
 * `full` differ solely in whether *autolinking* applies a relevance pre-filter;
 * the AI pass uses its own global junk threshold either way.
 *
 * So the stages below are the real ones, each pointing at the field that
 * genuinely drives it.
 *
 * Two things can take a stage out of this pane's hands, and both say so rather
 * than pretending:
 *   - `ai_one_pass_enabled` off engine-wide — no per-feed setting revives it.
 *   - a PipelinePlan at global, category or feed scope overriding the stage
 *     once `pipeline_engine_enabled` is on. The plan wins over the Feed
 *     booleans, so the checkbox here would be writing a value nothing reads.
 */
export type StageId =
  | "master"
  | "autolink"
  | "relevance"
  | "ai"
  | "regex"
  | "rules"
  | "tools"
  | "observables";

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
  observables: "observables",
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

export function describeStages(values: FeedFormValues, ctx: Context): StageRow[] {
  const { aiEnabled, pipeline } = ctx;
  const mode = values.intel_extraction_mode;
  const processing = mode !== "none";
  const autolink = processing && mode !== "manual";
  const aiRunning = processing && aiEnabled && values.ai_analysis_enabled;

  const rows: StageRow[] = [
    {
      id: "master",
      label: "Process this feed",
      detail:
        "Off ingests and indexes articles but extracts nothing — no entity is created, linked or scored.",
      on: processing,
      scope: "feed",
      disabled: false,
    },
    {
      id: "autolink",
      label: "Autolink known entities",
      detail:
        "Dictionary scan for actors, malware, CVEs, TTPs, vendors, products and tools already in your catalog.",
      on: autolink,
      scope: "feed",
      disabled: !processing,
    },
    {
      id: "relevance",
      label: "Only security-relevant articles",
      detail:
        "Scores each article against a keyword filter first and skips autolinking below the threshold.",
      on: autolink && mode === "selective",
      scope: "feed",
      disabled: !autolink,
      nested: true,
    },
    {
      id: "ai",
      label: "AI analysis (one pass)",
      detail: aiEnabled
        ? "Reads the article, judges the autolinks, and extracts TTPs, actors, malware, sectors, indicators and relationships."
        : "Off engine-wide. Turn on “AI one pass” in Engine settings before this does anything.",
      on: processing && aiEnabled && values.ai_analysis_enabled,
      scope: aiEnabled ? "feed" : "global",
      disabled: !processing || !aiEnabled,
      writes: true,
    },
    {
      // Not a stage of its own: `extract_tools` is read only inside
      // `apply_analysis_results`, so it is a sub-switch of the AI pass and does
      // nothing at all when that is off.
      id: "tools",
      label: "Create tool entities",
      detail:
        "Let the AI mint Tool rows from what it read. Off for advisory and rule-repository feeds — they name affected software, not tooling an adversary wielded. Entries the AI classes as an advisory are skipped either way.",
      on: aiRunning && values.extract_tools,
      scope: "feed",
      disabled: !aiRunning,
      nested: true,
      writes: true,
    },
    {
      id: "regex",
      label: "Look up CVEs in NVD",
      detail:
        "Fills in CVSS score, severity, description and affected products for CVEs named here. Without it a newly seen CVE stays a bare ID until a later enrichment sweep reaches it. Also pulls MITRE mitigation IDs. Costs NVD API quota.",
      on: processing && values.auto_extract_on_ingest,
      scope: "feed",
      disabled: !processing,
      writes: true,
    },
    {
      id: "rules",
      label: "Detection rule extraction",
      detail: "Pulls Sigma, YARA, SPL, Elastic and KQL rules out of the article body.",
      on: processing && values.extract_detection_rules,
      scope: "feed",
      disabled: !processing,
    },
    {
      // Genuinely ungated: `_scan_entry_observables` loads the entry and never
      // looks at the feed, so this runs for every entry on every feed — even
      // one switched off above. Showing it dim with the master switch would be
      // the same kind of lie this pane exists to remove.
      id: "observables",
      label: "Observables ledger",
      detail:
        "Runs on every article from every feed. Stages indicator candidates and sights values already in the ledger by exact match; regex alone never creates a ledger row.",
      on: true,
      scope: "global",
      disabled: true,
    },
  ];

  if (!pipeline?.engine_enabled) return rows;

  // A plan outranks the Feed booleans, so show its value and stop offering a
  // checkbox that would write somewhere nothing reads.
  return rows.map((row) => {
    const scope = planOverride(row.id, ctx);
    if (!scope) return row;
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
      // Coming back on, land on the default rather than whatever it was before
      // the feed was switched off — there is nowhere to remember that.
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
      // "observables" has no per-feed field to write.
      return { intel_extraction_mode: mode };
  }
}

/** One sentence describing what a new article from this feed goes through. */
export function summarizeStages(values: FeedFormValues, ctx: Context): string {
  const rows = describeStages(values, ctx);
  const on = (id: StageId) => rows.find((r) => r.id === id)?.on ?? false;

  if (!on("master")) {
    return "Articles are ingested, sanitized and searchable, and still checked against the indicator ledger. Nothing else is extracted, and no entity is created or linked.";
  }

  const parts: string[] = [];
  if (on("autolink")) {
    parts.push(
      on("relevance")
        ? "matched against your catalog when it looks security-relevant"
        : "matched against your catalog"
    );
  }
  if (on("ai")) parts.push("read by the AI");
  if (on("regex")) parts.push("enriched from NVD");
  if (on("observables")) parts.push("checked against the indicator ledger");

  let summary = parts.length
    ? `Every article is ${joinWords(parts)}.`
    : "Articles are ingested and indexed only.";
  summary += on("ai")
    ? " The AI may create entities you do not have yet."
    : " Nothing new is created — only what is already in your catalog gets linked.";
  if (on("rules")) summary += " Detection rules in the body are pulled out.";
  return summary;
}

function joinWords(parts: string[]): string {
  if (parts.length <= 1) return parts[0] ?? "";
  if (parts.length === 2) return `${parts[0]} and ${parts[1]}`;
  return `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
}
