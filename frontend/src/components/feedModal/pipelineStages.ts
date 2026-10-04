import type { FeedFormValues, IntelMode } from "./useFeedForm";

/**
 * The feed's ingest pipeline, described as what actually runs.
 *
 * The old control was a five-way preset ("Full", "Selective", "Known entities
 * only", "Manual", "None") mapped onto two columns. Three of those labels were
 * false: the one-pass AI analysis that does most of the extraction today gates
 * only on `intel_extraction_mode === "none"`, so a feed set to "Known entities
 * only — match against existing database" or "Manual — only when triggered"
 * still had the AI read every article and create entities. `selective` and
 * `full` differ solely in whether *autolinking* applies a relevance pre-filter;
 * the AI pass uses its own global junk threshold either way.
 *
 * So the stages below are the real ones, each pointing at the field that
 * genuinely drives it. Two have no per-feed switch at all and say so rather
 * than pretending — that is the `scope: "global"` marker, and it is honest
 * information, not decoration.
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

export interface StageRow {
  id: StageId;
  label: string;
  detail: string;
  on: boolean;
  /** "feed" = this feed's own switch; "global" = engine-wide, shown read-only. */
  scope: "feed" | "global";
  /** Off because the master switch is off, or because it is a global. */
  disabled: boolean;
  /** Indented under the stage above it. */
  nested?: boolean;
  /** This stage can create entities that did not exist before. */
  writes?: boolean;
}

export function describeStages(values: FeedFormValues, aiEnabled: boolean): StageRow[] {
  const mode = values.intel_extraction_mode;
  const processing = mode !== "none";
  const autolink = processing && mode !== "manual";

  return [
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
        ? "Reads the article, judges the autolinks, and extracts TTPs, actors, malware, sectors, indicators and relationships. There is no per-feed switch — turn off “Process this feed” to stop it."
        : "Off engine-wide. Turn on “AI one pass” in Engine settings to enable it.",
      on: processing && aiEnabled,
      scope: "global",
      disabled: true,
      writes: true,
    },
    {
      id: "regex",
      label: "Regex enrichment",
      detail:
        "Standalone CVE pass with NVD hydration, plus TTP and mitigation IDs. Costs NVD API quota.",
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
      id: "tools",
      label: "Create tool entities",
      detail:
        "Off for advisory and rule-repository feeds — they name affected software, not tooling an adversary wielded.",
      on: processing && values.extract_tools,
      scope: "feed",
      disabled: !processing,
    },
    {
      id: "observables",
      label: "Observables ledger",
      detail:
        "Sights indicators already in the ledger by exact match. Regex alone never creates a ledger row.",
      on: processing,
      scope: "global",
      disabled: true,
    },
  ];
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
    case "regex":
      return { auto_extract_on_ingest: next };
    case "rules":
      return { extract_detection_rules: next };
    case "tools":
      return { extract_tools: next };
    default:
      // "ai" and "observables" have no per-feed field to write.
      return { intel_extraction_mode: mode };
  }
}

/** One sentence describing what a new article from this feed goes through. */
export function summarizeStages(values: FeedFormValues, aiEnabled: boolean): string {
  const mode = values.intel_extraction_mode;
  if (mode === "none") {
    return "Articles are ingested, sanitized and searchable. Nothing is extracted from them, and no entity is created or linked.";
  }

  const parts: string[] = [];
  if (mode !== "manual") {
    parts.push(
      mode === "selective"
        ? "matched against your catalog when it looks security-relevant"
        : "matched against your catalog"
    );
  }
  if (aiEnabled) parts.push("read by the AI");
  if (values.auto_extract_on_ingest) parts.push("enriched from NVD");
  parts.push("checked against the indicator ledger");

  let summary = `Every article is ${joinWords(parts)}.`;
  summary += aiEnabled
    ? " The AI may create entities you do not have yet."
    : " Nothing new is created — only what is already in your catalog gets linked.";
  if (values.extract_detection_rules) {
    summary += " Detection rules in the body are pulled out.";
  }
  return summary;
}

function joinWords(parts: string[]): string {
  if (parts.length <= 1) return parts[0] ?? "";
  if (parts.length === 2) return `${parts[0]} and ${parts[1]}`;
  return `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
}
