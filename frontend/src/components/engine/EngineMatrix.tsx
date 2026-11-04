import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import api from "@/api/client";
import { useFeedHealth } from "@/hooks/useAnalytics";
import { useEntityLinkStats } from "@/hooks/useAutolinking";
import {
  ENGINE_WINDOWS,
  type EngineWindow,
  engineWindowHours,
  type ProcessingEntry,
  type ProcessingOutputs,
  type ProcessingStageCell,
  useEngineProcessing,
  useRetryPipelineErrors,
  usePipelineOverview,
  usePipelinePlans,
  useUpsertPlan,
} from "@/hooks/useEngine";
import { useExtractionStats } from "@/hooks/useExtraction";
import { useHygieneStats } from "@/hooks/useHygiene";
import { Chip } from "@/components/primitives/Chip";
import { Hint } from "@/components/primitives";
import { useFeeds } from "@/hooks/useFeeds";
import { useUIStore } from "@/stores/uiStore";

import { FeedHealthView } from "@/components/FeedHealthView";
import SystemSettings from "@/components/SystemSettings";

import { AutolinkingSection } from "./AutolinkingSection";
import { EngineSettingsSearch } from "./EngineSettingsSearch";
import { ClearCheckEngine, EngineSwitch } from "./EngineSwitch";
import { EntryOutputs } from "./EntryOutputs";
import { ExtractionTab } from "./ExtractionTab";
import { ProposalsQueue } from "./ProposalsQueue";
import type { ProposalDomain, ProposalOrigin } from "@/hooks/useHygiene";
import { StagePanel } from "./StagePanel";
import { skipReason, waitingOn } from "./adjudicationCopy";
import type { EngineDest } from "./engineSettingsIndex";
import m from "./EngineMatrix.module.css";
import styles from "./ProcessingTab.module.css";
import { confirmDialog } from "@/utils/dialog";

export type BrowseView = "jobs" | "plans" | "enrichment" | "maintenance" | "publishing";
/** The card's data views — all engine data lives in the one table card. */
export const MATRIX_VIEWS = ["entries", "entities", "links", "relationships", "review", "feeds"] as const;
export type MatrixView = (typeof MATRIX_VIEWS)[number];
/** The Review tab's lenses: the proposals queue and the applied history. */
export type ReviewLens = "proposals" | "history";
// The Action filter value that narrows the Review queue to type changes.
const RECLASSIFY_ACTIONS = "needs_reclassification,adjudication_reclassify";

// Tabs that show a snapshot rather than a window of activity: the picker hides on them.
const NO_WINDOW_VIEWS = new Set<MatrixView>(["review", "feeds"]);

// Stages whose enabled flag is plan-layerable (same set as the old Plans tab).
const TOGGLEABLE_STAGES = new Set([
  "autolink",
  "observables",
  "telegram_links",
  "extract",
  "cooccurrence",
  "correlation",
  "requirements",
  "score",
  "adjudicate",
]);

// Stage → column group. Order matches the backend's PROCESSING_STAGE_ORDER, so
// consecutive stages sharing a group key collapse into one header span.
const STAGE_GROUP: Record<string, { key: string; label: string; cls: string }> = {
  translate: { key: "pre", label: "pre", cls: styles.gpre },
  autolink: { key: "par", label: "parallel", cls: styles.gpar },
  observables: { key: "par", label: "parallel", cls: styles.gpar },
  telegram_links: { key: "par", label: "parallel", cls: styles.gpar },
  extract: { key: "par", label: "parallel", cls: styles.gpar },
  cooccurrence: { key: "post", label: "post", cls: styles.gpost },
  correlation: { key: "post", label: "post", cls: styles.gpost },
  requirements: { key: "post", label: "post", cls: styles.gpost },
  score: { key: "final", label: "final", cls: styles.gfinal },
  analyze: { key: "ai", label: "ai", cls: styles.greview },
  adjudicate: { key: "ai", label: "ai", cls: styles.greview },
  automate: { key: "side", label: "post-score", cls: styles.gside },
};

const SHORT_LABEL: Record<string, string> = {
  observables: "observ.",
  telegram_links: "telegram",
  cooccurrence: "co-occ",
  correlation: "correlate",
  requirements: "reqs",
};

function fmtMs(ms: number | null | undefined): string {
  if (ms == null) return "";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60_000).toFixed(1)}m`;
}

function relTime(iso: string | null): string {
  if (!iso) return "";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86_400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86_400)}d ago`;
}

// Radar score is 0–10 by rank (signals.py): 9+ is the top ~5%, 7+ the top ~18%.
function scoreCls(v: number | null): string {
  if (v == null) return styles.scoreLo;
  if (v >= 9) return styles.scoreHi;
  if (v >= 7) return styles.scoreMid;
  return styles.scoreLo;
}

function Sparkline({ series, className }: { series: number[]; className?: string }) {
  if (!series?.length) return null;
  const max = Math.max(1, ...series);
  const n = series.length;
  const pts = series.map((v, i) => `${(i / (n - 1)) * 78},${24 - (v / max) * 22}`).join(" ");
  const [lx, ly] = pts.split(" ").slice(-1)[0].split(",");
  return (
    <svg
      className={className ?? styles.spark}
      viewBox="0 0 78 24"
      preserveAspectRatio="none"
      aria-hidden="true"
    >
      <polyline fill="none" stroke="var(--accent)" strokeWidth="1.5" points={pts} />
      <circle cx={lx} cy={ly} r="2" fill="var(--accent)" />
    </svg>
  );
}

/**
 * Hover cards for the stages people hesitate over. Everything else keeps its
 * native tooltip — a card on all nine columns is a wall, not an explanation.
 */
const STAGE_HINTS: Record<string, { title: string; body: string; aside?: string }> = {
  extract: {
    title: "Extract",
    body: "Pattern matching, no AI: pulls CVE, technique and mitigation IDs (and detection rules, where the feed asks for them) straight out of the text.",
    aside: "Runs on ingest. The AI reads the article later, in the analysis column.",
  },
  analyze: {
    title: "AI analysis",
    body: "The one-pass AI read: entities, techniques, relationships and observables. Requested once scoring finishes, then waits its turn on the AI worker.",
    aside: "Skipped when it's switched off globally, when the feed turns AI off or extracts nothing, or when the article looks like non-security chatter. Near-duplicates copy an earlier analysis.",
  },
  adjudicate: {
    title: "AI review",
    body: "A second, smaller AI call re-reads the article next to everything the analysis wrote to it — links, new entities, edges, observables — and says keep, remove, merge, demote or drop per item.",
    aside: "Off by default. Shadow files verdicts as proposals; apply fixes high-confidence ones at ingest.",
  },
};

/** A synthetic or real cell's skip code, if any: `status: "skipped"` carries
 *  it in `detail.skipped`; a success run that bailed carries the same key. */
function cellSkipCode(cell: ProcessingStageCell | undefined): string | null {
  if (!cell || cell.status === "error" || cell.status === "retry" || cell.status === "queued") return null;
  const code = (cell.detail as { skipped?: unknown } | null | undefined)?.skipped;
  if (typeof code === "string" && code) return code;
  return cell.status === "skipped" ? "skipped" : null;
}

/** Verdict glyphs for the adjudicate stage's Output cell. Keys match the
 *  `detail.verdicts` counters the task returns (see pipeline_logging). */
const VERDICT_GLYPHS: { key: string; glyph: string; title: string }[] = [
  { key: "remove", glyph: "✂", title: "links removed" },
  { key: "reclassify", glyph: "↷", title: "links flagged for reclassification" },
  { key: "veto", glyph: "⊘", title: "new entities vetoed" },
  { key: "merge", glyph: "⇄", title: "new entities merged into existing ones" },
  { key: "demote", glyph: "↓", title: "relationship edges demoted" },
  { key: "drop", glyph: "✕", title: "observables dropped" },
];

/** Output-lens cell for the adjudicate stage: what the review decided. Reads
 *  the run's detail (verdict counters, mode, skip reason). */
function AdjudicateOutputCell({ cell }: { cell: ProcessingStageCell | undefined }) {
  const detail = cell?.detail as
    | { mode?: string; items?: number; verdicts?: Record<string, number>; skipped?: string; breaker?: boolean }
    | null
    | undefined;
  if (!cell) return <span className={`${m.outCell} ${m.outZero}`}>·</span>;
  if (cell.status === "queued") {
    return (
      <span className={`${m.outCell} ${m.outQueued}`} title={`queued — ${waitingOn(cell)}`}>
        …
      </span>
    );
  }
  const skip = cellSkipCode(cell);
  if (skip) {
    return (
      <span className={`${m.outCell} ${m.outZero}`} title={`skipped: ${skipReason(skip)}`}>
        —
      </span>
    );
  }
  if (cell.status !== "success" || !detail) return <span className={`${m.outCell} ${m.outZero}`}>·</span>;
  const verdicts = detail.verdicts ?? {};
  const shown = VERDICT_GLYPHS.filter((v) => (verdicts[v.key] ?? 0) > 0);
  const shadow = detail.mode !== "apply";
  const cls = `${m.outCell} ${shadow ? m.outShadow : ""}`;
  if (!shown.length) {
    return (
      <span className={`${m.outCell} ${m.outKept}`} title={`all ${detail.items ?? 0} items kept`}>
        ✓ {detail.items ?? 0}
      </span>
    );
  }
  const title =
    shown.map((v) => `${verdicts[v.key]} ${v.title}`).join(" · ") +
    (shadow ? " · shadow: proposals only" : " · applied") +
    (detail.breaker ? " · breaker tripped, downgraded to proposals" : "");
  return (
    <span className={cls} title={title}>
      {shown.map((v) => (
        <span key={v.key} className={m.outRels}>
          {verdicts[v.key]}
          {v.glyph}
        </span>
      ))}
    </span>
  );
}

/** Output-lens cell: what the stage produced for this entry. Only the stages
 *  with per-entry output metrics render counts; the rest show a dot. */
function OutputCell({ stage, outputs }: { stage: string; outputs: ProcessingOutputs | undefined }) {
  if (!outputs) return <span className={`${m.outCell} ${m.outZero}`}>·</span>;
  let parts: { n: number; cls: string; glyph: string; title: string }[] = [];
  if (stage === "autolink") {
    parts = [
      {
        n: outputs.links_auto + outputs.links_other,
        cls: m.outLinks,
        glyph: "🔗",
        title: "entity links (dictionary + unattributed CVE/TTP links)",
      },
    ];
  } else if (stage === "analyze") {
    parts = [
      { n: outputs.entities_created, cls: m.outEnts, glyph: "◆", title: "entities created by AI" },
      { n: outputs.links_ai, cls: m.outLinks, glyph: "🔗", title: "AI-validated links" },
    ];
  } else if (stage === "observables") {
    // The funnel, per entry: judged sightings over staged candidates.
    parts = [
      { n: outputs.observables ?? 0, cls: m.outEnts, glyph: "◎", title: "observable sightings recorded" },
      { n: outputs.observable_candidates ?? 0, cls: m.outLinks, glyph: "cand", title: "candidates staged (unjudged nominations)" },
    ];
  } else if (stage === "cooccurrence") {
    parts = [{ n: outputs.rels_cooc, cls: m.outRels, glyph: "⇄", title: "co-occurrence relationship edges" }];
  } else if (stage === "score") {
    parts = [{ n: outputs.signals, cls: m.outSigs, glyph: "sig", title: "signals fired" }];
  } else {
    return <span className={`${m.outCell} ${m.outZero}`}>·</span>;
  }
  const shown = parts.filter((pp) => pp.n > 0);
  if (!shown.length) return <span className={`${m.outCell} ${m.outZero}`}>0</span>;
  return (
    <span className={m.outCell} title={shown.map((pp) => `${pp.n} ${pp.title}`).join(" · ")}>
      {shown.map((pp) => (
        <span key={pp.glyph} className={pp.cls}>
          {pp.n}
          {pp.glyph}
        </span>
      ))}
    </span>
  );
}

/** The Engine console matrix: healthline, attention chips, live stage headers
 *  with peek popovers, and the per-entry pipeline table with Timing/Output
 *  lenses and an output-management drawer. */
export function EngineMatrix({
  initialStage,
  initialStatus,
  initialView,
  initialLens,
  initialOpenStage,
  onBrowse,
  onHighlightSetting,
}: {
  initialStage?: string;
  initialStatus?: string;
  initialView?: MatrixView;
  /** The Review tab's lens to open on (?lens=history). */
  initialLens?: ReviewLens;
  initialOpenStage?: string | null;
  onBrowse: (view: BrowseView) => void;
  /** Flash a setting once its host surface is open. */
  onHighlightSetting: (key: string) => void;
}) {
  const [window_, setWindow] = useState<EngineWindow>("24h");
  const windowHours = engineWindowHours(window_);
  const windowLabel = window_ === "all" ? "any time" : `the last ${window_}`;
  const [view, setView] = useState<MatrixView>(initialView ?? "entries");
  const [entStatus, setEntStatus] = useState<"all" | "review" | "orphan" | "dupe" | "stale">("all");
  // The window the duplicates chip replaced with "all", put back when its list closes.
  const [windowBeforeDupes, setWindowBeforeDupes] = useState<EngineWindow | null>(null);
  const restoreWindow = () => {
    if (windowBeforeDupes) setWindow(windowBeforeDupes);
    setWindowBeforeDupes(null);
  };
  const pickWindow = (w: EngineWindow) => {
    setWindowBeforeDupes(null);
    setWindow(w);
  };
  const [openStage, setOpenStage] = useState<string | null>(initialOpenStage ?? null);
  const [lens, setLens] = useState<"timing" | "output">("timing");
  // Review tab: which lens is showing.
  const [reviewLens, setReviewLens] = useState<ReviewLens>(initialLens ?? "proposals");
  // Pre-applied filters when a chip deep-links into the proposals queue.
  const [proposalsAction, setProposalsAction] = useState<string | undefined>(undefined);
  const [proposalsOrigin, setProposalsOrigin] = useState<ProposalOrigin | undefined>(undefined);
  const [proposalsDomain, setProposalsDomain] = useState<ProposalDomain | undefined>(undefined);
  const [status, setStatus] = useState<string | undefined>(initialStatus);
  const [stage, setStage] = useState<string | undefined>(initialStage);
  const [feedId, setFeedId] = useState<string | undefined>(undefined);
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [openId, setOpenId] = useState<string | null>(null);
  const [peek, setPeek] = useState<{ stage: string; left: number; top: number } | null>(null);
  const popWrapRef = useRef<HTMLDivElement>(null);

  // The open tab lives in the URL (?view=, and ?lens=history on Review), so
  // Back from a page the console links to lands on the same tab. It is
  // written in place, outside the router: the console already shows it, and
  // a navigation here would remount the console for nothing.
  useEffect(() => {
    const url = new URL(window.location.href);
    if (url.searchParams.get("section") !== "engine") return;
    url.searchParams.set("view", view);
    if (view === "review" && reviewLens !== "proposals") url.searchParams.set("lens", reviewLens);
    else url.searchParams.delete("lens");
    for (const legacy of ["tab", "stage", "status"]) url.searchParams.delete(legacy);
    if (url.href !== window.location.href) window.history.replaceState(window.history.state, "", url);
  }, [view, reviewLens]);

  // Panels belong to the tab they were opened on.
  const closePanels = () => {
    setOpenStage(null);
    setOpenId(null);
    setPeek(null);
  };
  // Deep-link filters are one-shot; drop them on any tab switch. Explicit
  // helper (not a view-effect) so attention chips can switch view AND land on
  // a filtered lens in one click without the reset racing them.
  const switchView = (v: MatrixView) => {
    if (v !== view) closePanels();
    setView(v);
    setProposalsAction(undefined);
    setProposalsOrigin(undefined);
    setProposalsDomain(undefined);
    if (v !== "review") setReviewLens("proposals");
    if (v !== "entities") {
      setEntStatus("all");
      restoreWindow();
    }
  };
  const openProposals = (opts: { action?: string; origin?: ProposalOrigin; domain?: ProposalDomain }) => {
    if (view !== "review") closePanels();
    if (view === "entities") {
      setEntStatus("all");
      restoreWindow();
    }
    setView("review");
    setReviewLens("proposals");
    setProposalsAction(opts.action);
    setProposalsOrigin(opts.origin);
    setProposalsDomain(opts.domain);
  };

  // "Find a setting" result → open whichever surface owns it, then flash the
  // row. Browse views live a level up, so those hand off to EngineSection.
  const gotoSetting = (dest: EngineDest, key: string) => {
    // No flash for the few settings that live outside the console — this page
    // unmounts on the way there, so the highlight would only fire on return.
    if (key && dest.kind !== "settings") onHighlightSetting(key);
    switch (dest.kind) {
      case "stage":
        switchView("entries");
        setOpenStage(dest.stage);
        break;
      case "view":
        switchView(dest.view);
        setOpenStage(null);
        break;
      case "browse":
        onBrowse(dest.browse);
        break;
      case "settings":
        navigate(`/settings?section=${dest.section}${dest.tab ? `&tab=${dest.tab}` : ""}`);
        break;
    }
  };

  useEffect(() => {
    const t = setTimeout(() => setSearch(searchInput.trim()), 300);
    return () => clearTimeout(t);
  }, [searchInput]);

  const query = useEngineProcessing({ window: window_, status, stage, feedId, search });
  const { data: overview } = usePipelineOverview();
  const { data: plans } = usePipelinePlans();
  const { data: extractionStats } = useExtractionStats("7d");
  const { data: linkStats } = useEntityLinkStats();
  const { data: hygieneStats } = useHygieneStats();
  const { data: feedHealth } = useFeedHealth();
  const { data: feeds } = useFeeds();
  const upsertPlan = useUpsertPlan();
  const retryErrors = useRetryPipelineErrors();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const setSelectedEntry = useUIStore((s) => s.setSelectedEntry);

  const openInReader = (entryId: string) => {
    setSelectedEntry(entryId);
    navigate("/");
  };

  const pages = query.data?.pages;
  const entries = useMemo(() => (pages ?? []).flatMap((p) => p.entries), [pages]);
  const stages = useMemo(() => pages?.[0]?.stages ?? [], [pages]);
  const stats = pages?.[0]?.stats;
  const labelByStage = useMemo(() => Object.fromEntries(stages.map((s) => [s.name, s.label])), [stages]);
  const overviewByStage = useMemo(
    () => Object.fromEntries((overview?.stages ?? []).map((s) => [s.name, s])),
    [overview],
  );
  const globalPlan = useMemo(() => plans?.find((p) => p.scope_type === "global"), [plans]);
  const sortedFeeds = useMemo(
    () =>
      [...(feeds?.items ?? [])].sort((a, b) =>
        (a.custom_title || a.title).localeCompare(b.custom_title || b.title, undefined, { sensitivity: "base" }),
      ),
    [feeds],
  );

  // group-header spans + which stage columns start a group (for left dividers)
  const groups = useMemo(() => {
    const out: { label: string; cls: string; span: number; firstStage: string }[] = [];
    for (const s of stages) {
      const g = STAGE_GROUP[s.name];
      const last = out[out.length - 1];
      if (last && STAGE_GROUP[last.firstStage]?.key === g?.key && last.label === g?.label) {
        last.span += 1;
      } else {
        out.push({ label: g?.label ?? s.name, cls: g?.cls ?? "", span: 1, firstStage: s.name });
      }
    }
    return out;
  }, [stages]);
  const groupStartStages = useMemo(() => new Set(groups.map((g) => g.firstStage)), [groups]);

  const retry = async (entryId: string, st: string) => {
    try {
      await api.post(`/engine/entries/${entryId}/stages/${st}/retry`);
      toast.success(`${st} re-dispatched`);
      setTimeout(() => qc.invalidateQueries({ queryKey: ["engine", "processing"] }), 3000);
    } catch {
      toast.error("Retry failed");
    }
  };

  // ---- stage enablement via the global plan (old Plans tab semantics) ------
  const planState = (st: string): boolean | undefined => globalPlan?.stages[st]?.enabled;
  // Header dot: while pipeline plans are inactive the legacy per-feed toggles
  // drive behavior, so reflect observed activity instead of the dormant plan
  // (extract's plan default is off yet it runs via feed flags — an "off" dot
  // over hundreds of green runs would lie).
  const effectiveOn = (st: string): boolean => {
    if (overview?.pipeline_engine_enabled) return planState(st) ?? overviewByStage[st]?.default_enabled ?? true;
    const runs = overviewByStage[st]?.runs_24h;
    return runs ? runs.success + runs.error + runs.retry > 0 : true;
  };

  // The header dot reports stage HEALTH in the window, never configuration.
  // Whether a stage can be toggled says nothing about whether it is working:
  // automate is not plan-gated yet runs on every entry, so gating the dot on
  // toggleability rendered a healthy stage identically to a dead one.
  const dotHealth = (st: string): "ok" | "warn" | "err" | "idle" => {
    const r = overviewByStage[st]?.runs_24h;
    if (!r) return "idle";
    if (r.error > 0) return "err";
    if (r.success + r.retry === 0) return "idle";
    return r.retry > 0 ? "warn" : "ok";
  };

  const dotLabel = (st: string): string => {
    const r = overviewByStage[st]?.runs_24h;
    switch (dotHealth(st)) {
      case "err":
        return `failing — ${r?.error.toLocaleString()} errored in this window`;
      case "warn":
        return `degraded — ${r?.retry.toLocaleString()} retried in this window`;
      case "ok":
        return `healthy — ${r?.success.toLocaleString()} clean runs in this window`;
      default:
        return "idle — no runs in this window";
    }
  };

  // Cycle inherit -> forced off -> forced on -> inherit, at GLOBAL scope, with
  // an impact confirm — identical plan semantics to the old Plans tab.
  const cycleStage = async (st: string) => {
    const current = planState(st);
    const next: boolean | undefined = current === undefined ? false : current === false ? true : undefined;
    const nextLabel = next === undefined ? "inherit (default on)" : next ? "forced ON" : "forced OFF";
    const runs = overviewByStage[st]?.runs_24h;
    const impact = runs ? `${st} ran on ${runs.success + runs.error} entries in the last 24h. ` : "";
    if (
      !(await confirmDialog({
        title: `Set ${st} globally`,
        message:
          `${impact}Set ${st} to ${nextLabel} at GLOBAL scope?\n\nThis is a live ingestion control` +
          (overview?.pipeline_engine_enabled
            ? "."
            : " (currently staged: Pipeline Plans flag is off, so legacy per-feed toggles still drive behavior)."),
        confirmLabel: `Set ${nextLabel}`,
        destructive: true,
      }))
    )
      return;
    const stagesNext = { ...(globalPlan?.stages ?? {}) };
    if (next === undefined) {
      const rest = { ...(stagesNext[st] ?? {}) };
      delete rest.enabled;
      if (Object.keys(rest.config ?? {}).length > 0) stagesNext[st] = rest;
      else delete stagesNext[st];
    } else {
      stagesNext[st] = { ...(stagesNext[st] ?? {}), enabled: next };
    }
    upsertPlan.mutate(
      {
        name: globalPlan?.name ?? "Global default",
        scope_type: "global",
        scope_id: globalPlan?.scope_id ?? null,
        stages: stagesNext,
        is_active: globalPlan?.is_active ?? true,
      },
      {
        onSuccess: () => toast.success(`${st}: ${nextLabel}`),
        onError: () => toast.error("Failed to update stage"),
      },
    );
  };

  const overrideCount = (st: string) =>
    (plans ?? []).filter((p) => p.scope_type !== "global" && p.stages[st]?.enabled !== undefined).length;

  const openPeek = (st: string, target: HTMLElement) => {
    if (peek?.stage === st) {
      setPeek(null);
      return;
    }
    const wrap = popWrapRef.current;
    const r = target.getBoundingClientRect();
    const w = wrap?.getBoundingClientRect();
    const raw = w ? r.left - w.left + r.width / 2 - 175 : 0;
    const left = Math.max(8, Math.min(raw, (w?.width ?? 800) - 360));
    const top = w ? r.bottom - w.top + 8 : 96;
    setPeek({ stage: st, left, top });
  };

  // The entries table's own filter, in words, for the "showing …" readout.
  // A stage alone means "errored at that stage" (the API's default).
  const entriesFilter = !status && !stage
    ? undefined
    : status === "in_flight"
      ? "in flight"
      : status === "complete"
        ? "complete"
        : stage
          ? `errored at ${labelByStage[stage] ?? stage}`
          : "errored";
  const clearEntriesFilter = () => {
    setStatus(undefined);
    setStage(undefined);
  };

  // One click for the whole error column (or every column): the same
  // re-dispatch the per-cell retry does, for every entry still stuck.
  const retryAllErrors = async () => {
    const where = stage ? `at ${labelByStage[stage] ?? stage}` : "at any stage";
    if (
      !(await confirmDialog({
        title: "Retry every error",
        message: `Re-run every stage still stuck on an error ${where}, for entries ingested in ${windowLabel}? Each is re-dispatched the way the per-cell retry does it; entries already re-run green are left alone.`,
        confirmLabel: "Retry all",
      }))
    )
      return;
    try {
      const r = await retryErrors.mutateAsync({ stage, window: window_ });
      const parts = [`${r.dispatched.toLocaleString()} re-dispatched`];
      if (r.skipped) parts.push(`${r.skipped} not retryable`);
      if (r.remaining) parts.push(`${r.remaining.toLocaleString()} more — run again`);
      toast.success(parts.join(" · "), {
        description: Object.entries(r.by_stage)
          .map(([st, n]) => `${labelByStage[st] ?? st}: ${n}`)
          .join(", "),
      });
    } catch (e) {
      toast.error(`Retry failed: ${(e as Error).message}`);
    }
  };

  const failingFeeds = feedHealth?.erroring_feeds?.length ?? 0;

  // The queues that need a person. Each chip is a filter on the table: the
  // ones with `active` light up while their view+filter is showing and clear
  // it on a second click; the rest just jump (`away` leaves the console).
  const attention: {
    key: string;
    n: number | undefined;
    label: string;
    cls: string;
    onClick: () => void;
    active?: boolean;
    clear?: () => void;
    away?: boolean;
    hint?: { title: string; body: string; aside?: string };
  }[] = [
    {
      key: "errors",
      n: stats?.errored,
      label: "stage errors",
      cls: m.aErr,
      active: view === "entries" && status === "error",
      clear: clearEntriesFilter,
      onClick: () => {
        switchView("entries");
        setStatus("error");
        setStage(undefined);
      },
    },
    {
      key: "dupes",
      n: extractionStats?.likely_duplicates,
      label: "duplicate candidates",
      cls: m.aWarn,
      active: view === "entities" && entStatus === "dupe",
      clear: () => {
        setEntStatus("all");
        restoreWindow();
      },
      onClick: () => {
        // The count is across all time, so the list it opens is too, until
        // the list closes.
        switchView("entities");
        setEntStatus("dupe");
        if (window_ !== "all") {
          setWindowBeforeDupes(windowBeforeDupes ?? window_);
          setWindow("all");
        }
      },
    },
    {
      key: "reclass",
      n: hygieneStats?.pending_advisories,
      label: "entities to reclassify",
      cls: m.aWarn,
      active: view === "review" && reviewLens === "proposals" && proposalsAction === RECLASSIFY_ACTIONS,
      clear: () => switchView("review"),
      onClick: () => openProposals({ action: RECLASSIFY_ACTIONS }),
    },
    {
      key: "adjudication",
      n: hygieneStats?.adjudication_pending,
      label: "adjudication verdicts",
      cls: m.aWarn,
      active: view === "review" && reviewLens === "proposals" && !proposalsAction && proposalsOrigin === "adjudicator",
      clear: () => switchView("review"),
      onClick: () => openProposals({ origin: "adjudicator" }),
      hint: {
        title: "Adjudication verdicts",
        body: "What the post-analysis review wants changed: links to remove, held matches to link, new entities to veto or merge, edges to demote, observables to capture or drop. In shadow mode these are suggestions until you apply them.",
        aside: "Opens Review filtered to the adjudicator.",
      },
    },
    {
      key: "feeds",
      n: failingFeeds,
      label: failingFeeds === 1 ? "feed erroring" : "feeds erroring",
      cls: m.aInfo,
      onClick: () => switchView("feeds"),
    },
  ];
  const activeAttention = attention.filter((a) => (a.n ?? 0) > 0);
  // The adjudicate stage's rolling circuit breaker: not a count, a state —
  // dispatch is paused until the timestamp lifts.
  const breakerUntil = hygieneStats?.adjudication_breaker_until
    ? new Date(hygieneStats.adjudication_breaker_until)
    : null;
  const breakerActive = !!breakerUntil && !Number.isNaN(breakerUntil.getTime()) && breakerUntil.getTime() > Date.now();

  const peekInfo = peek ? overviewByStage[peek.stage] : undefined;

  return (
    <div className={styles.wrap}>
      {/* top bar — the pulse (is anything stuck, is ingest flowing), the
          browse views, the window and the setting finder. The counts
          themselves live on the table card, next to what they count. */}
      <div className={m.topbar}>
        <span
          className={`${m.hdot} ${stats?.errored ? m.hdotErr : ""}`}
          role="img"
          aria-label={stats?.errored ? `${stats.errored} entries stuck at a stage` : "pipeline healthy"}
          title={stats?.errored ? `${stats.errored} entries stuck at a stage` : "pipeline healthy"}
        />
        {stats?.ingest_series && <Sparkline series={stats.ingest_series} className={m.hspark} />}
        <div className={m.attnTools}>
          <button type="button" className={m.browseBtn} onClick={() => onBrowse("jobs")}>
            Jobs
          </button>
          <button type="button" className={m.browseBtn} onClick={() => onBrowse("plans")}>
            Plans
          </button>
          <button type="button" className={m.browseBtn} onClick={() => onBrowse("enrichment")}>
            Enrichment
          </button>
          <button type="button" className={m.browseBtn} onClick={() => onBrowse("publishing")}>
            Publishing
          </button>
          <button type="button" className={m.browseBtn} onClick={() => onBrowse("maintenance")}>
            Maintenance
          </button>
        </div>
        <span className={m.topGrow} />
        {!NO_WINDOW_VIEWS.has(view) && (
          <div className={m.hwin}>
            {ENGINE_WINDOWS.map((w) => (
              <button key={w} className={window_ === w ? m.hwinOn : ""} onClick={() => pickWindow(w)}>
                {w === "all" ? "All" : w}
              </button>
            ))}
          </div>
        )}
        <EngineSettingsSearch onPick={gotoSetting} className={m.attnSearch} />
        <ClearCheckEngine />
        <EngineSwitch />
      </div>

      {/* matrix */}
      <div className={m.popWrap} ref={popWrapRef}>
        {peek && (
          <div className={m.pop} style={{ left: peek.left, top: peek.top }}>
            <div className={m.popHead}>
              <h4 className={m.popName}>{peek.stage.replace(/_/g, " ")}</h4>
              <span className={m.popKind}>{(peekInfo?.kind ?? "").replace(/_/g, " ")}</span>
              <button type="button" className={m.popClose} onClick={() => setPeek(null)} title="Close">
                ✕
              </button>
            </div>
            <div className={m.popBody}>
              <p className={m.popDesc}>{peekInfo?.description}</p>
              <div className={m.popRow}>
                <span className={m.popStat}>
                  24h: <b>{peekInfo?.runs_24h.success.toLocaleString() ?? "—"}</b> ✓
                </span>
                {(peekInfo?.runs_24h.error ?? 0) > 0 && (
                  <span className={`${m.popStat} ${m.popErrStat}`}>{peekInfo?.runs_24h.error} ✕</span>
                )}
                {(peekInfo?.runs_24h.retry ?? 0) > 0 && (
                  <span className={m.popStat}>{peekInfo?.runs_24h.retry} retrying</span>
                )}
                {(peekInfo?.runs_24h.queued ?? 0) > 0 && (
                  <span className={m.popStat}>{peekInfo?.runs_24h.queued} queued</span>
                )}
              </div>
              <div className={m.popRow}>
                {TOGGLEABLE_STAGES.has(peek.stage) ? (
                  <>
                    <Chip
                      tone="outline"
                      className={m.scopePill}
                      tint={
                        planState(peek.stage) === undefined
                          ? "var(--border)"
                          : planState(peek.stage)
                            ? "var(--success)"
                            : "var(--danger)"
                      }
                      fg={
                        planState(peek.stage) === undefined
                          ? "var(--text-secondary)"
                          : undefined
                      }
                    >
                      global:{" "}
                      {planState(peek.stage) === undefined
                        ? `inherit (${effectiveOn(peek.stage) ? "on" : "off"})`
                        : planState(peek.stage)
                          ? "forced on"
                          : "forced off"}
                    </Chip>
                    {overrideCount(peek.stage) > 0 && (
                      <Chip
                        tone="outline"
                        className={m.scopePill}
                        tint="var(--border)"
                        fg="var(--text-secondary)"
                      >
                        {overrideCount(peek.stage)} scope overrides
                      </Chip>
                    )}
                    <button
                      type="button"
                      className={m.toggleBtn}
                      disabled={upsertPlan.isPending}
                      onClick={() => cycleStage(peek.stage)}
                    >
                      Cycle: inherit → off → on
                    </button>
                  </>
                ) : (
                  <span className={m.popMuted}>
                    {peek.stage === "translate"
                      ? "Runs for feeds with translation enabled — not plan-gated."
                      : peek.stage === "analyze"
                        ? "Not plan-gated: the global switch, each feed's AI analysis toggle and the junk gate decide."
                        : "Always on — not plan-gated."}
                  </span>
                )}
              </div>
              {!overview?.pipeline_engine_enabled && TOGGLEABLE_STAGES.has(peek.stage) && (
                <p className={m.popWarn}>
                  Pipeline plans are configured but inactive — enable "Pipeline Plans" in the Plans view
                  (top-right) to apply them. Until then the legacy per-feed extraction toggles
                  drive behavior.
                </p>
              )}
            </div>
            <div className={m.popFoot}>
              <button
                type="button"
                className={m.popLink}
                onClick={() => {
                  setPeek(null);
                  // Enrich has no stage panel: its settings are the Enrichment page.
                  if (peek.stage === "enrich") onBrowse("enrichment");
                  else setOpenStage(peek.stage);
                }}
              >
                {peek.stage === "enrich" ? "Open Enrichment →" : "Full stage settings →"}
              </button>
              <button
                type="button"
                className={`${m.popLink} ${m.popMuted}`}
                onClick={() => {
                  setPeek(null);
                  onBrowse("plans");
                }}
              >
                Manage plans
              </button>
            </div>
          </div>
        )}

        <div className={`${styles.tablecard} ${m.card}`}>
          {/* toolbar — lives inside the card, mock-E style */}
          <div className={m.mhead}>
            <div className={m.viewSeg}>
              <button className={view === "feeds" ? m.viewOn : ""} onClick={() => switchView("feeds")}>
                Feeds
                {feedHealth ? <span className={m.viewCnt}>{feedHealth.summary.total.toLocaleString()}</span> : null}
              </button>
              <button className={view === "entries" ? m.viewOn : ""} onClick={() => switchView("entries")}>
                Entries{stats ? <span className={m.viewCnt}>{stats.ingested.toLocaleString()}</span> : null}
              </button>
              <button
                className={view === "entities" ? m.viewOn : ""}
                onClick={() => switchView("entities")}
                title="Entities the analysis created: confirm, merge, convert or delete them"
              >
                Entities
                {extractionStats ? <span className={m.viewCnt}>{extractionStats.total_created.toLocaleString()}</span> : null}
              </button>
              <button className={view === "links" ? m.viewOn : ""} onClick={() => switchView("links")}>
                Links{linkStats ? <span className={m.viewCnt}>{linkStats.total.toLocaleString()}</span> : null}
              </button>
              <button
                className={view === "relationships" ? m.viewOn : ""}
                onClick={() => switchView("relationships")}
              >
                Relationships
                {linkStats ? <span className={m.viewCnt}>{linkStats.relationships_total.toLocaleString()}</span> : null}
              </button>
              <button
                className={view === "review" ? m.viewOn : ""}
                onClick={() => switchView("review")}
                title="Everything the AI wants a person to approve, and the history of what was applied"
              >
                Review
                {hygieneStats?.pending_total ? (
                  <span className={m.viewBadge}>{hygieneStats.pending_total.toLocaleString()}</span>
                ) : null}
              </button>
            </div>
            {view === "entries" && (
              <>
                <div className={m.lens}>
                  <button
                    className={lens === "timing" ? m.lensOn : ""}
                    onClick={() => setLens("timing")}
                    title="Cells show stage durations"
                  >
                    Timing
                  </button>
                  <button
                    className={lens === "output" ? m.lensOn : ""}
                    onClick={() => setLens("output")}
                    title="Cells show what each stage produced"
                  >
                    Output
                  </button>
                </div>
                <select
                  className={styles.stageSelect}
                  value={feedId ?? ""}
                  onChange={(e) => setFeedId(e.target.value || undefined)}
                  title="Filter to one feed"
                >
                  <option value="">Feed: all</option>
                  {sortedFeeds.map((f) => (
                    <option key={f.id} value={f.id}>
                      {f.custom_title || f.title}
                    </option>
                  ))}
                </select>
                <div className={`${styles.search} ${m.msearch}`}>
                  🔍
                  <input
                    placeholder="Search title…"
                    value={searchInput}
                    onChange={(e) => setSearchInput(e.target.value)}
                  />
                </div>
                {/* the engine's counts for the window — a readout, not a filter */}
                <div className={m.counts}>
                  {entriesFilter && (
                    <span className={m.showing}>
                      showing {entries.length.toLocaleString()}
                      {query.hasNextPage ? "+" : ""} · {entriesFilter} ·{" "}
                      <button type="button" className={m.clearBtn} onClick={clearEntriesFilter}>
                        clear
                      </button>
                      {status === "error" && (
                        <>
                          {" · "}
                          <button
                            type="button"
                            className={m.retryAllBtn}
                            disabled={retryErrors.isPending}
                            title={`Re-run every stage still stuck on an error${stage ? ` at ${labelByStage[stage] ?? stage}` : ""} in this window`}
                            onClick={retryAllErrors}
                          >
                            {retryErrors.isPending ? "retrying…" : "retry all"}
                          </button>
                        </>
                      )}
                    </span>
                  )}
                  <span>
                    <b>{stats?.ingested?.toLocaleString() ?? "—"}</b> entries
                  </span>
                  <span>
                    <b>{stats?.complete?.toLocaleString() ?? "—"}</b> complete
                  </span>
                  <span>
                    <b className={stats?.errored ? m.cErr : ""}>{stats?.errored?.toLocaleString() ?? "—"}</b> errored
                  </span>
                  <span>
                    <b className={stats?.processing ? m.cProc : ""}>{stats?.processing?.toLocaleString() ?? "—"}</b>{" "}
                    in flight
                  </span>
                </div>
              </>
            )}
          </div>

          {/* needs-you — the queues that want a person, as filters on this card */}
          <div className={m.needs}>
            <span className={m.attnCap}>Needs you</span>
            {activeAttention.map((a) => (
              <Hint
                key={a.key}
                title={a.hint?.title ?? a.label}
                body={a.hint?.body ?? ""}
                aside={a.hint?.aside}
                disabled={!a.hint}
              >
                <button
                  type="button"
                  className={`${m.achip} ${a.cls} ${a.active ? m.achipOn : ""}`}
                  aria-pressed={a.clear ? !!a.active : undefined}
                  title={a.active ? "Clear this filter" : undefined}
                  onClick={a.active && a.clear ? a.clear : a.onClick}
                >
                  <span className={m.achipDot} />
                  <span className={m.achipN}>{a.n?.toLocaleString()}</span> {a.label}
                  {a.away && (
                    <span className={m.achipAway} aria-hidden="true">
                      ↗
                    </span>
                  )}
                  {a.active && (
                    <span className={m.achipX} aria-hidden="true">
                      ✕
                    </span>
                  )}
                </button>
              </Hint>
            ))}
            {breakerActive && breakerUntil && (
              <button
                type="button"
                className={`${m.achip} ${m.aWarn}`}
                title={`rolling circuit breaker tripped; dispatch resumes at ${breakerUntil.toLocaleTimeString()}`}
                onClick={() => {
                  switchView("entries");
                  setOpenStage("adjudicate");
                }}
              >
                <span className={m.achipDot} />
                adjudication paused (breaker)
              </button>
            )}
            {activeAttention.length === 0 && !breakerActive && (
              <span className={m.attnClear}>All clear — no queues need review.</span>
            )}
          </div>

          {/* full stage settings — expands inside the card, above the table */}
          {openStage && (
            <StagePanel
              stage={openStage}
              onClose={() => setOpenStage(null)}
              onViewErrored={(st) => {
                setOpenStage(null);
                switchView("entries");
                setStatus("error");
                setStage(st);
              }}
            />
          )}

          {view !== "entries" && (
            <div className={m.subView}>
              {view === "review" && (
                <div className={m.subLens}>
                  <div className={m.lens}>
                    <button className={reviewLens === "proposals" ? m.lensOn : ""} onClick={() => setReviewLens("proposals")}>
                      Proposals
                      {hygieneStats?.pending_total ? <span className={m.viewCnt}>{hygieneStats.pending_total.toLocaleString()}</span> : null}
                    </button>
                    <button className={reviewLens === "history" ? m.lensOn : ""} onClick={() => setReviewLens("history")}>
                      History
                    </button>
                  </div>
                  <span className={m.subLensHint}>
                    {reviewLens === "proposals"
                      ? "Everything the adjudicator, the duplicate review and the scans want changed, one row per entity. Its buttons settle every article's copy at once; every apply stays undoable from History."
                      : "Everything that was applied, by a person or by the stage in apply mode. Restore puts it back."}
                  </span>
                </div>
              )}
              {view === "links" && <AutolinkingSection embedded view="links" hours={windowHours} />}
              {view === "relationships" && <AutolinkingSection embedded view="relationships" hours={windowHours} />}
              {view === "review" && reviewLens === "proposals" && (
                <ProposalsQueue
                  lens="queue"
                  key={`q:${proposalsAction ?? "all"}:${proposalsOrigin ?? "all"}:${proposalsDomain ?? "all"}`}
                  initialAction={proposalsAction}
                  initialOrigin={proposalsOrigin}
                  initialDomain={proposalsDomain}
                  settingsOpen={openStage === "adjudicate"}
                  onToggleSettings={() => setOpenStage(openStage === "adjudicate" ? null : "adjudicate")}
                />
              )}
              {view === "review" && reviewLens === "history" && (
                <ProposalsQueue
                  lens="history"
                  key="hist"
                  settingsOpen={openStage === "adjudicate"}
                  onToggleSettings={() => setOpenStage(openStage === "adjudicate" ? null : "adjudicate")}
                />
              )}
              {view === "entities" && (
                <ExtractionTab key={entStatus} initialStatus={entStatus} window={window_} />
              )}
              {view === "feeds" && (
                <>
                  <FeedHealthView embedded />
                  <p className={m.subCap}>Fetch settings</p>
                  <SystemSettings filterGroups={["feeds", "rate_limiting", "image_proxy"]} flat />
                  <p className={m.subCap}>Intel-value weighting</p>
                  <SystemSettings filterGroups={["feed_value"]} flat hideGroupTitle />
                </>
              )}
            </div>
          )}

          {view === "entries" && (
          <>
          <div className={styles.tscroll}>
            <table className={styles.matrix}>
              <thead>
                <tr className={styles.grp}>
                  <th />
                  {groups.map((g, i) => (
                    <th key={i} className={`${g.cls} ${styles.gdiv}`} colSpan={g.span}>
                      {g.label}
                    </th>
                  ))}
                  <th className={styles.gdiv} colSpan={3} />
                </tr>
                <tr className={styles.colhead}>
                  <th className={styles.lft}>Entry</th>
                  {stages.map((s) => {
                    const info = overviewByStage[s.name];
                    const health = dotHealth(s.name);
                    return (
                      <th key={s.name} className={groupStartStages.has(s.name) ? styles.gdiv : ""}>
                        <Hint
                          title={STAGE_HINTS[s.name]?.title ?? s.label}
                          body={STAGE_HINTS[s.name]?.body ?? ""}
                          aside={STAGE_HINTS[s.name]?.aside}
                          disabled={!STAGE_HINTS[s.name] || peek?.stage === s.name}
                          align="center"
                        >
                        <button
                          type="button"
                          className={`${m.sth} ${peek?.stage === s.name ? m.sthOn : ""}`}
                          onClick={(e) => openPeek(s.name, e.currentTarget)}
                          title={
                            STAGE_HINTS[s.name]
                              ? undefined
                              : `${info?.description ?? s.label} — ${dotLabel(s.name)}. Click for status & settings.`
                          }
                        >
                          <span className={m.sthName}>
                            <span
                              className={`${m.sw} ${
                                health === "err"
                                  ? m.swErr
                                  : health === "warn"
                                    ? m.swWarn
                                    : health === "idle"
                                      ? m.swIdle
                                      : ""
                              }`}
                            />
                            {SHORT_LABEL[s.name] ?? s.name}
                          </span>
                          <span className={m.sthCounts}>
                            {info ? `${info.runs_24h.success.toLocaleString()}✓` : ""}
                            {info && info.runs_24h.error > 0 && (
                              <span className={m.sthErr}> {info.runs_24h.error}✕</span>
                            )}
                          </span>
                        </button>
                        </Hint>
                      </th>
                    );
                  })}
                  <th className={styles.gdiv}>Radar</th>
                  <th>Latency</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {entries.map((e) => (
                  <Row
                    key={e.id}
                    entry={e}
                    stages={stages.map((s) => s.name)}
                    groupStartStages={groupStartStages}
                    lens={lens}
                    open={openId === e.id}
                    onToggle={() => setOpenId(openId === e.id ? null : e.id)}
                    labelByStage={labelByStage}
                    onRetry={retry}
                    onOpenReader={openInReader}
                  />
                ))}
                {!entries.length && !query.isLoading && (
                  <tr>
                    <td colSpan={stages.length + 4} className={styles.empty}>
                      No entries match these filters in {windowLabel}.
                    </td>
                  </tr>
                )}
                {query.isLoading && (
                  <tr>
                    <td colSpan={stages.length + 4} className={styles.empty}>
                      Loading…
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          <div className={styles.legend}>
            {lens === "timing" ? (
              <>
                <span className={styles.li}>
                  <span className={`${styles.pip} ${styles.ok}`}>31ms</span> completed — cell shows duration
                </span>
                <span className={styles.li}>
                  <span className={`${styles.pip} ${styles.err}`}>error</span> failed
                </span>
                <span className={styles.li}>
                  <span className={`${styles.pip} ${styles.retry}`}>retry</span> retrying
                </span>
                <span className={styles.li}>
                  <span className={`${styles.pip} ${styles.pend}`}>queued</span> processing
                </span>
                <span className={styles.li}>
                  <span className={`${styles.pip} ${styles.skip}`}>—</span> skipped / n/a
                </span>
              </>
            ) : (
              <>
                <span className={styles.li}>
                  <span className={m.outCell}>
                    <span className={m.outLinks}>3🔗</span>
                  </span>{" "}
                  entity links created
                </span>
                <span className={styles.li}>
                  <span className={m.outCell}>
                    <span className={m.outEnts}>1◆</span>
                  </span>{" "}
                  entities created
                </span>
                <span className={styles.li}>
                  <span className={m.outCell}>
                    <span className={m.outRels}>2⇄</span>
                  </span>{" "}
                  relationship edges
                </span>
                <span className={styles.li}>
                  <span className={m.outCell}>
                    <span className={m.outSigs}>2sig</span>
                  </span>{" "}
                  signals fired
                </span>
              </>
            )}
            <span className={styles.legendNote}>
              Inline stages (sanitize · dedup · relevance · index) run during fetch and aren't dispatched — they
              don't appear as columns.
            </span>
          </div>

          <div className={styles.tfoot}>
            <span>
              Showing {entries.length}
              {stats ? ` of ${stats.ingested.toLocaleString()}` : ""} entries · newest first
              {query.hasNextPage && (
                <>
                  {" · "}
                  <button
                    className={styles.moreBtn}
                    disabled={query.isFetchingNextPage}
                    onClick={() => query.fetchNextPage()}
                  >
                    {query.isFetchingNextPage ? "Loading…" : "Load more"}
                  </button>
                </>
              )}
            </span>
          </div>
          </>
          )}
        </div>
      </div>

    </div>
  );
}

function StatusCell({
  cell,
  pending,
  title,
}: {
  cell: ProcessingStageCell | undefined;
  pending: boolean;
  title: string;
}) {
  if (!cell) {
    if (pending)
      return (
        <span className={`${styles.pip} ${styles.pend}`} title={`${title} · queued`}>
          queued
        </span>
      );
    return (
      <span className={`${styles.pip} ${styles.skip}`} title={`${title} · not run`}>
        —
      </span>
    );
  }
  if (cell.status === "error")
    return (
      <span className={`${styles.pip} ${styles.err}`} title={`${title} · error — ${cell.error ?? ""}`}>
        error
      </span>
    );
  if (cell.status === "retry")
    return (
      <span className={`${styles.pip} ${styles.retry}`} title={`${title} · retry`}>
        retry
      </span>
    );
  if (cell.status === "queued")
    return (
      <span className={`${styles.pip} ${styles.pend}`} title={`${title} · queued — ${waitingOn(cell)}`}>
        {cell.detail?.waiting_on === "analysis" ? "waits" : "queued"}
      </span>
    );
  if (cell.status === "success" && cell.detail?.reused_from)
    return (
      <span className={`${styles.pip} ${styles.ok}`} title={`${title} · copied from a near-duplicate article`}>
        copy
      </span>
    );
  // A gate skipped the stage, or the run bailed before reviewing anything —
  // never a green "ok", the reason lives in the tooltip.
  const skip = cellSkipCode(cell);
  if (skip)
    return (
      <span className={`${styles.pip} ${styles.skip}`} title={`${title} · skipped — ${skipReason(skip)}`}>
        —
      </span>
    );
  return (
    <span className={`${styles.pip} ${styles.ok}`} title={`${title} · success`}>
      {fmtMs(cell.duration_ms) || "ok"}
    </span>
  );
}

function Row({
  entry,
  stages,
  groupStartStages,
  lens,
  open,
  onToggle,
  labelByStage,
  onRetry,
  onOpenReader,
}: {
  entry: ProcessingEntry;
  stages: string[];
  groupStartStages: Set<string>;
  lens: "timing" | "output";
  open: boolean;
  onToggle: () => void;
  labelByStage: Record<string, string>;
  onRetry: (entryId: string, stage: string) => void;
  onOpenReader: (entryId: string) => void;
}) {
  const lastRunIdx = stages.reduce((acc, s, i) => (entry.stages[s] ? i : acc), -1);
  const latencySlow = (entry.latency_ms ?? 0) > 10_000;

  return (
    <>
      <tr className={open ? styles.rowOpen : ""}>
        <td className={styles.ecell}>
          <button className={styles.etitle} onClick={onToggle} title={entry.title}>
            {entry.title}
          </button>
          <span className={styles.emeta}>
            <span className={styles.feedtag}>{entry.feed ?? "—"}</span> ·{" "}
            <span className={styles.disc}>{relTime(entry.created_at)}</span>
          </span>
        </td>
        {stages.map((s, i) => (
          <td key={s} className={groupStartStages.has(s) ? styles.gdiv : ""}>
            {lens === "output" ? (
              s === "adjudicate" ? (
                <AdjudicateOutputCell cell={entry.stages[s]} />
              ) : (
                <OutputCell stage={s} outputs={entry.outputs} />
              )
            ) : (
              <StatusCell
                cell={entry.stages[s]}
                pending={entry.status === "in_flight" && i > lastRunIdx}
                title={labelByStage[s] ?? s}
              />
            )}
          </td>
        ))}
        <td className={styles.gdiv}>
          <span className={`${styles.score} ${scoreCls(entry.radar_score)}`}>
            {entry.radar_score != null ? entry.radar_score.toFixed(1) : "—"}
            <span className={styles.scoreUnit}>rdr</span>
          </span>
        </td>
        <td>
          <span className={`${styles.lat} ${latencySlow ? styles.latSlow : ""}`}>
            {entry.latency_ms != null ? fmtMs(entry.latency_ms) : "—"}
          </span>
        </td>
        <td>
          <button className={styles.expander} onClick={onToggle}>
            <span className="caret-glyph">{open ? "▾" : "▸"}</span>
          </button>
        </td>
      </tr>
      {open && (
        <tr className={styles.drawer}>
          <td colSpan={stages.length + 4}>
            <div className={m.drawerGrid}>
              <div>
                <p className={styles.drawH}>Stage timeline</p>
                <div className={styles.stagelist}>
                  {stages
                    .filter((s) => entry.stages[s])
                    .map((s) => {
                      const c = entry.stages[s];
                      const isErr = c.status === "error";
                      const skip = cellSkipCode(c);
                      const dotCls = isErr
                        ? styles.sdotErr
                        : c.status === "retry" || c.status === "queued"
                          ? styles.sdotRetry
                          : skip
                            ? styles.sdotSkip
                            : styles.sdotOk;
                      return (
                        <div key={s} className={`${styles.srow} ${isErr ? styles.srowErr : ""}`}>
                          <span className={`${styles.sdot} ${dotCls}`} />
                          <span className={styles.sname}>{labelByStage[s] ?? s}</span>
                          <span className={styles.sdetail}>
                            {isErr
                              ? c.error
                              : c.status === "retry"
                                ? "retrying"
                                : c.status === "queued"
                                  ? "queued — waiting on the AI worker"
                                  : skip
                                    ? `skipped — ${skipReason(skip)}`
                                    : ""}
                          </span>
                          {isErr && c.retryable ? (
                            <button className={styles.retrybtn} onClick={() => onRetry(entry.id, s)}>
                              Retry stage
                            </button>
                          ) : (
                            <span className={styles.sdur}>{fmtMs(c.duration_ms)}</span>
                          )}
                        </div>
                      );
                    })}
                </div>
              </div>
              <div>
                <p className={styles.drawH}>Engine output for this entry</p>
                <EntryOutputs entryId={entry.id} />
              </div>
              <div>
                <p className={styles.drawH}>Entry context</p>
                <dl className={styles.kv}>
                  <dt>Entry ID</dt>
                  <dd>{entry.id.slice(0, 8)}…</dd>
                  <dt>Feed</dt>
                  <dd>{entry.feed ?? "—"}</dd>
                  <dt>Category</dt>
                  <dd>{entry.category ?? "—"}</dd>
                  <dt>Ingested</dt>
                  <dd>{entry.created_at ? new Date(entry.created_at).toLocaleString() : "—"}</dd>
                  <dt>End-to-end</dt>
                  <dd>{entry.latency_ms != null ? fmtMs(entry.latency_ms) : "—"}</dd>
                  <dt>Status</dt>
                  <dd>{entry.status === "in_flight" ? "processing" : entry.status}</dd>
                  <dt>Open</dt>
                  <dd>
                    <button className={styles.readerLink} onClick={() => onOpenReader(entry.id)}>
                      Reader ↗
                    </button>
                  </dd>
                </dl>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
