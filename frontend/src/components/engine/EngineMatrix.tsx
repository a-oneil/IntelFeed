import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import api from "@/api/client";
import { useFeedHealth } from "@/hooks/useAnalytics";
import { useEntityLinkStats } from "@/hooks/useAutolinking";
import {
  type ProcessingEntry,
  type ProcessingOutputs,
  type ProcessingStageCell,
  useEngineProcessing,
  useExtractionStatus,
  useLinkValidationStats,
  usePipelineOverview,
  usePipelinePlans,
  useUpsertPlan,
} from "@/hooks/useEngine";
import { useExtractionStats } from "@/hooks/useExtraction";
import { Chip } from "@/components/primitives/Chip";
import { Hint } from "@/components/primitives";
import { useFeeds } from "@/hooks/useFeeds";
import { useUIStore } from "@/stores/uiStore";

import { FeedHealthView } from "@/components/FeedHealthView";
import SystemSettings from "@/components/SystemSettings";

import { AutolinkingSection } from "./AutolinkingSection";
import { EngineSettingsSearch } from "./EngineSettingsSearch";
import { EntryOutputs } from "./EntryOutputs";
import { ExtractionTab } from "./ExtractionTab";
import { ProposalsQueue } from "./ProposalsQueue";
import { StagePanel } from "./StagePanel";
import type { EngineDest } from "./engineSettingsIndex";
import m from "./EngineMatrix.module.css";
import styles from "./ProcessingTab.module.css";
import { confirmDialog } from "@/utils/dialog";

export type BrowseView = "jobs" | "plans" | "maintenance" | "publishing";
/** The card's data views — all engine data lives in the one table card. */
export type MatrixView = "entries" | "links" | "relationships" | "entities" | "feeds";

const WINDOWS = ["1h", "24h", "7d"] as const;

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

function scoreCls(v: number | null): string {
  if (v == null) return styles.scoreLo;
  if (v >= 80) return styles.scoreHi;
  if (v >= 50) return styles.scoreMid;
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
    body: "Where AI reads an article and proposes entities, techniques and CVEs.",
    aside: "Nothing it proposes goes live without clearing the creation gates.",
  },
};

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
  } else if (stage === "extract") {
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
  initialEntityStatus,
  initialOpenStage,
  onBrowse,
  onHighlightSetting,
}: {
  initialStage?: string;
  initialStatus?: string;
  initialView?: MatrixView;
  initialEntityStatus?: "all" | "review" | "orphan" | "dupe";
  initialOpenStage?: string | null;
  onBrowse: (view: BrowseView) => void;
  /** Flash a setting once its host surface is open. */
  onHighlightSetting: (key: string) => void;
}) {
  const [window_, setWindow] = useState("24h");
  const [view, setView] = useState<MatrixView>(initialView ?? "entries");
  const [entStatus, setEntStatus] = useState<"all" | "review" | "orphan" | "dupe">(initialEntityStatus ?? "all");
  const [openStage, setOpenStage] = useState<string | null>(initialOpenStage ?? null);
  const [lens, setLens] = useState<"timing" | "output">("timing");
  const [proposalsMode, setProposalsMode] = useState(false);
  // Pre-applied action filter when a chip deep-links into a proposals queue.
  const [proposalsAction, setProposalsAction] = useState<string | undefined>(undefined);
  const [status, setStatus] = useState<string | undefined>(initialStatus);
  const [stage, setStage] = useState<string | undefined>(initialStage);
  const [feedId, setFeedId] = useState<string | undefined>(undefined);
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [openId, setOpenId] = useState<string | null>(null);
  const [peek, setPeek] = useState<{ stage: string; left: number; top: number } | null>(null);
  const popWrapRef = useRef<HTMLDivElement>(null);

  // Proposals mode only applies to Links / AI-entities; drop it on any tab
  // switch. Explicit helper (not a view-effect) so attention chips can switch
  // view AND land in proposals mode in one click without the reset racing them.
  const switchView = (v: MatrixView) => {
    setView(v);
    setProposalsMode(false);
    setProposalsAction(undefined);
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
        navigate(`/settings?section=${dest.section}`);
        break;
    }
  };

  useEffect(() => {
    const t = setTimeout(() => setSearch(searchInput.trim()), 300);
    return () => clearTimeout(t);
  }, [searchInput]);

  const query = useEngineProcessing({ window: window_, status, stage, feedId, search });
  const { data: extraction } = useExtractionStatus();
  const { data: overview } = usePipelineOverview();
  const { data: plans } = usePipelinePlans();
  const { data: extractionStats } = useExtractionStats("7d");
  const { data: linkStats } = useEntityLinkStats();
  const { data: validationStats } = useLinkValidationStats();
  const { data: feedHealth } = useFeedHealth();
  const { data: feeds } = useFeeds();
  const upsertPlan = useUpsertPlan();
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

  const statusChips: { key: string | undefined; label: string; count?: number }[] = [
    { key: undefined, label: "All", count: stats?.ingested },
    { key: "error", label: "Errored", count: stats?.errored },
    { key: "in_flight", label: "Processing", count: stats?.processing },
    { key: "complete", label: "Complete", count: stats?.complete },
  ];

  const pct = stats && stats.ingested ? Math.round((stats.complete / stats.ingested) * 1000) / 10 : 0;
  const failingFeeds = feedHealth?.erroring_feeds?.length ?? 0;
  const aiQueue = extraction ? (extraction.queue.pending ?? 0) : undefined;

  const attention: {
    key: string;
    n: number | undefined;
    label: string;
    cls: string;
    onClick: () => void;
    hint?: { title: string; body: string; aside?: string };
  }[] = [
    {
      key: "errors",
      n: stats?.errored,
      label: "stage errors",
      cls: m.aErr,
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
      onClick: () => {
        setEntStatus("dupe");
        switchView("entities");
      },
    },
    {
      key: "reclass",
      n: validationStats?.reclassify_pending,
      label: "reclassify proposals",
      cls: m.aWarn,
      onClick: () => {
        setView("links");
        setProposalsMode(true);
        setProposalsAction("needs_reclassification");
      },
    },
    {
      key: "pending",
      n: linkStats?.pending,
      label: "pending links",
      cls: m.aInfo,
      onClick: () => switchView("links"),
      hint: {
        title: "Pending links",
        body: "Matches the autolinker isn't willing to commit to — usually a name that's also an ordinary word.",
        aside: "They stay out of the graph until AI or you confirm them.",
      },
    },
    {
      key: "obs-candidates",
      n: stats?.observable_candidates,
      label: "observable candidates",
      cls: m.aInfo,
      onClick: () => navigate("/workbench/observables?queue=1"),
      hint: {
        title: "Observable candidates",
        body: `Pattern nominations no judgment door has confirmed — ${stats?.observable_confirmed ?? 0} sightings were confirmed against them this window. If that ratio drifts, the scan is the first place to look.`,
        aside: "Opens the candidates queue in the Observables workbench.",
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

  const peekInfo = peek ? overviewByStage[peek.stage] : undefined;

  return (
    <div className={styles.wrap}>
      {/* healthline — one row of clearly labeled stats */}
      <div className={m.healthline}>
        <span className={`${m.hdot} ${stats?.errored ? m.hdotErr : ""}`} />
        <span className={m.hitem}>
          <b>{stats?.ingested?.toLocaleString() ?? "—"}</b>
          <span>entries</span>
          {stats?.ingest_series && <Sparkline series={stats.ingest_series} className={m.hspark} />}
        </span>
        <span className={m.hitem}>
          <b className={m.hok}>{pct}%</b>
          <span>scored</span>
        </span>
        <span className={m.hitem}>
          {(stats?.errored ?? 0) > 0 ? (
            <button
              type="button"
              className={m.herr}
              onClick={() => {
                switchView("entries");
                setStatus("error");
                setStage(undefined);
              }}
            >
              {stats?.errored} errored
            </button>
          ) : (
            <>
              <b>0</b>
              <span>errored</span>
            </>
          )}
        </span>
        {(stats?.processing ?? 0) > 0 && (
          <span className={m.hitem}>
            <b className={m.hproc}>{stats?.processing}</b>
            <span>in flight</span>
          </span>
        )}
        <span className={m.hitem}>
          <b>{stats ? fmtMs(stats.median_latency_ms) || "—" : "—"}</b>
          <span>median</span>
        </span>
        <span className={m.hitem}>
          <b>${extraction?.spent_today_usd.toFixed(2) ?? "—"}</b>
          <span>of ${extraction?.daily_budget_usd.toFixed(0) ?? "—"} AI</span>
        </span>
        {aiQueue != null && aiQueue > 0 && (
          <span className={m.hitem}>
            <b>{aiQueue.toLocaleString()}</b>
            <span>queued</span>
          </span>
        )}
        <div className={m.hwin}>
          {WINDOWS.map((w) => (
            <button key={w} className={window_ === w ? m.hwinOn : ""} onClick={() => setWindow(w)}>
              {w}
            </button>
          ))}
        </div>
      </div>

      {/* attention chips */}
      <div className={m.attn}>
        <div className={m.attnLeft}>
          <span className={m.attnCap}>Needs you</span>
          {activeAttention.map((a) => (
            <Hint
              key={a.key}
              title={a.hint?.title ?? a.label}
              body={a.hint?.body ?? ""}
              aside={a.hint?.aside}
              disabled={!a.hint}
            >
              <button type="button" className={`${m.achip} ${a.cls}`} onClick={a.onClick}>
                <span className={m.achipDot} />
                <span className={m.achipN}>{a.n?.toLocaleString()}</span> {a.label}
              </button>
            </Hint>
          ))}
          {activeAttention.length === 0 && <span className={m.attnClear}>All clear — no queues need review.</span>}
        </div>
        <div className={m.attnTools}>
          <button type="button" className={m.browseBtn} onClick={() => onBrowse("jobs")}>
            Jobs
          </button>
          <button type="button" className={m.browseBtn} onClick={() => onBrowse("plans")}>
            Plans
          </button>
          <button type="button" className={m.browseBtn} onClick={() => setOpenStage("enrich")}>
            Enrichment
          </button>
          <button type="button" className={m.browseBtn} onClick={() => onBrowse("publishing")}>
            Publishing
          </button>
          <button type="button" className={m.browseBtn} onClick={() => onBrowse("maintenance")}>
            Maintenance
          </button>
          <EngineSettingsSearch onPick={gotoSetting} className={m.attnSearch} />
        </div>
      </div>

      {/* matrix */}
      <div className={m.popWrap} ref={popWrapRef}>
        {peek && (
          <div className={m.pop} style={{ left: peek.left, top: peek.top }}>
            <div className={m.popHead}>
              <h4 className={m.popName}>{peek.stage.replace(/_/g, " ")}</h4>
              <span className={m.popKind}>{peekInfo?.kind ?? ""}</span>
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
                  setOpenStage(peek.stage);
                }}
              >
                Full stage settings →
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
              <button className={view === "entities" ? m.viewOn : ""} onClick={() => switchView("entities")}>
                AI entities
                {extractionStats ? <span className={m.viewCnt}>{extractionStats.total_created.toLocaleString()}</span> : null}
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
                {statusChips.map((c) => (
                  <button
                    key={c.label}
                    className={`${styles.chip} ${status === c.key ? styles.chipActive : ""}`}
                    onClick={() => setStatus(c.key)}
                  >
                    {c.label}
                    {c.count != null && <span className={styles.chipCount}>{c.count.toLocaleString()}</span>}
                  </button>
                ))}
                <select
                  className={styles.stageSelect}
                  value={stage ?? ""}
                  onChange={(e) => setStage(e.target.value || undefined)}
                  title="Filter to entries that errored at a stage"
                >
                  <option value="">Errored at: any stage</option>
                  {stages.map((s) => (
                    <option key={s.name} value={s.name}>
                      Errored at: {s.label}
                    </option>
                  ))}
                </select>
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
              </>
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
              {/* Data ↔ Proposals lens — Links and AI-entities tabs can flip to
                  the AI/scan cleanup queue that maintains that surface. */}
              {(view === "links" || view === "entities") && (
                <div className={m.subLens}>
                  <div className={m.lens}>
                    <button
                      className={!proposalsMode ? m.lensOn : ""}
                      onClick={() => {
                        setProposalsMode(false);
                        setProposalsAction(undefined);
                      }}
                    >
                      {view === "links" ? "Links" : "Entities"}
                    </button>
                    <button
                      className={proposalsMode ? m.lensOn : ""}
                      onClick={() => {
                        setProposalsMode(true);
                        setProposalsAction(undefined);
                      }}
                    >
                      Proposals
                    </button>
                  </div>
                  {proposalsMode && (
                    <span className={m.subLensHint}>
                      {view === "links"
                        ? "Link-validator suggestions — apply or dismiss without leaving the table"
                        : "Merge / rename / reclassify suggestions over AI-created entities"}
                    </span>
                  )}
                </div>
              )}
              {view === "links" &&
                (proposalsMode ? (
                  <ProposalsQueue domain="links" key={proposalsAction ?? "all"} initialAction={proposalsAction} />
                ) : (
                  <AutolinkingSection embedded view="links" />
                ))}
              {view === "relationships" && <AutolinkingSection embedded view="relationships" />}
              {view === "entities" &&
                (proposalsMode ? (
                  <ProposalsQueue domain="entities" />
                ) : (
                  <ExtractionTab embedded key={entStatus} initialStatus={entStatus} />
                ))}
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
                      No entries match these filters in the last {window_}.
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
              <OutputCell stage={s} outputs={entry.outputs} />
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
            {entry.radar_score != null ? Math.round(entry.radar_score) : "—"}
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
                      const dotCls = isErr ? styles.sdotErr : c.status === "retry" ? styles.sdotRetry : styles.sdotOk;
                      return (
                        <div key={s} className={`${styles.srow} ${isErr ? styles.srowErr : ""}`}>
                          <span className={`${styles.sdot} ${dotCls}`} />
                          <span className={styles.sname}>{labelByStage[s] ?? s}</span>
                          <span className={styles.sdetail}>
                            {isErr ? c.error : c.status === "retry" ? "retrying" : ""}
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
