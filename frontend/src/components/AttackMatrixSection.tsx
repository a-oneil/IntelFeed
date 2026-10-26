import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAttackMatrix } from "@/hooks/useAttackMatrix";
import {
  buildNavigatorLayer,
  heatAlpha,
  type AttackDomain,
  type MatrixLayerMode,
  type MatrixTechnique,
} from "@/utils/attackMatrix";
import { PageHeader, Segmented } from "@/components/primitives";
import { useIsVisitor } from "@/stores/authStore";
import styles from "./AttackMatrixSection.module.css";

const DOMAINS: Array<{ value: AttackDomain; label: string }> = [
  { value: "enterprise", label: "Enterprise" },
  { value: "mobile", label: "Mobile" },
  { value: "ics", label: "ICS" },
];

/* Keyed by string so the shared Segmented control can drive them; `days`
   itself stays `number | null` for the query. */
const WINDOWS: Array<{ value: string; label: string; days: number | null }> = [
  { value: "7", label: "7d", days: 7 },
  { value: "30", label: "30d", days: 30 },
  { value: "90", label: "90d", days: 90 },
  { value: "all", label: "All", days: null },
];

const MODES: Array<{ value: MatrixLayerMode; label: string; title: string }> = [
  { value: "heat", label: "Feed heat", title: "Color by article frequency in your feeds" },
  { value: "coverage", label: "Coverage", title: "Color by detection rule coverage" },
  { value: "combined", label: "Both", title: "Heat by frequency, edge by coverage" },
];

const COVERAGE_LABELS: Record<MatrixTechnique["coverage"], string> = {
  covered: "Covered",
  library_only: "Missing telemetry",
  no_rule: "No rule",
};

const COVERAGE_VARS: Record<MatrixTechnique["coverage"], string> = {
  covered: "var(--success)",
  library_only: "var(--warning)",
  no_rule: "var(--danger)",
};

interface TooltipState {
  x: number;
  y: number;
  tech: MatrixTechnique;
  tacticName: string;
}

export function AttackMatrixSection() {
  const navigate = useNavigate();
  const [domain, setDomain] = useState<AttackDomain>("enterprise");
  const [days, setDays] = useState<number | null>(30);
  const [chosenMode, setMode] = useState<MatrixLayerMode>("combined");
  // Detection coverage is signed-in only (the server leaves it out of a
  // visitor's response), so a visitor sees article heat alone.
  const isVisitor = useIsVisitor();
  const mode: MatrixLayerMode = isVisitor ? "heat" : chosenMode;
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [tooltip, setTooltip] = useState<TooltipState | null>(null);

  const { data, isLoading, isError } = useAttackMatrix(domain, days);

  const expandableIds = useMemo(() => {
    const ids = new Set<string>();
    for (const col of data?.tactics ?? []) {
      for (const t of col.techniques) {
        if (t.subtechniques && t.subtechniques.length > 0) ids.add(t.technique_id);
      }
    }
    return ids;
  }, [data]);

  const allExpanded = expandableIds.size > 0 && expanded.size >= expandableIds.size;

  const toggleExpanded = (techniqueId: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(techniqueId)) next.delete(techniqueId);
      else next.add(techniqueId);
      return next;
    });
  };

  const handleExport = () => {
    if (!data) return;
    const layer = buildNavigatorLayer(data);
    const blob = new Blob([JSON.stringify(layer, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `intelfeed-attack-${data.domain}-${data.days ? `${data.days}d` : "all"}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const showTooltip = (e: React.MouseEvent<HTMLElement>, tech: MatrixTechnique, tacticName: string) => {
    const rect = e.currentTarget.getBoundingClientRect();
    let x = rect.right + 8;
    if (x + 300 > window.innerWidth) x = Math.max(8, rect.left - 308);
    const y = Math.min(rect.top, window.innerHeight - 190);
    setTooltip({ x, y, tech, tacticName });
  };

  const maxCount = data?.max_article_count ?? 0;
  const windowLabel = days ? `last ${days} days` : "all time";

  const cellStyle = (tech: MatrixTechnique, displayCount: number): React.CSSProperties => {
    const style: React.CSSProperties = {};
    if (mode === "heat" || mode === "combined") {
      const pct = Math.round(heatAlpha(displayCount, maxCount) * 100);
      if (pct > 0) style.background = `color-mix(in srgb, var(--entity-ttp) ${pct}%, transparent)`;
    }
    if (mode === "coverage") {
      style.background = `color-mix(in srgb, ${COVERAGE_VARS[tech.coverage]} 16%, transparent)`;
      style.borderLeft = `3px solid ${COVERAGE_VARS[tech.coverage]}`;
    }
    if (mode === "combined") {
      style.borderLeft = `3px solid ${COVERAGE_VARS[tech.coverage]}`;
    }
    return style;
  };

  const renderCell = (tech: MatrixTechnique, tacticId: string, tacticName: string, isSub: boolean) => {
    const subs = tech.subtechniques ?? [];
    const isExpanded = expanded.has(tech.technique_id);
    const displayCount = !isSub && !isExpanded ? (tech.rollup_article_count ?? tech.article_count) : tech.article_count;
    return (
      <div key={`${tacticId}:${tech.technique_id}`}>
        <div
          className={`${styles.cell} ${isSub ? styles.subCell : ""}`}
          style={cellStyle(tech, displayCount)}
          onClick={() => navigate(`/workbench/ttp/${tech.id}`)}
          onMouseEnter={(e) => showTooltip(e, tech, tacticName)}
          onMouseLeave={() => setTooltip(null)}
        >
          <div className={styles.cellHeader}>
            <span className={styles.cellId}>{tech.technique_id}</span>
            {displayCount > 0 && <span className={styles.cellCount}>{displayCount}</span>}
            {subs.length > 0 && (
              <button
                className={styles.expandBtn}
                onClick={(e) => {
                  e.stopPropagation();
                  toggleExpanded(tech.technique_id);
                }}
                aria-label={isExpanded ? "Collapse sub-techniques" : "Expand sub-techniques"}
                title={`${subs.length} sub-technique${subs.length === 1 ? "" : "s"}`}
              >
                <svg viewBox="0 0 10 10" className={isExpanded ? styles.chevronOpen : styles.chevron}>
                  <path d="M2.5 1L7.5 5L2.5 9" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </button>
            )}
          </div>
          <span className={styles.cellName}>{tech.name}</span>
        </div>
        {isExpanded && subs.map((sub) => renderCell(sub, tacticId, tacticName, true))}
      </div>
    );
  };

  return (
    <>
      <PageHeader
        title="ATT&CK Matrix"
        actions={
          <>
            <button
              className={styles.actionBtn}
              onClick={() => setExpanded(allExpanded ? new Set() : new Set(expandableIds))}
              disabled={expandableIds.size === 0}
            >
              {allExpanded ? "Collapse subs" : "Expand subs"}
            </button>
            {!isVisitor && (
              <button className={styles.actionBtn} onClick={handleExport} disabled={!data}>
                Export Navigator JSON
              </button>
            )}
          </>
        }
        controls={
          <>
            <Segmented<AttackDomain>
              label="Matrix domain"
              value={domain}
              onChange={setDomain}
              options={DOMAINS}
            />
            <Segmented
              label="Time window"
              size="sm"
              value={WINDOWS.find((w) => w.days === days)?.value ?? "all"}
              onChange={(v) => setDays(WINDOWS.find((w) => w.value === v)?.days ?? null)}
              options={WINDOWS}
            />
            {!isVisitor && (
              <Segmented<MatrixLayerMode>
                label="Layer mode"
                size="sm"
                value={mode}
                onChange={setMode}
                options={MODES}
              />
            )}
          </>
        }
      />

      {data && (
        <div className={styles.summaryBar}>
          {!isVisitor && data.coverage_summary && (
            <>
              <span className={styles.summaryItem}>
                <span className={styles.legendSwatch} style={{ background: "var(--success)" }} />
                {data.coverage_summary.covered} covered
              </span>
              <span className={styles.summaryItem}>
                <span className={styles.legendSwatch} style={{ background: "var(--warning)" }} />
                {data.coverage_summary.library_only} missing telemetry
              </span>
              <span className={styles.summaryItem}>
                <span className={styles.legendSwatch} style={{ background: "var(--danger)" }} />
                {data.coverage_summary.no_rule} no rule
              </span>
            </>
          )}
          <span className={styles.summaryMeta}>
            {data.technique_count} techniques · heat = articles seen {windowLabel}
          </span>
        </div>
      )}

      <div className={styles.body}>
        {isLoading && <div className={styles.status}>Loading matrix…</div>}
        {isError && <div className={styles.status}>Failed to load the ATT&amp;CK matrix.</div>}
        {data && (
          <div
            className={styles.matrix}
            style={{ gridTemplateColumns: `repeat(${data.tactics.length}, minmax(150px, 1fr))` }}
          >
            {data.tactics.map((col) => (
              <div key={col.id} className={styles.tacticCol}>
                <div className={styles.tacticHeader}>
                  <span className={styles.tacticName}>{col.name}</span>
                  <span className={styles.tacticCount}>{col.techniques.length}</span>
                </div>
                {col.techniques.map((tech) => renderCell(tech, col.id, col.name, false))}
              </div>
            ))}
          </div>
        )}
      </div>

      {tooltip && (
        <div className={styles.tooltip} style={{ left: tooltip.x, top: tooltip.y }}>
          <div className={styles.tooltipTitle}>
            {tooltip.tech.technique_id} — {tooltip.tech.name}
          </div>
          <div className={styles.tooltipRow}>Tactic: {tooltip.tacticName}</div>
          <div className={styles.tooltipRow}>
            Articles ({windowLabel}): {tooltip.tech.article_count}
            {tooltip.tech.rollup_article_count != null &&
              tooltip.tech.rollup_article_count !== tooltip.tech.article_count &&
              ` (${tooltip.tech.rollup_article_count} incl. sub-techniques)`}
          </div>
          {tooltip.tech.coverage && (
            <div className={styles.tooltipRow}>
              Rules: {tooltip.tech.rule_count} —{" "}
              <span style={{ color: COVERAGE_VARS[tooltip.tech.coverage] }}>
                {COVERAGE_LABELS[tooltip.tech.coverage]}
              </span>
            </div>
          )}
          {tooltip.tech.coverage === "library_only" && (tooltip.tech.missing_data_sources?.length ?? 0) > 0 && (
            <div className={styles.tooltipRow}>
              Missing telemetry: {tooltip.tech.missing_data_sources.slice(0, 4).join(", ")}
              {tooltip.tech.missing_data_sources.length > 4 && "…"}
            </div>
          )}
          <div className={styles.tooltipHint}>Click to open technique profile</div>
        </div>
      )}
    </>
  );
}
