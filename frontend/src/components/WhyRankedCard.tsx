import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { signalBand, SIGNAL_BAND_LABEL } from "@/utils/signalBand";
import { RadarFeedbackButtons } from "@/components/RadarFeedbackButtons";
import { Hint } from "@/components/primitives";
import type { EntryExposure, EntryPersonalization, PrioritySignal } from "@/api/types";
import styles from "./WhyRankedCard.module.css";

interface WhyRankedCardProps {
  /** The 0–10 priority score. */
  score: number;
  /** The raw signal sum the score was scaled from — what the rows add up to. */
  raw?: number | null;
  signals: PrioritySignal[];
  exposure?: EntryExposure | null;
  personal?: EntryPersonalization | null;
  /** When set, the header carries ▲/▼ verdict buttons that feed the ranking. */
  entryId?: string;
}

const FAMILY_LABEL: Record<string, string> = {
  severity: "Severity",
  coverage: "Coverage",
  interest: "Interest",
  novelty: "Novelty",
  content: "Content",
  exposure: "Watched",
  other: "Other",
};

/** A learned family weight as a signed percentage off the shared weight. */
function pctLabel(weight: number): string {
  const delta = Math.round((weight - 1) * 100);
  return `${delta > 0 ? "+" : ""}${delta}%`;
}

function signed(n: number): string {
  return `${n >= 0 ? "+" : "−"}${Math.abs(n).toFixed(2)}`;
}

/** One line of the ledger: what fired, which family it belongs to, and how much it added to (or took off) the score. */
interface Row {
  key: string;
  family: string;
  label: string;
  text: string;
  /** Contribution to the score, already rarity-weighted. */
  value: number;
  /** Raw strength before weighting, shown only in the "Show the math" breakdown. */
  raw?: number;
}

/** "Why it's ranked": the reader-side explanation of an entry's signal score.

    A ledger rather than a chart: every row is one signal, ordered by what it contributed, and the rows sum to the header score. Each row shows the engine's rarity-weighted contribution (`weighted` in the payload), not the raw signal strength; raw strength beside a weighted total doesn't add up and can draw the smallest contributor as the longest bar.

    Collapsed by default: the one line most readers see carries the score and the top reason. */
export function WhyRankedCard({ score, raw, signals, exposure, personal, entryId }: WhyRankedCardProps) {
  // Local, not persisted: every article starts with the one-line summary and expanding is a per-article choice. A stored preference would leave the full ledger open on every entry after one click.
  const [collapsed, setCollapsed] = useState(true);
  const [showMath, setShowMath] = useState(false);
  const navigate = useNavigate();

  const rows = useMemo<Row[]>(() => {
    const out: Row[] = signals.map((sig, i) => ({
      key: `${sig.type}-${i}`,
      family: sig.family,
      label: FAMILY_LABEL[sig.family] ?? sig.family,
      text: sig.explanation,
      // Older payloads carry no `weighted`; the raw score is the fallback.
      value: sig.weighted ?? sig.score,
      raw: sig.score,
    }));
    // Exposure is computed at read time rather than stored as a signal, but it lifts the score the same way, so it gets a row too.
    if (exposure) {
      const asset = exposure.asset_name
        ? `${exposure.asset_name} is on your watched stack`
        : "Affects a vendor or product you follow";
      // The posture goes in this row, next to the asset it concerns, rather than in a separate callout that would name a CVE shown nowhere else on the card.
      const cve = exposure.cve_ids[0];
      const posture =
        exposure.posture === "no_rule" && cve
          ? ` · ${cve} has no detection rule yet`
          : exposure.posture === "defended"
            ? " · covered by a rule in your library"
            : exposure.posture === "blind" && cve
              ? ` · ${cve} has a rule, but not the telemetry it needs`
              : "";
      out.push({
        key: "exposure",
        family: "exposure",
        label: FAMILY_LABEL.exposure,
        text: `${asset}${posture}`,
        value: exposure.lift,
      });
    }
    return out.sort((a, b) => b.value - a.value);
  }, [signals, exposure]);

  if (rows.length === 0) return null;

  const band = signalBand(score);
  const lead = rows[0];
  const ledgerTotal = rows.reduce((sum, r) => sum + r.value, 0);
  // Rows are weighted with today's rates, while the stored sum was fixed at scoring time, so beyond display rounding the two can legitimately differ.
  const drifted = raw != null && Math.abs(ledgerTotal - raw) > 0.1;

  return (
    <div className={`${styles.card} ${styles[`edge_${band}`]}`}>
      <div className={styles.headerRow}>
        <Hint
          title="Why this ranked"
          body={entryId ? "The signals that set this article's rank in your queue." : "The signals that set this article's rank in the queue."}
          aside={
            entryId
              ? "▲ / ▼ changes your weights only. It does not change anyone else's queue."
              : undefined
          }
        >
        <button
          className={styles.header}
          onClick={() => setCollapsed(!collapsed)}
          aria-expanded={!collapsed}
          aria-label={collapsed ? "Why it's ranked: show the breakdown" : "Why it's ranked: hide the breakdown"}
        >
          <span className={`${styles.score} ${styles[band]}`}>◆ {score.toFixed(1)}</span>
          {collapsed ? (
            <>
              {/* The line most readers see: it leads with the reason, not the card's own name. */}
              <span className={styles.leadText}>{lead.text}</span>
              {rows.length > 1 && (
                <span className={styles.more}>+{rows.length - 1} more</span>
              )}
            </>
          ) : (
            <span className={styles.bandLabel}>· {SIGNAL_BAND_LABEL[band]} priority</span>
          )}
          <span className={styles.arrow}>{collapsed ? "▾" : "▴"}</span>
        </button>
        </Hint>
        {entryId && <RadarFeedbackButtons entryId={entryId} />}
      </div>

      {!collapsed && (
        <div className={styles.body}>
          <ul className={styles.ledger}>
            {rows.map((row, i) => (
              <li key={row.key} className={`${styles.row} ${row.value < 0 ? styles.rowNeg : ""}`}>
                <span className={`${styles.rule} ${styles[`bg_${row.family}`] ?? styles.bg_other}`} />
                <span className={styles.rowMain}>
                  <span className={`${styles.rowFam} ${styles[`fam_${row.family}`] ?? ""}`}>
                    {row.label}
                    {i === 0 && rows.length > 1 && row.value > 0 && (
                      <span className={styles.driver}> · largest contribution</span>
                    )}
                  </span>
                  <span className={styles.rowText}>{row.text}</span>
                </span>
                <span className={`${styles.rowVal} ${row.value < 0 ? styles.valNeg : ""}`}>
                  {signed(row.value)}
                </span>
              </li>
            ))}
          </ul>

          {showMath && (
            <div className={styles.math}>
              <div className={styles.mathHead}>
                Each signal&rsquo;s raw strength × how rare that signal is
              </div>
              {rows.map((row) => (
                <div key={row.key} className={styles.mathRow}>
                  <span className={styles.mathName}>{row.label}</span>
                  <span className={styles.mathCalc}>
                    {row.raw != null && row.raw !== 0
                      ? `${row.raw.toFixed(2)} × ${(row.value / row.raw).toFixed(2)} rarity`
                      : "added at read time"}
                  </span>
                  <span className={styles.mathVal}>{signed(row.value)}</span>
                </div>
              ))}
              {drifted ? (
                <>
                  {/* Rarity weights are recomputed nightly and old entries aren't re-scored, so an entry's stored score can predate the weights above. Say so rather than print a sum that doesn't reconcile. */}
                  <div className={styles.mathTotal}>
                    <span>At today&rsquo;s weights</span>
                    <span>{ledgerTotal.toFixed(2)}</span>
                  </div>
                  <div className={styles.mathTotalSub}>
                    <span>Stored score</span>
                    <span>
                      {raw != null && `${raw.toFixed(2)} → `}◆ {score.toFixed(1)}
                    </span>
                  </div>
                </>
              ) : (
                <div className={styles.mathTotal}>
                  <span>Shared score</span>
                  <span>
                    {ledgerTotal.toFixed(2)} → ◆ {score.toFixed(1)}
                  </span>
                </div>
              )}
              <p className={styles.mathNote}>
                Rarity weights are recomputed nightly. A signal that fires on 40% of articles is
                worth less than one that fires on 1%. The sum is then ranked against the last 30
                days on a 0 to 10 scale: 9 is about the top 5%, 10 the top 1%.
                {drifted
                  ? " This entry's stored score was computed with earlier weights, so it differs from today's total."
                  : " This score is the same for everyone."}
              </p>
            </div>
          )}

          <div className={styles.footer}>
            {personal && personal.families.length > 0 && (
              <span className={styles.footItem}>
                Your votes change this by{" "}
                <b className={styles.footLift}>{signed(personal.lift)}</b> in your ordering
                only{" "}
                <span className={styles.footDetail}>
                  (
                  {personal.families.map((f, i) => (
                    <span key={f.family}>
                      {i > 0 && ", "}
                      {FAMILY_LABEL[f.family] ?? f.family} {pctLabel(f.weight)}
                    </span>
                  ))}
                  )
                </span>
              </span>
            )}
            {/* Both links sit in one right-aligned group so they stay together when the prose before them wraps. */}
            <span className={styles.footLinks}>
              {personal && personal.families.length > 0 && (
                <button
                  className={styles.footLink}
                  onClick={() => navigate("/settings?section=reading")}
                  title="See the weights learned from your votes, pause personalization, or reset them"
                >
                  Your Radar
                </button>
              )}
              <button className={styles.footLink} onClick={() => setShowMath((v) => !v)}>
                {showMath ? "Hide the math" : "Show the math"}
              </button>
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
