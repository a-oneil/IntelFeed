import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { useNavigate } from "react-router-dom";
import { dayWindowIso, useDayIntel, type DayIntelFilters } from "@/hooks/useDayIntel";
import { useIsMobile } from "@/hooks/useMediaQuery";
import { entityProfilePath } from "@/components/entityProfile/entityProfileConfig";
import styles from "./DayIntelChips.module.css";

interface Props {
  dayKey: string;
  filters: DayIntelFilters;
}

/** Max chips shown on a single day divider. Signal / new-today take priority, so
 *  busy days lead with urgency and quiet days fall back to the top entities.
 *  The strip scrolls sideways rather than wrapping, so a narrow divider carries
 *  the same count as a wide one — the two constants stay separate only so the
 *  mobile cap can be tuned without touching the desktop one. */
const MAX_CHIPS = 5;
const MAX_CHIPS_MOBILE = 5;

/** Compact "what was this day about" chips on the day divider. Shows urgency
 *  signals first (actively-exploited CVEs, newly-tracked actors), then the
 *  top-mentioned technique / sector / CVE / actor for a 3-second read without
 *  opening every entry. */
// Chip labels stay human — the canonical slug (threat_actor) would read oddly
// in "new threat_actor".
const NEW_ENTITY_LABEL: Record<string, string> = {
  threat_actor: "actor",
  malware: "malware",
};

/** One chip plus the plain-English line the legend shows for it. The strip is
 *  dense and unlabelled by design, so every chip carries its own explanation
 *  rather than relying on a static legend that drifts from what's rendered. */
interface ChipSpec {
  key: string;
  node: ReactNode;
  term: string;
  blurb: string;
}

export function DayIntelChips({ dayKey, filters }: Props) {
  const navigate = useNavigate();
  const isMobile = useIsMobile();
  const win = dayWindowIso(dayKey);
  const { data } = useDayIntel(dayKey, win?.since ?? null, win?.before ?? null, filters);

  if (!data) return null;
  const { threat_actor, malware, cve, ttp, sector, product, country, signals } = data;

  const go = (path: string) => (e: React.MouseEvent) => {
    e.stopPropagation();
    navigate(path);
  };

  const plural = (n: number) => (n === 1 ? "entry" : "entries");

  // Priority order — highest analyst value first, sliced to MAX_CHIPS.
  const chips: ChipSpec[] = [];

  // 1. Signal: actively-exploited CVEs in the window (display-only, alert style).
  if (signals.actively_exploited > 0) {
    chips.push({
      key: "signal",
      term: "actively exploited",
      blurb:
        "Vulnerabilities named on this day that are in CISA's KEV catalog or have been seen exploited in the wild.",
      node: (
        <span
          key="signal"
          data-chip="signal"
          className={`${styles.chip} ${styles.signal}`}
          title={`${signals.actively_exploited} actively-exploited ${
            signals.actively_exploited === 1 ? "CVE" : "CVEs"
          } (KEV / known exploitation) mentioned today`}
        >
          <span className={styles.pip} aria-hidden="true" />
          {signals.actively_exploited} actively exploited
        </span>
      ),
    });
  }

  // 2. New today: an entity first tracked within this window.
  if (signals.new) {
    const n = signals.new;
    const path = entityProfilePath(n.type === "threat_actor" ? "threat_actor" : "malware", n.id);
    chips.push({
      key: "new",
      term: `new ${NEW_ENTITY_LABEL[n.type] ?? n.type}`,
      blurb: "IntelFeed had never tracked this group or family before this day.",
      node: (
        <button
          key="new"
          data-chip="new"
          type="button"
          className={`${styles.chip} ${styles.newflag}`}
          onClick={go(path)}
          title={
            n.total > 1
              ? `${n.total} newly-tracked entities today — ${n.name} first seen`
              : `${n.name} first tracked today`
          }
        >
          <span className={styles.star} aria-hidden="true">
            ★
          </span>
          <span className={styles.chipLabel}>new {NEW_ENTITY_LABEL[n.type] ?? n.type}</span>
          <span className={styles.chipName}>{n.name}</span>
          {n.total > 1 && <span className={styles.chipCount}>+{n.total - 1}</span>}
        </button>
      ),
    });
  }

  // 3. Top technique.
  if (ttp) {
    chips.push({
      key: "ttp",
      term: "ttp",
      blurb: "The ATT&CK technique named in the most of this day's articles.",
      node: (
        <button
          key="ttp"
          data-chip="ttp"
          type="button"
          className={`${styles.chip} ${styles.ttp}`}
          onClick={go(`/workbench/ttp/${ttp.id}`)}
          title={`${ttp.count} ${plural(ttp.count)} mention ${ttp.technique_id} ${ttp.name}`}
        >
          <span className={styles.chipLabel}>ttp</span>
          <span className={`${styles.chipName} ${styles.mono}`}>{ttp.technique_id}</span>
          <span className={styles.chipName}>{ttp.name}</span>
          {ttp.count > 1 && <span className={styles.chipCount}>×{ttp.count}</span>}
        </button>
      ),
    });
  }

  // 4. Top targeted sector (display-only — sectors have no profile route).
  if (sector) {
    chips.push({
      key: "sector",
      term: "sector",
      blurb: "The industry named as the target in the most of this day's articles.",
      node: (
        <span
          key="sector"
          data-chip="sector"
          className={`${styles.chip} ${styles.sector} ${styles.static}`}
          title={`${sector.count} ${plural(sector.count)} target ${sector.name}`}
        >
          <span className={styles.chipLabel}>sector</span>
          <span className={styles.chipName}>{sector.name}</span>
          {sector.count > 1 && <span className={styles.chipCount}>×{sector.count}</span>}
        </span>
      ),
    });
  }

  // 5. Top CVE — exploited-first pick; trailing value is CVSS when known.
  if (cve) {
    chips.push({
      key: "cve",
      term: cve.kev ? "cve · kev" : "cve",
      blurb:
        "The day's headline vulnerability — exploited ones outrank merely popular ones, and KEV says it's in CISA's known-exploited catalog. The trailing number is its CVSS score.",
      node: (
        <button
          key="cve"
          data-chip="cve"
          type="button"
          className={`${styles.chip} ${styles.cve}`}
          onClick={go(`/workbench/cve/${cve.id}`)}
          title={
            `${cve.count} ${plural(cve.count)} mention ${cve.name}` +
            (cve.kev ? " · in CISA KEV" : "") +
            (cve.cvss_score != null ? ` · CVSS ${cve.cvss_score}` : "")
          }
        >
          <span className={styles.chipLabel}>{cve.kev ? "cve · kev" : "cve"}</span>
          <span className={`${styles.chipName} ${styles.mono}`}>{cve.name}</span>
          {cve.cvss_score != null ? (
            <span className={styles.chipCount}>{cve.cvss_score.toFixed(1)}</span>
          ) : (
            cve.count > 1 && <span className={styles.chipCount}>×{cve.count}</span>
          )}
        </button>
      ),
    });
  }

  // Lower-priority fills — only surface on quiet days when slots remain.
  if (threat_actor) {
    chips.push({
      key: "threat_actor",
      term: "actor",
      blurb: "The threat actor named in the most of this day's articles.",
      node: (
        <button
          key="threat_actor"
          data-chip="threat_actor"
          type="button"
          className={`${styles.chip} ${styles.actor}`}
          onClick={go(entityProfilePath("threat_actor", threat_actor.id))}
          title={`${threat_actor.count} ${plural(threat_actor.count)} mention ${threat_actor.name}`}
        >
          <span className={styles.chipLabel}>actor</span>
          <span className={styles.chipName}>{threat_actor.name}</span>
          {threat_actor.count > 1 && <span className={styles.chipCount}>×{threat_actor.count}</span>}
        </button>
      ),
    });
  }
  if (malware) {
    chips.push({
      key: "malware",
      term: "malware",
      blurb: "The malware family named in the most of this day's articles.",
      node: (
        <button
          key="malware"
          data-chip="malware"
          type="button"
          className={`${styles.chip} ${styles.malware}`}
          onClick={go(entityProfilePath("malware", malware.id))}
          title={`${malware.count} ${plural(malware.count)} mention ${malware.name}`}
        >
          <span className={styles.chipLabel}>malware</span>
          <span className={styles.chipName}>{malware.name}</span>
          {malware.count > 1 && <span className={styles.chipCount}>×{malware.count}</span>}
        </button>
      ),
    });
  }
  if (product) {
    chips.push({
      key: "product",
      term: "product",
      blurb: "The product named in the most of this day's articles.",
      node: (
        <button
          key="product"
          data-chip="product"
          type="button"
          className={`${styles.chip} ${styles.product}`}
          onClick={go(`/workbench/product/${product.id}`)}
          title={`${product.count} ${plural(product.count)} mention ${product.name}`}
        >
          <span className={styles.chipLabel}>product</span>
          <span className={styles.chipName}>{product.name}</span>
          {product.count > 1 && <span className={styles.chipCount}>×{product.count}</span>}
        </button>
      ),
    });
  }
  if (country) {
    chips.push({
      key: "country",
      term: "country",
      blurb: "The country named in the most of this day's articles.",
      node: (
        <button
          key="country"
          data-chip="country"
          type="button"
          className={`${styles.chip} ${styles.country}`}
          onClick={go(`/workbench/country/${country.id}`)}
          title={`${country.count} ${plural(country.count)} mention ${country.name}`}
        >
          <span className={styles.chipLabel}>country</span>
          <span className={styles.chipName}>{country.name}</span>
          {country.count > 1 && <span className={styles.chipCount}>×{country.count}</span>}
        </button>
      ),
    });
  }

  if (chips.length === 0) return null;

  const shown = chips.slice(0, isMobile ? MAX_CHIPS_MOBILE : MAX_CHIPS);

  return (
    <div className={styles.chips}>
      {/* Leads the strip so the explanation is the first thing in reading order —
          the chips themselves are deliberately terse, and nothing else on the
          divider says where they come from. */}
      <ChipLegend items={shown} />
      {shown.map((c) => c.node)}
    </div>
  );
}

/** "?" chip that opens a legend for the chips actually on screen. Portalled and
 *  fixed-positioned: the strip is an overflow scroller, so an in-flow popover
 *  would be clipped by it. */
function ChipLegend({ items }: { items: ChipSpec[] }) {
  const [open, setOpen] = useState(false);
  const btnRef = useRef<HTMLButtonElement>(null);
  const popRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ left: number; top: number } | null>(null);

  // Measure after the popover mounts, then clamp into the viewport — a divider
  // near the bottom of the list flips the panel above the button.
  useLayoutEffect(() => {
    if (!open) {
      setPos(null);
      return;
    }
    const btn = btnRef.current;
    const pop = popRef.current;
    if (!btn || !pop) return;
    const b = btn.getBoundingClientRect();
    const p = pop.getBoundingClientRect();
    const pad = 8;
    let left = b.left;
    if (left + p.width > window.innerWidth - pad) left = window.innerWidth - p.width - pad;
    if (left < pad) left = pad;
    let top = b.bottom + 6;
    if (top + p.height > window.innerHeight - pad) top = Math.max(pad, b.top - 6 - p.height);
    setPos({ left, top });
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      // Capture-phase stop: the entry list's Escape handler would otherwise
      // clear the reader selection out from under a simple "close the popover".
      e.stopPropagation();
      setOpen(false);
    };
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node;
      if (popRef.current?.contains(t) || btnRef.current?.contains(t)) return;
      setOpen(false);
    };
    document.addEventListener("keydown", onKey, true);
    document.addEventListener("mousedown", onDown, true);
    return () => {
      document.removeEventListener("keydown", onKey, true);
      document.removeEventListener("mousedown", onDown, true);
    };
  }, [open]);

  return (
    <>
      <button
        ref={btnRef}
        type="button"
        className={`${styles.chip} ${styles.explain}`}
        aria-expanded={open}
        aria-label="What are these chips?"
        title="What are these chips?"
        onClick={(e) => {
          e.stopPropagation();
          setOpen((v) => !v);
        }}
      >
        ?
      </button>
      {open &&
        createPortal(
          <div
            ref={popRef}
            role="dialog"
            aria-label="About these chips"
            className={styles.legend}
            // Rendered offscreen for the first paint so the measure-then-clamp
            // pass doesn't flash the panel in the wrong place.
            style={pos ? { left: pos.left, top: pos.top } : { left: -9999, top: 0 }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className={styles.legendTitle}>What this day was about</div>
            <p className={styles.legendIntro}>
              A read of the entities IntelFeed pulled out of this day's articles — the
              most-mentioned ones, with anything urgent first. Click a chip to open its profile.
            </p>
            <dl className={styles.legendList}>
              {items.map((i) => (
                <div key={i.key} className={styles.legendRow}>
                  <dt className={`${styles.chipLabel} ${styles.legendTerm} ${styles[legendTone(i.key)] ?? ""}`}>
                    {i.term}
                  </dt>
                  <dd className={styles.legendBlurb}>{i.blurb}</dd>
                </div>
              ))}
            </dl>
            <p className={styles.legendFoot}>
              ×N is how many of this day's articles mention it. Counts include muted feeds, so the
              strip can be wider than the list below it. Five chips max.
            </p>
          </div>,
          document.body,
        )}
    </>
  );
}

/** Legend terms reuse the chip's own colour so the row and the chip read as the
 *  same object. Two chip keys differ from their CSS class name; the rest match. */
const LEGEND_TONE_CLASS: Record<string, string> = {
  new: "newflag",
  threat_actor: "actor",
};

function legendTone(key: string): string {
  return LEGEND_TONE_CLASS[key] ?? key;
}
