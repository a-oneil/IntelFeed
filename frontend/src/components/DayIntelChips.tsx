import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import {
  dayWindowIso,
  useDayIntel,
  type DayIntelEntity,
  type DayIntelFilters,
} from "@/hooks/useDayIntel";
import { useIsMobile } from "@/hooks/useMediaQuery";
import styles from "./DayIntelChips.module.css";

/** Entry-list filter a chip asks for. Mirrors the `/entries` query params it
 *  becomes; `entity_type`/`entity_id` travel together. */
export interface DayFocusFilter {
  exploited_cves?: boolean;
  entity_type?: string;
  entity_id?: string;
  sector?: string;
}

/** The engaged chip, and what the list is showing because of it. */
export interface DayFocus {
  /** The divider this was clicked on — the filter is scoped to that one day. */
  dayKey: string;
  /** Which chip is lit, so re-clicking clears rather than comparing filters. */
  chip: string;
  /** Plain-English phrase for the tooltip and the list's clear-filter banner. */
  label: string;
  filter: DayFocusFilter;
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

interface Props {
  dayKey: string;
  filters: DayIntelFilters;
  /** The list's current day focus, whichever divider set it. */
  focus?: DayFocus | null;
  /** Set or clear that focus. Omitted where the list can't be filtered. */
  onFocus?: (focus: DayFocus | null) => void;
}

/** Legend copy for the four low-priority fill chips, which are built in a loop. */
const FILL_BLURBS: Record<string, string> = {
  threat_actor: "The threat actor named in the most of this day's articles.",
  malware: "The malware family named in the most of this day's articles.",
  product: "The product named in the most of this day's articles.",
  country: "The country named in the most of this day's articles.",
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

export function DayIntelChips({ dayKey, filters, focus, onFocus }: Props) {
  const isMobile = useIsMobile();
  const win = dayWindowIso(dayKey);
  const { data } = useDayIntel(dayKey, win?.since ?? null, win?.before ?? null, filters);

  if (!data) return null;
  const { threat_actor, malware, cve, ttp, sector, product, country, signals } = data;

  const plural = (n: number) => (n === 1 ? "entry" : "entries");

  /** Every chip is a filter toggle: it narrows the list below to this day's
   *  articles carrying what the chip names, and clicking it again clears that.
   *  Where no `onFocus` is supplied the chip still describes the day, it just
   *  renders as a label rather than pretending to be interactive. */
  const chipButton = (
    chipKey: string,
    tone: string,
    label: string,
    filter: DayFocusFilter,
    title: string,
    children: ReactNode,
  ) => {
    if (!onFocus) {
      return (
        <span key={chipKey} data-chip={chipKey} className={`${styles.chip} ${tone} ${styles.static}`} title={title}>
          {children}
        </span>
      );
    }
    const active = focus?.dayKey === dayKey && focus.chip === chipKey;
    return (
      <button
        key={chipKey}
        data-chip={chipKey}
        type="button"
        className={`${styles.chip} ${tone} ${active ? styles.chipActive : ""}`}
        aria-pressed={active}
        onClick={(e) => {
          e.stopPropagation();
          onFocus(active ? null : { dayKey, chip: chipKey, label, filter });
        }}
        title={active ? `Showing only ${label} — click to clear` : `${title} — click to show only these`}
      >
        {children}
        {active && (
          <span className={styles.clear} aria-hidden="true">
            ✕
          </span>
        )}
      </button>
    );
  };

  // Priority order — highest analyst value first, sliced to MAX_CHIPS.
  const chips: ChipSpec[] = [];

  // 1. Signal: actively-exploited CVEs in the window. Unlike the rest this one
  // names a set rather than a single entity — its number is a count of
  // vulnerabilities — so its filter is the same KEV / active-exploitation
  // predicate the badge itself is counted with.
  if (signals.actively_exploited > 0) {
    chips.push({
      key: "signal",
      term: "actively exploited",
      blurb:
        "Vulnerabilities named on this day that are in CISA's KEV catalog or have been seen exploited in the wild.",
      node: chipButton(
        "signal",
        styles.signal,
        "articles mentioning an actively-exploited CVE",
        { exploited_cves: true },
        `${signals.actively_exploited} actively-exploited ${
          signals.actively_exploited === 1 ? "CVE" : "CVEs"
        } (KEV / known exploitation) mentioned today`,
        <>
          <span className={styles.pip} aria-hidden="true" />
          {signals.actively_exploited} actively exploited
        </>,
      ),
    });
  }

  // 2. New today: an entity first tracked within this window.
  if (signals.new) {
    const n = signals.new;
    chips.push({
      key: "new",
      term: `new ${NEW_ENTITY_LABEL[n.type] ?? n.type}`,
      blurb: "IntelFeed had never tracked this group or family before this day.",
      node: chipButton(
        "new",
        styles.newflag,
        `articles mentioning ${n.name}`,
        { entity_type: n.type, entity_id: n.id },
        n.total > 1
          ? `${n.total} newly-tracked entities today — ${n.name} first seen`
          : `${n.name} first tracked today`,
        <>
          <span className={styles.star} aria-hidden="true">
            ★
          </span>
          <span className={styles.chipLabel}>new {NEW_ENTITY_LABEL[n.type] ?? n.type}</span>
          <span className={styles.chipName}>{n.name}</span>
          {n.total > 1 && <span className={styles.chipCount}>+{n.total - 1}</span>}
        </>,
      ),
    });
  }

  // 3. Top technique.
  if (ttp) {
    chips.push({
      key: "ttp",
      term: "ttp",
      blurb: "The ATT&CK technique named in the most of this day's articles.",
      node: chipButton(
        "ttp",
        styles.ttp,
        `articles mentioning ${ttp.technique_id}`,
        { entity_type: "ttp", entity_id: ttp.id },
        `${ttp.count} ${plural(ttp.count)} mention ${ttp.technique_id} ${ttp.name}`,
        <>
          <span className={styles.chipLabel}>ttp</span>
          <span className={`${styles.chipName} ${styles.mono}`}>{ttp.technique_id}</span>
          <span className={styles.chipName}>{ttp.name}</span>
          {ttp.count > 1 && <span className={styles.chipCount}>×{ttp.count}</span>}
        </>,
      ),
    });
  }

  // 4. Top targeted sector. Sectors are a controlled vocabulary rather than an
  // entity table, so this one filters by slug.
  if (sector) {
    chips.push({
      key: "sector",
      term: "sector",
      blurb: "The industry named as the target in the most of this day's articles.",
      node: chipButton(
        "sector",
        styles.sector,
        `articles targeting ${sector.name}`,
        { sector: sector.slug },
        `${sector.count} ${plural(sector.count)} target ${sector.name}`,
        <>
          <span className={styles.chipLabel}>sector</span>
          <span className={styles.chipName}>{sector.name}</span>
          {sector.count > 1 && <span className={styles.chipCount}>×{sector.count}</span>}
        </>,
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
      node: chipButton(
        "cve",
        styles.cve,
        `articles mentioning ${cve.name}`,
        { entity_type: "cve", entity_id: cve.id },
        `${cve.count} ${plural(cve.count)} mention ${cve.name}` +
          (cve.kev ? " · in CISA KEV" : "") +
          (cve.cvss_score != null ? ` · CVSS ${cve.cvss_score}` : ""),
        <>
          <span className={styles.chipLabel}>{cve.kev ? "cve · kev" : "cve"}</span>
          <span className={`${styles.chipName} ${styles.mono}`}>{cve.name}</span>
          {cve.cvss_score != null ? (
            <span className={styles.chipCount}>{cve.cvss_score.toFixed(1)}</span>
          ) : (
            cve.count > 1 && <span className={styles.chipCount}>×{cve.count}</span>
          )}
        </>,
      ),
    });
  }

  // Lower-priority fills — only surface on quiet days when slots remain.
  const fills: [string, string, string, DayIntelEntity | null][] = [
    ["threat_actor", "actor", styles.actor, threat_actor],
    ["malware", "malware", styles.malware, malware],
    ["product", "product", styles.product, product],
    ["country", "country", styles.country, country],
  ];
  for (const [chipKey, term, tone, entity] of fills) {
    if (!entity) continue;
    chips.push({
      key: chipKey,
      term,
      blurb: FILL_BLURBS[chipKey],
      node: chipButton(
        chipKey,
        tone,
        `articles mentioning ${entity.name}`,
        { entity_type: chipKey, entity_id: entity.id },
        `${entity.count} ${plural(entity.count)} mention ${entity.name}`,
        <>
          <span className={styles.chipLabel}>{term}</span>
          <span className={styles.chipName}>{entity.name}</span>
          {entity.count > 1 && <span className={styles.chipCount}>×{entity.count}</span>}
        </>,
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
              most-mentioned ones, with anything urgent first. Click a chip to show only the
              articles it appears in; click it again to bring the rest back.
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
