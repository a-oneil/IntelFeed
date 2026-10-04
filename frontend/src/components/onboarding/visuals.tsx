/**
 * Schematics for the three steps where geometry *is* the content.
 *
 * A three-panel reader described in prose doesn't land, and a screenshot would
 * be locked to whichever of the 51 themes it was captured in and stale the next
 * time a surface moves. These draw the shape instead, from `currentColor` and
 * the theme tokens, so they follow whatever theme the reader is actually using.
 *
 * Decorative by design: the prose beside each one carries the meaning, so they
 * are `aria-hidden` rather than competing with it for a screen reader.
 */

import styles from "./OnboardingWizard.module.css";

const RULE = "var(--border)";
const DIM = "var(--text-muted)";
const MUTED = "var(--text-secondary)";
const ACCENT = "var(--accent)";
const SURFACE = "var(--bg-secondary)";
const GROUND = "var(--bg-primary)";

function Frame({ children, label }: { children: React.ReactNode; label: string }) {
  return (
    <figure className={styles.viz}>
      <svg viewBox="0 0 560 180" role="img" aria-label={label} preserveAspectRatio="xMidYMid meet">
        {children}
      </svg>
    </figure>
  );
}

export function ReaderSchematic() {
  return (
    <Frame label="The three-panel reader: a feed rail, the entries in the selected feed, and the article">
      <rect x="1" y="1" width="558" height="178" rx="6" fill={GROUND} stroke={RULE} />
      <line x1="111" y1="1" x2="111" y2="179" stroke={RULE} />
      <line x1="290" y1="1" x2="290" y2="179" stroke={RULE} />

      <text x="12" y="21" fill={MUTED} fontFamily="var(--font-mono)" fontSize="9">
        FEEDS
      </text>
      {[70, 86, 58, 78, 64].map((w, i) => (
        <rect key={i} x="12" y={32 + i * 17} width={w} height="6" rx="3" fill={RULE} />
      ))}
      <rect x="12" y="117" width="88" height="6" rx="3" fill={ACCENT} opacity="0.65" />

      <text x="124" y="21" fill={MUTED} fontFamily="var(--font-mono)" fontSize="9">
        ENTRIES
      </text>
      {[0, 1, 2, 3].map((i) => (
        <g key={i}>
          <rect
            x="122"
            y={30 + i * 35}
            width="156"
            height="28"
            rx="4"
            fill={i === 1 ? SURFACE : "none"}
            stroke={i === 1 ? ACCENT : RULE}
          />
          <rect
            x="130"
            y={38 + i * 35}
            width={[120, 104, 132, 96][i]}
            height="5"
            rx="2.5"
            fill={MUTED}
            opacity="0.8"
          />
          <rect x="130" y={48 + i * 35} width={[58, 70, 46, 62][i]} height="4" rx="2" fill={DIM} />
        </g>
      ))}

      <text x="303" y="21" fill={MUTED} fontFamily="var(--font-mono)" fontSize="9">
        ARTICLE
      </text>
      <rect x="303" y="30" width="180" height="8" rx="4" fill="var(--text-primary)" opacity="0.75" />
      <rect x="303" y="44" width="110" height="5" rx="2.5" fill={DIM} />
      {[244, 230, 238, 206, 242, 180].map((w, i) => (
        <rect key={i} x="303" y={60 + i * 13} width={w} height="4" rx="2" fill={RULE} />
      ))}
      {[
        { x: 303, w: 42, t: "APT29" },
        { x: 351, w: 56, t: "CVE-…" },
        { x: 413, w: 40, t: "T1566" },
      ].map((c) => (
        <g key={c.t}>
          <rect x={c.x} y="140" width={c.w} height="13" rx="3" fill="none" stroke={ACCENT} />
          <text x={c.x + 7} y="150" fill={ACCENT} fontFamily="var(--font-mono)" fontSize="8">
            {c.t}
          </text>
        </g>
      ))}
    </Frame>
  );
}

const QUEUE_ROWS = [
  { y: 14, w: 300, score: 94, label: "Actor you watch · 3 sources · exploited CVE" },
  { y: 50, w: 232, score: 81, label: "KEV addition · vendor you track" },
  { y: 86, w: 168, score: 63, label: "New malware family · 1 source" },
  { y: 122, w: 104, score: 38, label: "Routine advisory" },
];

export function QueueSchematic() {
  return (
    <Frame label="The priority queue: entries ranked by signal, highest first">
      {QUEUE_ROWS.map((r) => (
        <g key={r.score}>
          <rect x="1" y={r.y} width="558" height="28" rx="5" fill={SURFACE} stroke={RULE} />
          <rect x="9" y={r.y + 8} width={r.w} height="12" rx="3" fill={ACCENT} opacity={r.score / 140} />
          <text x="16" y={r.y + 18} fill="var(--text-primary)" fontFamily="var(--font-mono)" fontSize="9">
            {r.label}
          </text>
          <text
            x="536"
            y={r.y + 18}
            fill={MUTED}
            fontFamily="var(--font-mono)"
            fontSize="10"
            textAnchor="end"
          >
            {r.score}
          </text>
        </g>
      ))}
    </Frame>
  );
}

const PIVOTS = [
  { y: 18, label: "APT29", count: "41 articles" },
  { y: 78, label: "CVE-2026-1234", count: "12 articles" },
  { y: 138, label: "T1566 Phishing", count: "86 articles" },
];

export function PivotSchematic() {
  return (
    <figure className={styles.viz}>
      <svg
        viewBox="0 0 560 190"
        role="img"
        aria-label="Pivoting: one article links to entities, and each entity gathers every other article that named it"
        preserveAspectRatio="xMidYMid meet"
      >
        <rect x="10" y="78" width="128" height="34" rx="5" fill={SURFACE} stroke={RULE} />
        <text x="22" y="99" fill="var(--text-primary)" fontFamily="var(--font-mono)" fontSize="9">
          Article you read
        </text>
        {PIVOTS.map((e) => (
          <g key={e.label}>
            <path
              d={`M138 95 C 180 95, 190 ${e.y + 17}, 232 ${e.y + 17}`}
              fill="none"
              stroke={ACCENT}
              strokeWidth="1.3"
              opacity="0.7"
            />
            <rect x="232" y={e.y} width="140" height="34" rx="5" fill="var(--bg-tertiary)" stroke={ACCENT} />
            <text x="244" y={e.y + 21} fill={ACCENT} fontFamily="var(--font-mono)" fontSize="9">
              {e.label}
            </text>
            <path d={`M372 ${e.y + 17} L 418 ${e.y + 17}`} fill="none" stroke={RULE} strokeWidth="1.3" />
            <rect x="418" y={e.y + 3} width="132" height="28" rx="5" fill={SURFACE} stroke={RULE} />
            <text x="430" y={e.y + 21} fill={MUTED} fontFamily="var(--font-mono)" fontSize="9">
              {e.count}
            </text>
          </g>
        ))}
      </svg>
    </figure>
  );
}
