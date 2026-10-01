/**
 * ObservableLifecycleStrip — the indicator's clock on the same lifecycle rail
 * CVEs use: first sighting → latest sighting → projected expiry. A new
 * sighting resets decay, so the expiry node is a projection, not a deadline.
 * Kinds that never decay (hashes, host artifacts, fingerprints) end at the
 * latest sighting with a "no decay" note instead of an expiry node.
 */
import type { ObservableResponse } from "@/api/types";
import styles from "./entityProfile.module.css";

function shortDate(iso: string): string {
  const d = new Date(iso.includes("T") ? iso : `${iso}T00:00:00`);
  const opts: Intl.DateTimeFormatOptions = { month: "short", day: "numeric" };
  if (d.getFullYear() !== new Date().getFullYear()) opts.year = "numeric";
  return d.toLocaleDateString(undefined, opts);
}

interface Node {
  key: string;
  label: string;
  date: string | null;
  sub: string | null;
  kind: "start" | "sight" | "due";
}

/** "Latest report · 3" when articles back the value; a list-feed-only row says
 *  so instead of counting its export variants as reports. */
function lifecycleSightingLabel(d: ObservableResponse): string {
  const reports = d.report_count ?? 0;
  const feeds = d.feed_source_count ?? 0;
  if (reports > 1) return `Latest report · ${reports}`;
  if (reports === 1) return feeds ? "Only report (+ feed)" : "Only report";
  if (feeds) return `Listed on ${feeds} indicator feed${feeds === 1 ? "" : "s"}`;
  return d.sighting_count > 1 ? `Latest sighting · ${d.sighting_count}` : "Only sighting";
}

export function ObservableLifecycleStrip({ detail }: { detail: ObservableResponse | undefined }) {
  if (!detail?.first_seen_at) return null;

  const decays = detail.decay_half_life_days != null;
  const nodes: Node[] = [
    { key: "first", label: "First seen", date: detail.first_seen_at, sub: null, kind: "start" },
    {
      key: "last",
      label: lifecycleSightingLabel(detail),
      date: detail.last_seen_at,
      sub: detail.confidence_pinned ? "pinned" : decays ? "clock reset" : "no decay",
      kind: "sight",
    },
  ];
  if (decays && detail.expires_at && !detail.confidence_pinned) {
    nodes.push({
      key: "expiry",
      label: detail.status === "expired" ? "Expired" : "Projected expiry",
      date: detail.expires_at,
      sub: `${detail.decay_half_life_days}d half-life`,
      kind: "due",
    });
  }

  // Proportional positions by date, spread to a minimum gap so labels hold.
  const ts = nodes.map((n) => (n.date ? new Date(n.date).getTime() : 0));
  const span = Math.max(ts[ts.length - 1] - ts[0], 1);
  let fracs = ts.map((t) => (t - ts[0]) / span);
  const MIN_GAP = 0.22;
  for (let i = 1; i < fracs.length; i++) fracs[i] = Math.max(fracs[i], fracs[i - 1] + MIN_GAP);
  // Normalize so the last node lands at 1 — it renders pinned to the track's
  // right edge, and a single-sighting row (first == last) would otherwise show
  // a 22% progress bar under a dot at 100%.
  const end = fracs[fracs.length - 1];
  if (end > 0) fracs = fracs.map((f) => f / end);

  const ioc = "var(--entity-ioc, #d946ef)";
  const sightIdx = 1;

  return (
    <div className={styles.lifecycleCard}>
      <div className={styles.lcTrack}>
        <div className={styles.lcBaseline} />
        <div
          className={styles.lcProgress}
          style={{
            width: `${fracs[sightIdx] * 100}%`,
            background: `linear-gradient(90deg, var(--text-muted), ${ioc})`,
          }}
        />
        {nodes.map((n, i) => (
          <span
            key={n.key}
            className={`${styles.lcDot} ${n.kind === "due" ? styles.lcDotDue : styles.lcDotStart}`}
            style={{
              ...(i === nodes.length - 1 ? { right: 0 } : { left: `${fracs[i] * 100}%` }),
              ...(n.kind === "sight"
                ? { background: ioc, boxShadow: `0 0 0 3px color-mix(in srgb, ${ioc} 25%, transparent)` }
                : {}),
            }}
          />
        ))}
      </div>
      <div className={styles.lcLabels}>
        {nodes.map((n, i) => {
          const isLast = i === nodes.length - 1;
          return (
            <div
              key={n.key}
              className={`${styles.lcLabel} ${isLast ? styles.lcLabelEnd : ""}`}
              style={isLast ? { right: 0 } : { left: `${fracs[i] * 100}%` }}
            >
              <div className={styles.lcLabelName} style={n.kind === "sight" ? { color: ioc } : undefined}>
                {n.label}
              </div>
              <div className={styles.lcLabelDate}>
                {n.date ? shortDate(n.date) : "—"}
                {n.sub ? ` · ${n.sub}` : ""}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
