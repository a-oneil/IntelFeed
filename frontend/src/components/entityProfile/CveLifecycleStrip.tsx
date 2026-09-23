/**
 * CveLifecycleStrip — the CVE's story as a node-and-track rail under the pulse
 * line: Disclosed → PoC public → Exploited in wild → KEV added → Remediation
 * due. Reached stages are filled dots on a progress line (the latest reached
 * gets a glow ring); the remediation deadline is a hollow circle at the end.
 * Nodes sit proportionally by date where dates exist, with a minimum gap so
 * labels stay legible. Data the profile already fetches — no new pipeline.
 */
import type { CVE, EntitySearchResult } from "@/api/types";
import { extractNvd } from "./cveRefs";
import { isKnownExploited } from "./entityProfileConfig";
import styles from "./entityProfile.module.css";

type StageKind = "start" | "poc" | "wild" | "kev" | "due";

/** Compact node date: "Aug 6", with the year only when it isn't this year —
 * the rail's labels sit close together and long dates collide. */
function shortDate(iso: string): string {
  const d = new Date(iso.includes("T") ? iso : `${iso}T00:00:00`);
  const opts: Intl.DateTimeFormatOptions = { month: "short", day: "numeric" };
  if (d.getFullYear() !== new Date().getFullYear()) opts.year = "numeric";
  return d.toLocaleDateString(undefined, opts);
}

interface Stage {
  kind: StageKind;
  label: string;
  date: string | null;
  sub: string | null;
}

/** Node positions: proportional to dates where known, undated stages
 * interpolated between dated neighbors, then spread to a minimum gap. */
function positions(stages: Stage[]): number[] {
  const n = stages.length;
  if (n === 1) return [0];
  const ts = stages.map((s) => (s.date ? new Date(s.date).getTime() : null));
  const even = stages.map((_, i) => i / (n - 1));
  let fracs = even;
  const first = ts[0];
  const last = ts[n - 1];
  if (first != null && last != null && last > first) {
    fracs = ts.map((t, i) => {
      if (t != null) return Math.min(Math.max((t - first) / (last - first), 0), 1);
      // undated: midpoint between nearest dated neighbors
      let lo = i - 1;
      while (lo >= 0 && ts[lo] == null) lo--;
      let hi = i + 1;
      while (hi < n && ts[hi] == null) hi++;
      const a = lo >= 0 && ts[lo] != null ? (ts[lo]! - first) / (last - first) : 0;
      const b = hi < n && ts[hi] != null ? (ts[hi]! - first) / (last - first) : 1;
      return (a + b) / 2;
    });
  }
  // Enforce a readable minimum gap, then rescale into [0,1] if it overflowed.
  const minGap = Math.min(0.16, 1 / (n - 1) / 1.4);
  const spread = [...fracs];
  for (let i = 1; i < n; i++) spread[i] = Math.max(spread[i], spread[i - 1] + minGap);
  const overflow = spread[n - 1];
  return overflow > 1 ? spread.map((f) => f / overflow) : spread;
}

export function CveLifecycleStrip({
  entity,
  cveDetail,
}: {
  entity: EntitySearchResult;
  cveDetail?: CVE;
}) {
  if (!cveDetail) return null;
  const nvd = extractNvd(cveDetail.nvd_data);
  const timeline = Array.isArray(cveDetail.timeline) ? cveDetail.timeline : [];
  const timelineDate = (pattern: RegExp): string | null =>
    timeline.find((t) => t?.event && pattern.test(t.event))?.date ?? null;

  const stages: Stage[] = [];

  const disclosed = nvd.published ?? timelineDate(/disclos|publish/i);
  if (disclosed) stages.push({ kind: "start", label: "Disclosed", date: disclosed, sub: null });
  else if (cveDetail.first_seen_at)
    stages.push({ kind: "start", label: "First seen", date: cveDetail.first_seen_at, sub: null });

  const pocCount = cveDetail.github_poc_count ?? entity.github_poc_count ?? 0;
  if (pocCount > 0 || cveDetail.metasploit_module) {
    const repos = pocCount > 0 ? ` · ${pocCount} repo${pocCount === 1 ? "" : "s"}` : "";
    stages.push({
      kind: "poc",
      label: `PoC public${repos}`,
      date: timelineDate(/poc|proof.of.concept|exploit code/i),
      sub: null,
    });
  }

  const availability = (cveDetail.exploit_availability ?? entity.exploit_availability ?? "").toLowerCase();
  if (availability === "active_exploitation") {
    stages.push({
      kind: "wild",
      label: "Exploited in wild",
      date: timelineDate(/exploit(ed)? in|in.the.wild|active exploit/i),
      sub: null,
    });
  }

  const isKev = isKnownExploited({
    is_kev: cveDetail.is_kev ?? entity.is_kev,
    exploit_status: cveDetail.exploit_status ?? entity.exploit_status,
  });
  const kevAdded = cveDetail.kev_date_added ?? entity.kev_date_added;
  if (isKev) stages.push({ kind: "kev", label: "KEV added", date: kevAdded ?? null, sub: null });

  const kevDue = cveDetail.kev_due_date ?? entity.kev_due_date;
  if (kevDue) {
    const days = Math.round((new Date(kevDue).getTime() - Date.now()) / 86_400_000);
    stages.push({
      kind: "due",
      label: days >= 0 ? "Remediation due" : "Remediation overdue",
      date: kevDue,
      sub: days >= 0 ? `in ${days}d` : `${-days}d ago`,
    });
  }

  // A strip with one stage says nothing the Snapshot doesn't.
  if (stages.length < 2) return null;

  const fracs = positions(stages);
  // Progress runs to the latest *reached* stage; the due date is the future.
  const reached = stages.map((s, i) => (s.kind !== "due" ? i : -1)).filter((i) => i >= 0);
  const lastReached = reached.length ? reached[reached.length - 1] : 0;
  const glowIdx = lastReached; // the newest reached stage carries the ring

  const dotClass: Record<StageKind, string> = {
    start: styles.lcDotStart,
    poc: styles.lcDotPoc,
    wild: styles.lcDotWild,
    kev: styles.lcDotWild,
    due: styles.lcDotDue,
  };
  const labelClass: Record<StageKind, string> = {
    start: "",
    poc: "",
    wild: "",
    kev: styles.lcLabelHot,
    due: styles.lcLabelDue,
  };

  return (
    <div className={styles.lifecycleCard}>
      <div className={styles.lcTrack}>
        <div className={styles.lcBaseline} />
        <div className={styles.lcProgress} style={{ width: `${fracs[lastReached] * 100}%` }} />
        {stages.map((s, i) => (
          <span
            key={s.kind}
            className={`${styles.lcDot} ${dotClass[s.kind]} ${i === glowIdx ? styles.lcDotGlow : ""}`}
            style={i === stages.length - 1 ? { right: 0 } : { left: `${fracs[i] * 100}%` }}
          />
        ))}
      </div>
      <div className={styles.lcLabels}>
        {stages.map((s, i) => {
          const isLast = i === stages.length - 1;
          // Labels near the right edge grow leftward so they never run into
          // the right-aligned final label.
          const nearEnd = !isLast && fracs[i] > 0.8;
          return (
            <div
              key={s.kind}
              className={`${styles.lcLabel} ${isLast || nearEnd ? styles.lcLabelEnd : ""}`}
              style={
                isLast
                  ? { right: 0 }
                  : nearEnd
                    ? { right: `${(1 - fracs[i]) * 100}%`, marginRight: "24px" }
                    : { left: `${fracs[i] * 100}%` }
              }
            >
              <div className={`${styles.lcLabelName} ${labelClass[s.kind]}`}>{s.label}</div>
              <div className={styles.lcLabelDate}>
                {s.date ? shortDate(s.date) : "—"}
                {s.sub ? ` · ${s.sub}` : ""}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
