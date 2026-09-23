import type { RansomwareStats } from "@/hooks/useRansomware";
import { ransomwareGroupColor } from "@/utils/ransomwareColors";

import type { LeakFilters } from "./leakFilters";
import styles from "./LeakWatchRail.module.css";

const PRESETS = [
  { days: 1, label: "24h" },
  { days: 7, label: "7d" },
  { days: 30, label: "30d" },
  { days: 3650, label: "All" },
];

function toggleInSet(set: string[], v: string): string[] {
  return set.includes(v) ? set.filter((x) => x !== v) : [...set, v];
}

/**
 * The leak-watch facet rail.
 *
 * Split out of the feed so it can sit beside the page header as a full-height
 * column — the same shape as the search page's facet rail and the rule
 * library's — rather than as a sticky card inside the feed's own scroll area.
 * Its state lives in RansomwareSection, which owns both this and the feed.
 */
export function LeakWatchRail({
  filters,
  onChange,
  stats,
}: {
  filters: LeakFilters;
  onChange: (patch: Partial<LeakFilters>) => void;
  stats?: RansomwareStats;
}) {
  return (
    <>
      <div className={styles.grp}>
        <div className={styles.toggleRow}>
          <span className={styles.toggleLbl}>Watched only</span>
          <label className={styles.switch}>
            <input
              type="checkbox"
              checked={filters.watchedOnly}
              onChange={(e) => onChange({ watchedOnly: e.target.checked })}
            />
            <span className={styles.switchTrack} />
            <span className={styles.switchKnob} />
          </label>
        </div>
      </div>

      <FacetGroup
        title="Ransomware group"
        selected={filters.groups}
        onClear={() => onChange({ groups: [] })}
        items={(stats?.groups ?? []).map((g) => ({
          value: g.name,
          label: g.name,
          count: g.victims,
          color: ransomwareGroupColor(g.color),
        }))}
        onToggle={(v) => onChange({ groups: toggleInSet(filters.groups, v) })}
      />
      <FacetGroup
        title="Sector"
        selected={filters.sectors}
        onClear={() => onChange({ sectors: [] })}
        items={(stats?.sectors ?? []).map((s) => ({ value: s.sector, label: s.label, count: s.victims }))}
        onToggle={(v) => onChange({ sectors: toggleInSet(filters.sectors, v) })}
      />
      <FacetGroup
        title="Country"
        selected={filters.countries}
        onClear={() => onChange({ countries: [] })}
        items={(stats?.countries ?? [])
          .filter((c) => c.iso_code)
          .map((c) => ({ value: c.iso_code as string, label: `${c.name} (${c.iso_code})`, count: c.victims }))}
        onToggle={(v) => onChange({ countries: toggleInSet(filters.countries, v) })}
      />

      <div className={styles.grp}>
        <h4 className={styles.railH4}>First seen</h4>
        <div className={styles.presets}>
          {PRESETS.map((p) => (
            <button
              key={p.days}
              className={filters.days === p.days ? styles.presetOn : styles.preset}
              onClick={() => onChange({ days: p.days })}
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>
    </>
  );
}

function FacetGroup({
  title,
  items,
  selected,
  onToggle,
  onClear,
}: {
  title: string;
  items: Array<{ value: string; label: string; count: number; color?: string }>;
  selected: string[];
  onToggle: (v: string) => void;
  onClear: () => void;
}) {
  if (items.length === 0) return null;
  return (
    <div className={styles.grp}>
      <h4 className={styles.railH4}>
        {title}
        {selected.length > 0 && (
          <button className={styles.clr} onClick={onClear}>
            clear
          </button>
        )}
      </h4>
      <div>
        {items.map((it) => {
          const on = selected.includes(it.value);
          return (
            <div key={it.value} className={on ? styles.facetOn : styles.facet} onClick={() => onToggle(it.value)} role="button" tabIndex={0}>
              <span className={styles.facetBox}>
                {on && (
                  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3.5">
                    <path d="m5 12 5 5L20 6" />
                  </svg>
                )}
              </span>
              {it.color && <span className={styles.facetDot} style={{ background: it.color }} />}
              <span className={styles.facetName}>{it.label}</span>
              <span className={styles.facetCnt}>{it.count}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
