import { Chip, Panel } from "@/components/primitives";
import { type GroupStat, useRansomwareStats } from "@/hooks/useRansomware";
import { ransomwareGroupColor } from "@/utils/ransomwareColors";

import { VictimsTimeChart } from "./VictimsTimeChart";
import styles from "./RansomwareLandscape.module.css";

const RANGES = [
  { days: 30, label: "30d" },
  { days: 90, label: "90d" },
  { days: 365, label: "1y" },
];

function GroupName({
  group,
  onPivotGroup,
}: {
  group: GroupStat | null;
  onPivotGroup?: (groupId: string, groupName?: string) => void;
}) {
  if (!group) return <>—</>;
  const dot = <span className={styles.gdot} style={{ background: ransomwareGroupColor(group.color) }} />;
  if (group.id && onPivotGroup) {
    return (
      <button
        className={styles.groupNameBtn}
        onClick={() => onPivotGroup(group.id as string, group.name)}
        title={`Open ${group.name} profile`}
      >
        {dot}
        {group.name}
      </button>
    );
  }
  return (
    <>
      {dot}
      {group.name}
    </>
  );
}

function trend(pct: number, up: boolean) {
  const cls = up ? styles.up : styles.dn;
  return (
    <span className={cls}>
      {up ? "▲" : "▼"} {Math.abs(pct)}%
    </span>
  );
}

/** Range options for the header's window switch, which the section owns. */
export const LANDSCAPE_RANGES = RANGES.map((r) => ({ value: String(r.days), label: r.label }));

export function RansomwareLandscape({
  days,
  onPivotGroup,
}: {
  /** Owned by RansomwareSection so the switch can live in the page header. */
  days: number;
  onPivotGroup?: (groupId: string, groupName?: string) => void;
}) {
  const { data, isLoading } = useRansomwareStats(days);

  return (
    <div className={styles.root}>

      {isLoading && !data ? (
        <div className={styles.loading}>Loading…</div>
      ) : !data ? null : (
        <>
          <div className={styles.kpis}>
            <div className={styles.kpi}>
              <div className={styles.k}>Victims · {days}d</div>
              <div className={styles.v}>{data.totals.victims.toLocaleString()}</div>
              <div className={styles.d}>
                {trend(data.totals.victims_wow, data.totals.victims_wow >= 0)}{" "}
                <span className={styles.muted}>vs prior {days}d</span>
              </div>
            </div>
            <div className={styles.kpi}>
              <div className={styles.k}>Most active group</div>
              <div className={styles.vsm}>
                <GroupName group={data.most_active_group} onPivotGroup={onPivotGroup} />
              </div>
              <div className={styles.d}>
                <span className={styles.muted}>
                  {data.most_active_group
                    ? `${data.most_active_group.victims} victims · ${data.most_active_group.share}% share`
                    : "no data"}
                </span>
              </div>
            </div>
            <div className={styles.kpi}>
              <div className={styles.k}>Fastest riser</div>
              <div className={styles.vsm}>
                <GroupName group={data.fastest_riser} onPivotGroup={onPivotGroup} />
              </div>
              <div className={styles.d}>
                {data.fastest_riser && trend(data.fastest_riser.wow_trend, data.fastest_riser.trend_up)}{" "}
                <span className={styles.muted}>WoW volume</span>
              </div>
            </div>
            <div className={styles.kpi}>
              <div className={styles.k}>Sectors hit</div>
              <div className={styles.v}>{data.totals.sectors_hit}</div>
              <div className={styles.d}>
                <span className={styles.muted}>{data.sectors[0] ? `${data.sectors[0].label} leads (${data.sectors[0].share}%)` : ""}</span>
              </div>
            </div>
            <div className={styles.kpi}>
              <div className={styles.k}>Watchlist exposure</div>
              <div className={styles.vCrit}>{data.totals.watchlist_hits}</div>
              <div className={styles.d}>
                <span className={styles.muted}>watched orgs / sectors hit</span>
              </div>
            </div>
          </div>

          <Panel
            title="Victim disclosures over time"
            subtitle="Weekly new-victim postings across all tracked leak sites"
            surface="card"
            padding="lg"
            divider={false}
            className={styles.card}
          >
            <VictimsTimeChart points={data.timeseries} />
          </Panel>

          <div className={styles.two}>
            <Panel
              title="Most active groups"
              subtitle="Victim count · share · week-over-week"
              surface="card"
              padding="lg"
              divider={false}
              className={styles.card}
            >
              <div className={styles.bars}>
                {data.groups.map((g) => {
                  const clickable = Boolean(g.id && onPivotGroup);
                  return (
                  <div
                    key={g.id ?? g.name}
                    className={clickable ? `${styles.bar} ${styles.barClickable}` : styles.bar}
                    onClick={clickable ? () => onPivotGroup?.(g.id as string, g.name) : undefined}
                    role={clickable ? "button" : undefined}
                    tabIndex={clickable ? 0 : undefined}
                    title={clickable ? `Open ${g.name} profile` : undefined}
                  >
                    <span className={styles.lblMono}>
                      <span className={styles.gdot} style={{ background: ransomwareGroupColor(g.color) }} />
                      {g.name}
                    </span>
                    <span className={styles.track}>
                      <span
                        className={styles.fill}
                        style={{
                          width: `${data.groups[0] ? (g.victims / data.groups[0].victims) * 100 : 0}%`,
                          background: ransomwareGroupColor(g.color),
                        }}
                      />
                    </span>
                    <span className={styles.val}>
                      {g.victims}
                      <span className={g.trend_up ? styles.upSm : styles.dnSm}>
                        {g.trend_up ? "▲" : "▼"}
                        {Math.abs(g.wow_trend)}%
                      </span>
                    </span>
                  </div>
                  );
                })}
              </div>
            </Panel>

            <Panel
              title="Sectors targeted"
              subtitle="Share of disclosed victims by industry"
              surface="card"
              padding="lg"
              divider={false}
              className={styles.card}
            >
              <div className={styles.bars}>
                {data.sectors.map((s) => (
                  <div key={s.sector} className={styles.bar}>
                    <span className={styles.lbl}>{s.label}</span>
                    <span className={styles.track}>
                      <span
                        className={styles.fillAccent}
                        style={{ width: `${data.sectors[0] ? (s.victims / data.sectors[0].victims) * 100 : 0}%` }}
                      />
                    </span>
                    <span className={styles.val}>
                      {s.victims}
                      <span className={styles.share}>{s.share}%</span>
                    </span>
                  </div>
                ))}
              </div>
            </Panel>
          </div>

          <div className={styles.two}>
            <Panel
              title="Victims by country"
              subtitle="Where disclosed organizations are headquartered"
              surface="card"
              padding="lg"
              divider={false}
              className={styles.card}
            >
              <div className={styles.geo}>
                {data.countries.map((c) => (
                  <div key={c.id ?? c.name} className={styles.georow}>
                    <span className={styles.gtrack}>
                      <span
                        className={styles.gfill}
                        style={{ width: `${data.countries[0] ? (c.victims / data.countries[0].victims) * 100 : 0}%` }}
                      />
                      <span className={styles.gname}>
                        {c.name}
                        {c.iso_code && <span className={styles.iso}>{c.iso_code}</span>}
                      </span>
                    </span>
                    <span className={styles.gval}>{c.victims}</span>
                  </div>
                ))}
                {data.countries.length === 0 && <div className={styles.emptySmall}>No country data.</div>}
              </div>
            </Panel>

            <Panel
              title="Your watchlist exposure"
              subtitle={`Watched entities against ${days}d disclosures`}
              surface="card"
              padding="lg"
              divider={false}
              className={styles.card}
            >
              <div className={styles.expo}>
                {data.watchlist_exposure.map((e, i) => (
                  <div key={i} className={e.hit ? styles.erHit : styles.er}>
                    <span className={styles.eico}>{e.hit ? "🎯" : "○"}</span>
                    <span className={styles.et}>
                      <div className={styles.en}>{e.name}</div>
                      <div className={styles.es}>
                        {e.kind} · {e.detail}
                      </div>
                    </span>
                    {e.hit ? (
                      <Chip tone="solid" tint="var(--entity-victim)" className={styles.badgeRed}>
                        HIT
                      </Chip>
                    ) : (
                      <span className={styles.badgeOk}>CLEAR</span>
                    )}
                  </div>
                ))}
                {data.watchlist_exposure.length === 0 && (
                  <div className={styles.emptySmall}>No watched groups, orgs, or sectors yet.</div>
                )}
              </div>
            </Panel>
          </div>
        </>
      )}
    </div>
  );
}
