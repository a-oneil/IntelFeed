import { useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";

import { useDeleteWatch, useUpsertWatch } from "@/hooks/useWatchlist";
import { type Disclosure, type RansomwareStats, useDisclosures } from "@/hooks/useRansomware";
import { Chip } from "@/components/primitives/Chip";
import { ransomwareGroupColor } from "@/utils/ransomwareColors";

import { ALL_TIME_DAYS, type LeakFilters, toDisclosureFilters } from "./leakFilters";
import styles from "./LeakWatchFeed.module.css";

function hoursSince(iso: string): number {
  return (Date.now() - new Date(iso).getTime()) / 3.6e6;
}
function rel(iso: string): string {
  const h = hoursSince(iso);
  if (h < 1) return "just now";
  if (h < 24) return `${Math.floor(h)}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}
function dayBucket(iso: string): string {
  const h = hoursSince(iso);
  if (h < 24) return "Today";
  if (h < 48) return "Yesterday";
  if (h < 168) return "This week";
  return "Earlier";
}

function WatchStar({ victimId, name, watched }: { victimId: string; name: string; watched: boolean }) {
  const upsert = useUpsertWatch();
  const del = useDeleteWatch();
  const qc = useQueryClient();
  const busy = upsert.isPending || del.isPending;
  const toggle = async (e: React.MouseEvent) => {
    e.stopPropagation();
    if (watched) await del.mutateAsync({ entity_type: "ransomware_victim", entity_id: victimId });
    else await upsert.mutateAsync({ entity_type: "ransomware_victim", entity_id: victimId, mode: "watch" });
    qc.invalidateQueries({ queryKey: ["ransomware"] });
  };
  return (
    <button
      className={watched ? styles.starOn : styles.star}
      onClick={toggle}
      disabled={busy}
      title={watched ? `Unwatch ${name}` : `Watch ${name}`}
      aria-label={watched ? "Unwatch organization" : "Watch organization"}
    >
      <svg width="16" height="16" viewBox="0 0 24 24" fill={watched ? "currentColor" : "none"} stroke="currentColor" strokeWidth="2">
        <path d="m12 2 3 6.5 7 .8-5 4.8 1.3 7L12 18l-6.6 3.1 1.3-7-5-4.8 7-.8Z" />
      </svg>
    </button>
  );
}

type Divider = { divider: string; count: number };
type FeedRow = Disclosure | Divider;

export function LeakWatchFeed({
  filters,
  onChange,
  stats,
  onPivotGroup,
}: {
  filters: LeakFilters;
  onChange: (patch: Partial<LeakFilters>) => void;
  stats?: RansomwareStats;
  onPivotGroup?: (groupId: string, groupName?: string) => void;
}) {
  const { days, sort } = filters;
  const [open, setOpen] = useState<string | null>(null);
  const [alertDismissed, setAlertDismissed] = useState(false);

  const query = useMemo(() => toDisclosureFilters(filters), [filters]);
  const { data, fetchNextPage, hasNextPage, isFetching, isFetchingNextPage } = useDisclosures(query);

  const items = useMemo(() => data?.pages.flatMap((p) => p.items) ?? [], [data]);
  const total = data?.pages[0]?.total ?? 0;

  const alert = useMemo(() => items.find((d) => d.watched && d.is_new) ?? null, [items]);

  const rows: FeedRow[] = useMemo(() => {
    if (sort !== "recent") return items;
    const out: FeedRow[] = [];
    let last: string | null = null;
    for (const d of items) {
      const b = dayBucket(d.posted_at);
      if (b !== last) {
        last = b;
        out.push({ divider: b, count: items.filter((x) => dayBucket(x.posted_at) === b).length });
      }
      out.push(d);
    }
    return out;
  }, [items, sort]);

  const stat = stats?.totals;

  return (
    <div className={styles.root}>
      {alert && !alertDismissed && (
        <div className={styles.alert}>
          <Chip tone="solid" tint="var(--entity-victim)" className={styles.alertBadge}>
            WATCHLIST HIT
          </Chip>
          <div className={styles.alertMsg}>
            <b className={styles.org}>{alert.victim_name}</b> — a watched organization — was posted to{" "}
            <b>{alert.group_name ?? "an unattributed group"}</b>&apos;s leak site <b>{rel(alert.posted_at)}</b>.
          </div>
          <button className={styles.alertX} onClick={() => setAlertDismissed(true)} aria-label="Dismiss">
            ✕
          </button>
        </div>
      )}

      {stat && (
        <div className={styles.stats}>
          <div className={styles.stat}>
            <div className={styles.sk}>New victims · {days >= ALL_TIME_DAYS ? "all" : `${days}d`}</div>
            <div className={styles.sv}>{stat.victims.toLocaleString()}</div>
            <div className={styles.ssub}>
              <span className={stat.victims_wow >= 0 ? styles.up : styles.dn}>
                {stat.victims_wow >= 0 ? "▲" : "▼"} {Math.abs(stat.victims_wow)}%
              </span>{" "}
              vs prior
            </div>
          </div>
          <div className={styles.stat}>
            <div className={styles.sk}>Active groups</div>
            <div className={styles.sv}>{stat.groups_active}</div>
            <div className={styles.ssub}>{stats?.groups.slice(0, 3).map((g) => g.name).join(", ")}</div>
          </div>
          <div className={styles.stat}>
            <div className={styles.sk}>Top sector hit</div>
            <div className={styles.svSm}>{stats?.sectors[0]?.label ?? "—"}</div>
            <div className={styles.ssub}>{stats?.sectors[0] ? `${stats.sectors[0].victims} victims` : ""}</div>
          </div>
          <div className={styles.statCrit}>
            <div className={styles.sk}>Watchlist hits</div>
            <div className={styles.svCrit}>{stat.watchlist_hits}</div>
            <div className={styles.ssub}>watched orgs / sectors</div>
          </div>
        </div>
      )}

      <main className={styles.feed}>
          <div className={styles.feedHead}>
            <span className={styles.count}>
              <b>{total}</b> disclosures
            </span>
            <span className={styles.sortWrap}>
              Sort
              <select value={sort} onChange={(e) => onChange({ sort: e.target.value as LeakFilters["sort"] })}>
                <option value="recent">Newest first</option>
                <option value="group">By group</option>
                <option value="sector">By sector</option>
              </select>
            </span>
          </div>

          {rows.length === 0 && !isFetching && <div className={styles.empty}>No disclosures match these filters.</div>}

          {rows.map((r) =>
            "divider" in r ? (
              <div key={`div-${r.divider}`} className={styles.daydiv}>
                <span>{r.divider}</span>
                <span className={styles.daydivN}>{r.count}</span>
              </div>
            ) : (
              <Row key={r.id} d={r} open={open === r.id} onToggle={() => setOpen(open === r.id ? null : r.id)} onPivotGroup={onPivotGroup} />
            ),
          )}

          {hasNextPage && (
            <button className={styles.loadMore} onClick={() => fetchNextPage()} disabled={isFetchingNextPage}>
              {isFetchingNextPage ? "Loading…" : "Load more"}
            </button>
          )}
      </main>
    </div>
  );
}

function Row({
  d,
  open,
  onToggle,
  onPivotGroup,
}: {
  d: Disclosure;
  open: boolean;
  onToggle: () => void;
  onPivotGroup?: (groupId: string, groupName?: string) => void;
}) {
  return (
    <div className={`${styles.row} ${d.watched ? styles.rowWatched : ""} ${open ? styles.rowOpen : ""}`}>
      <div className={styles.rowMain} onClick={onToggle}>
        <span className={d.is_new ? styles.pulseNew : styles.pulse} />
        <div className={styles.cellMain}>
          <div className={styles.orgLine}>
            <span className={styles.orgName}>{d.victim_name}</span>
            {d.domain && <span className={styles.dom}>{d.domain}</span>}
            {d.is_new && (
              <Chip tone="solid" size="sm" tint="var(--entity-victim)" className={styles.newtag}>
                NEW
              </Chip>
            )}
            {d.watched && (
              <Chip tone="solid" size="sm" tint="var(--accent)" className={styles.watchedtag}>
                WATCHED
              </Chip>
            )}
          </div>
          <div className={styles.metaLine}>
            {d.group_id && onPivotGroup ? (
              <button
                className={styles.chipBtn}
                onClick={(e) => {
                  e.stopPropagation();
                  onPivotGroup(d.group_id as string, d.group_name ?? undefined);
                }}
                title={`Open ${d.group_name} profile`}
              >
                <span className={styles.chipDot} style={{ background: ransomwareGroupColor(d.group_color) }} />
                <b>{d.group_name}</b>
              </button>
            ) : (
              <span className={styles.chip}>
                <span className={styles.chipDot} style={{ background: ransomwareGroupColor(d.group_color) }} />
                <b>{d.group_name ?? "Unattributed"}</b>
              </span>
            )}
            {d.sector_label && (
              <Chip
                pill
                tone="outline"
                tint="var(--border)"
                fg="var(--text-secondary)"
                truncate
                title={d.sector_label}
                className={styles.chipSector}
              >
                {d.sector_label}
              </Chip>
            )}
            {d.country_code && <span className={styles.chipCountry}>{d.country_code}</span>}
          </div>
          {open && (
            <div className={styles.detail}>
              <div className={styles.dgrid}>
                <div>
                  <div className={styles.dk}>Data claimed</div>
                  <div className={styles.dv}>{d.claimed_data ?? "—"}</div>
                </div>
                <div>
                  <div className={styles.dk}>First seen</div>
                  <div className={styles.dv}>{rel(d.posted_at)}</div>
                </div>
                {d.published_at && (
                  <div>
                    <div className={styles.dk}>Publish deadline</div>
                    <div className={styles.dv}>{new Date(d.published_at).toLocaleDateString()}</div>
                  </div>
                )}
                <div>
                  <div className={styles.dk}>Source</div>
                  <div className={styles.dv}>{d.source}</div>
                </div>
              </div>
              <div className={styles.acts}>
                <WatchStar victimId={d.victim_id} name={d.victim_name} watched={d.watched} />
                {d.group_id && onPivotGroup && (
                  <button
                    className={styles.actBtn}
                    onClick={(e) => {
                      e.stopPropagation();
                      onPivotGroup(d.group_id as string, d.group_name ?? undefined);
                    }}
                  >
                    ↳ Pivot to {d.group_name} profile
                  </button>
                )}
                {d.leak_site_url && (
                  <a className={styles.actBtn} href={d.leak_site_url} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}>
                    ⤓ Leak site post
                  </a>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
      <div className={styles.cellRight}>
        <span className={styles.seen}>{rel(d.posted_at)}</span>
        <WatchStar victimId={d.victim_id} name={d.victim_name} watched={d.watched} />
      </div>
    </div>
  );
}
