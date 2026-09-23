import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { toast } from "sonner";

import {
  useExposureBoard,
  useStack,
  useUpsertWatch,
  useDeleteWatch,
  type StackExposureItem,
  type StackExposureResponse,
} from "@/hooks/useWatchlist";
import { useVendors, useProducts } from "@/hooks/useIntelligence";
import { Chip, PageHeader, Segmented } from "@/components/primitives";
import styles from "./ExposurePage.module.css";

const WEEK_MS = 7 * 86_400_000;

function isRecent(iso: string | null): boolean {
  if (!iso) return false;
  const t = new Date(iso).getTime();
  return !Number.isNaN(t) && Date.now() - t <= WEEK_MS;
}
function severityClass(sev: string | null): string {
  const s = (sev ?? "").toUpperCase();
  if (s === "CRITICAL") return styles.sevCritical;
  if (s === "HIGH") return styles.sevHigh;
  if (s === "MEDIUM") return styles.sevMedium;
  return styles.sevLow;
}
function relAge(iso: string | null): string {
  if (!iso) return "—";
  const days = Math.floor((Date.now() - new Date(iso).getTime()) / 86_400_000);
  if (Number.isNaN(days)) return "—";
  if (days <= 0) return "today";
  if (days < 7) return `${days}d ago`;
  if (days < 30) return `${Math.floor(days / 7)}w ago`;
  if (days < 365) return `${Math.floor(days / 30)}mo ago`;
  return `${Math.floor(days / 365)}y ago`;
}

export function ExposurePage() {
  const [view, setView] = useState<"vulns" | "follow">("vulns");
  const { data, isLoading, isError } = useExposureBoard();

  return (
    <div className={styles.page}>
      <PageHeader
        title="Vendor Watch"
        flush
        actions={
          <Segmented<"vulns" | "follow">
            label="Vendor Watch views"
            role="tablist"
            value={view}
            onChange={setView}
            options={[
              { value: "vulns", label: "Vulnerabilities" },
              { value: "follow", label: "Following" },
            ]}
          />
        }
        subtitle={
          view === "vulns"
            ? "New and actively-exploited vulnerabilities in the vendors and products you follow — with detection-library coverage."
            : "Follow the vendors and products you care about. Their vulnerabilities surface here and in your Radar."
        }
      />

      {isLoading && <div className={styles.state}>Loading…</div>}
      {isError && <div className={styles.state}>Couldn&rsquo;t load Vendor Watch.</div>}
      {data && view === "vulns" && <VulnView data={data} onFollow={() => setView("follow")} />}
      {data && view === "follow" && <FollowView data={data} />}
    </div>
  );
}

/* ───────────────────── Vulnerabilities ───────────────────── */

type Filter = { kevOnly?: boolean; epssHigh?: boolean; noRule?: boolean } | null;
type Sort = "new" | "trending" | "epss";

export function VulnView({ data, onFollow }: { data: StackExposureResponse; onFollow: () => void }) {
  const navigate = useNavigate();
  const [filter, setFilter] = useState<Filter>(null);
  const [sort, setSort] = useState<Sort>("new");
  const { stack, counts, assets, items } = data;

  const newThisWeek = useMemo(() => items.filter((i) => isRecent(i.published_at)).length, [items]);
  const trending = useMemo(
    () => items.reduce<StackExposureItem | null>((top, i) => (i.entry_count > (top?.entry_count ?? 0) ? i : top), null),
    [items],
  );

  const rows = useMemo(() => {
    const matched = !filter
      ? items
      : items.filter((i) => {
          if (filter.kevOnly && !i.is_kev) return false;
          if (filter.epssHigh && !(i.epss_score != null && i.epss_score >= 0.5)) return false;
          if (filter.noRule && i.posture !== "no_rule") return false;
          return true;
        });
    const cp = [...matched];
    if (sort === "new") cp.sort((a, b) => tms(b.published_at) - tms(a.published_at));
    else if (sort === "trending") cp.sort((a, b) => b.entry_count - a.entry_count);
    else cp.sort((a, b) => (b.epss_score ?? 0) - (a.epss_score ?? 0));
    return cp;
  }, [items, filter, sort]);

  const same = (a: Filter, b: Filter) => JSON.stringify(a ?? {}) === JSON.stringify(b ?? {});
  const toggle = (f: NonNullable<Filter>) => setFilter((cur) => (same(cur, f) ? null : f));

  if (stack.count === 0) {
    return (
      <div className={styles.empty}>
        <p className={styles.emptyTitle}>You&rsquo;re not following any vendors yet.</p>
        <p className={styles.emptyBody}>
          Switch to <em>Following</em>, or open any vendor/product profile and choose <em>Follow</em>. Their
          vulnerabilities — new, exploited, and trending across the whole landscape — will surface here.
        </p>
        <button className={styles.emptyCta} onClick={onFollow}>
          Follow a vendor →
        </button>
      </div>
    );
  }

  return (
    <>
      {/* Following — the whole point, up top */}
      <div className={styles.stackRow}>
        <span className={styles.stackRowLabel}>Following</span>
        {assets.map((a) => (
          <span key={`${a.type}-${a.name}`} className={styles.stackChip}>
            <span className={`${styles.assetIco} ${a.type === "vendor" ? styles.icoV : styles.icoP}`}>
              {a.type === "vendor" ? "V" : "P"}
            </span>
            {a.name}
            <span className={styles.stackChipCount}>{a.cve_count}</span>
          </span>
        ))}
        <button className={styles.addChip} onClick={onFollow}>
          + follow a vendor
        </button>
      </div>

      <div className={styles.tiles}>
        <button className={`${styles.tile} ${!filter ? styles.tileActive : ""}`} onClick={() => setFilter(null)}>
          <span className={`${styles.tileNum} ${styles.numNew}`}>{newThisWeek}</span>
          <span className={styles.tileLabel}>New this week</span>
          <span className={styles.tileSub}>in vendors you follow</span>
        </button>
        <button
          className={`${styles.tile} ${same(filter, { kevOnly: true }) ? styles.tileActive : ""}`}
          onClick={() => toggle({ kevOnly: true })}
        >
          <span className={`${styles.tileNum} ${styles.numKev}`}>{counts.kev ?? 0}</span>
          <span className={styles.tileLabel}>Actively exploited</span>
          <span className={styles.tileSub}>on CISA KEV / weaponized</span>
        </button>
        <button
          className={`${styles.tile} ${same(filter, { noRule: true }) ? styles.tileActive : ""}`}
          onClick={() => toggle({ noRule: true })}
        >
          <span className={`${styles.tileNum} ${styles.numGap}`}>{counts.no_rule ?? 0}</span>
          <span className={styles.tileLabel}>No detection yet</span>
          <span className={styles.tileSub}>gap in the rule library</span>
        </button>
        <button className={styles.tile} onClick={() => setSort("trending")} disabled={!trending}>
          <span className={styles.tileNum} style={{ fontSize: "18px", marginTop: "3px" }}>
            {trending?.cve_id ?? "—"}
          </span>
          <span className={styles.tileLabel}>Trending now</span>
          <span className={styles.tileSub}>🔥 {trending?.entry_count ?? 0} mentions</span>
        </button>
      </div>

      <div className={styles.filters}>
        <button className={`${styles.fbtn} ${!filter ? styles.fbtnOn : ""}`} onClick={() => setFilter(null)}>
          All {counts.affecting ?? 0}
        </button>
        <button
          className={`${styles.fbtn} ${same(filter, { kevOnly: true }) ? styles.fbtnOn : ""}`}
          onClick={() => toggle({ kevOnly: true })}
        >
          KEV only
        </button>
        <button
          className={`${styles.fbtn} ${same(filter, { epssHigh: true }) ? styles.fbtnOn : ""}`}
          onClick={() => toggle({ epssHigh: true })}
        >
          EPSS ≥ 50%
        </button>
        <button
          className={`${styles.fbtn} ${same(filter, { noRule: true }) ? styles.fbtnOn : ""}`}
          onClick={() => toggle({ noRule: true })}
        >
          No detection
        </button>
        <div className={styles.sortSeg}>
          <span className={styles.sortSegLbl}>sort</span>
          {(["new", "trending", "epss"] as Sort[]).map((s) => (
            <button
              key={s}
              className={styles.sortSegBtn}
              aria-selected={sort === s}
              onClick={() => setSort(s)}
            >
              {s === "new" ? "Newest" : s === "trending" ? "🔥 Trending" : "EPSS"}
            </button>
          ))}
        </div>
      </div>

      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th>CVE</th>
              <th>Vendor / product</th>
              <th>Why it matters</th>
              <th>First seen</th>
              <th>Detection library</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((i) => (
              <tr key={i.cve_id}>
                <td>
                  <span className={styles.cveId}>
                    <span className={`${styles.sevDot} ${severityClass(i.severity)}`} />
                    <Link to={`/workbench/cve/${encodeURIComponent(i.cve_id)}`}>{i.cve_id}</Link>
                  </span>
                  {i.description && <div className={styles.cveDesc}>{i.description}</div>}
                </td>
                <td>
                  {i.asset_name ? (
                    <span className={styles.affects}>
                      <span className={`${styles.assetIco} ${i.asset_type === "vendor" ? styles.icoV : styles.icoP}`}>
                        {i.asset_type === "vendor" ? "V" : "P"}
                      </span>
                      <span className={styles.mono}>{i.asset_name}</span>
                    </span>
                  ) : (
                    <span className={styles.dim}>—</span>
                  )}
                </td>
                <td>
                  <div className={styles.sig}>
                    <div className={styles.sigRow}>
                      {i.is_kev && (
                        <Chip tone="toned" tint="var(--danger)" pill className={styles.chipMono}>
                          KEV
                        </Chip>
                      )}
                      {i.exploited && !i.is_kev && (
                        <Chip tone="toned" tint="var(--warning)" pill className={styles.chipMono}>
                          weaponized
                        </Chip>
                      )}
                      {i.epss_score != null && (
                        <Chip tone="toned" tint="var(--warning)" pill className={styles.chipMono}>
                          EPSS {Math.round(i.epss_score * 100)}%
                        </Chip>
                      )}
                    </div>
                    {i.entry_count > 0 && (
                      <span className={`${styles.trend} ${i.entry_count >= 40 ? styles.trendHot : ""}`}>
                        {i.entry_count >= 40 ? "🔥 " : ""}
                        {i.entry_count} mentions
                      </span>
                    )}
                  </div>
                </td>
                <td>
                  <span className={`${styles.agecell} ${isRecent(i.published_at) ? styles.ageNew : ""}`}>
                    {relAge(i.published_at)}
                  </span>
                </td>
                <td>
                  {i.posture === "no_rule" ? (
                    <button
                      className={styles.draftBtn}
                      onClick={() => navigate(`/workbench/cve/${encodeURIComponent(i.cve_id)}`)}
                    >
                      Write →
                    </button>
                  ) : i.posture === "defended" ? (
                    <span className={styles.covered}>✓ covered</span>
                  ) : i.posture === "blind" ? (
                    <span className={styles.coveredWeak}>
                      ✓ rule exists
                      {i.missing_data_sources.length > 0 && (
                        <span className={styles.need}>needs {i.missing_data_sources.join(", ")}</span>
                      )}
                    </span>
                  ) : (
                    <span className={styles.dim}>—</span>
                  )}
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={5} className={styles.tableEmpty}>
                  No vulnerabilities match this filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

function tms(iso: string | null): number {
  if (!iso) return 0;
  const t = new Date(iso).getTime();
  return Number.isNaN(t) ? 0 : t;
}

/* ───────────────────── Following (manage) ───────────────────── */

export function FollowView({ data }: { data: StackExposureResponse }) {
  const [q, setQ] = useState("");
  const { data: followRows } = useStack();
  const { data: products } = useProducts(q ? { search: q, limit: 6 } : undefined);
  const { data: vendors } = useVendors(q ? { search: q, limit: 4 } : undefined);
  const upsert = useUpsertWatch();
  const del = useDeleteWatch();

  const followedIds = useMemo(() => new Set((followRows ?? []).map((r) => r.entity_id)), [followRows]);
  const countByName = useMemo(() => {
    const m = new Map<string, { cve: number; kev: number }>();
    for (const a of data.assets) m.set(a.name, { cve: a.cve_count, kev: a.kev_count });
    return m;
  }, [data.assets]);

  type Result = { id: string; name: string; type: "vendor" | "product"; sub: string };
  const results: Result[] = useMemo(() => {
    if (!q) return [];
    const p = (products?.items ?? []).map((x) => ({
      id: x.id,
      name: x.name,
      type: "product" as const,
      sub: (x as { normalized_name?: string }).normalized_name || "product",
    }));
    const v = (vendors?.items ?? []).map((x) => ({
      id: x.id,
      name: x.name,
      type: "vendor" as const,
      sub: (x as { normalized_name?: string }).normalized_name || "vendor",
    }));
    return [...p, ...v].slice(0, 8);
  }, [q, products, vendors]);

  const follow = (r: Result) =>
    upsert.mutate(
      { entity_type: r.type, entity_id: r.id, mode: "stack" },
      { onSuccess: () => toast.success(`Following ${r.name}`) },
    );
  const unfollow = (entity_type: string, entity_id: string, name: string) =>
    del.mutate({ entity_type, entity_id }, { onSuccess: () => toast.success(`Unfollowed ${name}`) });

  return (
    <div className={styles.buildGrid}>
      <div className={styles.searchPanel}>
        <h3 className={styles.panelH}>Follow a vendor or product</h3>
        <p className={styles.panelSub}>
          Search IntelFeed&rsquo;s vendor &amp; product entities. Each maps to NVD CPE, so their vulnerabilities are
          matched exactly across the whole landscape.
        </p>
        <div className={styles.sbox}>
          <span className={styles.mono} style={{ color: "var(--text-muted)" }}>
            ⌕
          </span>
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search vendors or products…" aria-label="Search vendors" />
        </div>
        {results.map((r) => {
          const following = followedIds.has(r.id);
          return (
            <div key={`${r.type}-${r.id}`} className={styles.result}>
              <span className={`${styles.assetIco} ${styles.icoBig} ${r.type === "vendor" ? styles.icoV : styles.icoP}`}>
                {r.type === "vendor" ? "V" : "P"}
              </span>
              <div className={styles.resultMeta}>
                <b>{r.name}</b>
                <div className={styles.resultSub}>{r.sub}</div>
              </div>
              <button
                className={`${styles.addBtn} ${following ? styles.addBtnDone : ""}`}
                disabled={following}
                onClick={() => follow(r)}
              >
                {following ? "✓ following" : "+ follow"}
              </button>
            </div>
          );
        })}
        {q && results.length === 0 && <div className={styles.noResults}>No vendors or products match &ldquo;{q}&rdquo;.</div>}
      </div>

      <div className={styles.managePanel}>
        <div className={styles.panelHRow}>
          <h3 className={styles.panelH}>Following</h3>
          <span className={styles.mono} style={{ color: "var(--accent-intel, #58a6ff)", fontWeight: 700 }}>
            {followRows?.length ?? 0}
          </span>
        </div>
        {(followRows ?? []).length === 0 && <div className={styles.noResults}>Not following anything yet — search to follow.</div>}
        {(followRows ?? []).map((row) => {
          const c = countByName.get(row.entity_name ?? "");
          return (
            <div key={row.id} className={styles.manageItem}>
              <span className={`${styles.assetIco} ${row.entity_type === "vendor" ? styles.icoV : styles.icoP}`}>
                {row.entity_type === "vendor" ? "V" : "P"}
              </span>
              <div className={styles.manageMeta}>
                <b>{row.entity_name ?? "—"}</b>
                <div className={styles.manageSub}>
                  {c?.kev ? (
                    <Chip tone="toned" tint="var(--danger)" pill className={styles.chipMono}>
                      {c.kev} KEV
                    </Chip>
                  ) : null}
                  <span className={styles.mono}>{c?.cve ?? 0} vulns</span>
                </div>
              </div>
              <button
                className={styles.rmBtn}
                aria-label={`Unfollow ${row.entity_name}`}
                onClick={() => unfollow(row.entity_type, row.entity_id, row.entity_name ?? "vendor")}
              >
                ×
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default ExposurePage;
