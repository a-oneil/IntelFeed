import { useMemo } from "react";
import { Link, useNavigate } from "react-router-dom";
import type { StackExposureItem, StackExposureResponse } from "@/hooks/useWatchlist";
import styles from "./VulnLandscape.module.css";

/** Vendor Watch's pulse and completeness, re-idiomed for the Threats page.

    The tiles keep the four questions the old page answered at a glance; the
    exhaustive stack table survives as the long tail below the ranked board —
    completeness without a ranking opinion, in the same table idiom as the
    library rather than a second design language. */

const WEEK_MS = 7 * 86_400_000;

function isRecent(iso: string | null): boolean {
  if (!iso) return false;
  const t = new Date(iso).getTime();
  return !Number.isNaN(t) && Date.now() - t <= WEEK_MS;
}

function relAge(iso: string | null): string {
  if (!iso) return "—";
  const days = Math.floor((Date.now() - new Date(iso).getTime()) / 86_400_000);
  if (Number.isNaN(days)) return "—";
  if (days <= 0) return "today";
  if (days < 7) return `${days}d`;
  if (days < 30) return `${Math.floor(days / 7)}w`;
  if (days < 365) return `${Math.floor(days / 30)}mo`;
  return `${Math.floor(days / 365)}y`;
}

export function VulnTiles({
  data,
  onFollow,
}: {
  data: StackExposureResponse;
  onFollow: () => void;
}) {
  const { stack, counts, items } = data;
  const newThisWeek = useMemo(() => items.filter((i) => isRecent(i.published_at)).length, [items]);
  const trending = useMemo(
    () =>
      items.reduce<StackExposureItem | null>(
        (top, i) => (i.entry_count > (top?.entry_count ?? 0) ? i : top),
        null
      ),
    [items]
  );

  if (stack.count === 0) {
    return (
      <div className={styles.emptyStack}>
        <span>
          You&rsquo;re not following any vendors or products yet — the board below ranks the whole
          landscape, and nothing can sort onto your surface until the stack says what you run.
        </span>
        <button className={styles.followBtn} onClick={onFollow}>
          Follow a vendor →
        </button>
      </div>
    );
  }

  return (
    <div className={styles.tiles}>
      <div className={styles.tile}>
        <b className={styles.numNew}>{newThisWeek}</b>
        <span>new this week in vendors you follow</span>
      </div>
      <div className={styles.tile}>
        <b className={styles.numKev}>{counts.kev ?? 0}</b>
        <span>actively exploited — CISA KEV / weaponized</span>
      </div>
      <div className={styles.tile}>
        <b className={styles.numGap}>{counts.no_rule ?? 0}</b>
        <span>no rule resolves to them in the library</span>
      </div>
      <div className={styles.tile}>
        <b className={styles.numTrend}>{trending?.cve_id ?? "—"}</b>
        <span>trending now · {trending?.entry_count ?? 0} mentions</span>
      </div>
    </div>
  );
}

export function VulnLongTail({ data }: { data: StackExposureResponse }) {
  const navigate = useNavigate();
  const rows = data.items;
  if (rows.length === 0) return null;

  return (
    <div className={styles.tail}>
      <div className={styles.tailHead}>
        The long tail — your stack, exhaustive · {rows.length}
        <span>every CVE affecting a followed vendor/product, no ranking opinion</span>
      </div>
      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th>CVE</th>
              <th>Product</th>
              <th className={styles.num}>EPSS</th>
              <th className={styles.num}>Mentions</th>
              <th className={styles.num}>First seen</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((i) => (
              <tr key={i.cve_id}>
                <td className={styles.cveCell}>
                  <Link to={`/workbench/cve/${encodeURIComponent(i.cve_id)}`}>{i.cve_id}</Link>
                  {i.is_kev && <span className={styles.kev}>KEV</span>}
                  {i.description && <div className={styles.desc}>{i.description}</div>}
                </td>
                <td className={styles.prod}>{i.asset_name ?? "—"}</td>
                <td className={styles.num}>
                  {i.epss_score != null ? `${Math.round(i.epss_score * 100)}%` : "—"}
                </td>
                <td className={styles.num}>{i.entry_count || "—"}</td>
                <td className={`${styles.num} ${isRecent(i.published_at) ? styles.fresh : ""}`}>
                  {relAge(i.published_at)}
                </td>
                <td className={styles.actCell}>
                  {i.posture === "no_rule" ? (
                    <button
                      className={styles.writeBtn}
                      onClick={() => navigate(`/workbench/cve/${encodeURIComponent(i.cve_id)}?tab=detection`)}
                    >
                      Write →
                    </button>
                  ) : i.posture === "defended" ? (
                    <span className={styles.covered}>defended</span>
                  ) : i.posture === "blind" ? (
                    <span className={styles.blind} title={`Rules exist but need ${i.missing_data_sources.join(", ")}`}>
                      collect
                    </span>
                  ) : (
                    <span className={styles.dim}>—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
