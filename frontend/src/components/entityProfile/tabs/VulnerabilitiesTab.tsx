/**
 * VulnerabilitiesTab — authoritative CVE list on vendor, product and weakness
 * profiles, fed by NVD structured data rather than article co-mentions. Vendor
 * and product modes read cve_affected (CPE); weakness mode reads cve_weaknesses.
 *
 * Vendor mode shows the full rollup (direct vendor rows plus every product with
 * vendor_id = this vendor) with per-row product labels; product mode scopes to
 * the product's own rows with version ranges; weakness mode spans the whole
 * abstraction subtree by default and labels each row with the descendant that
 * actually matched.
 *
 * Row design is deliberately calm: severity is the left stripe + the CVSS
 * color, at most one small status chip (KEV, else EXPLOITED), everything
 * else monochrome.
 */
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Chip } from "@/components/primitives";
import {
  useAffectedCves,
  formatVersionRange,
  type AffectedCveFilters,
  type AffectedCVEItem,
  type AffectedKind,
  type AffectedSort,
} from "@/hooks/useAffectedCves";
import { entityProfilePath } from "../entityProfileConfig";
import profileStyles from "../entityProfile.module.css";
import styles from "./VulnerabilitiesTab.module.css";
import { AsyncStateLoading } from "@/components/AsyncState";

const SEVERITIES = [
  { key: "critical", label: "Critical", dot: "#f87171" },
  { key: "high", label: "High", dot: "#fb923c" },
  { key: "medium", label: "Medium", dot: "#eab308" },
  { key: "low", label: "Low", dot: "#4ade80" },
];

const SEV_ROW_CLASS: Record<string, string> = {
  critical: styles.sevCritical,
  high: styles.sevHigh,
  medium: styles.sevMedium,
  low: styles.sevLow,
};

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function formatDate(iso: string | null): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (isNaN(d.getTime())) return null;
  return `${MONTHS[d.getMonth()]} ${d.getFullYear()}`;
}

function Row({
  item,
  mode,
  subjectCwe,
}: {
  item: AffectedCVEItem;
  mode: AffectedKind;
  /** The weakness whose profile this is, so a row matched on the subject itself
   * doesn't repeat it and a row matched on a descendant can say so. */
  subjectCwe?: string;
}) {
  const viaDescendant = mode === "cwe" && !!item.matched_cwe && item.matched_cwe !== subjectCwe;
  const sevClass = SEV_ROW_CLASS[item.severity?.toLowerCase() ?? ""] ?? "";
  const date = formatDate(item.published_at);
  const version = mode === "product" && item.products[0]
    ? formatVersionRange(item.products[0].version_start, item.products[0].version_end)
    : null;
  const epssPct = item.epss_score != null ? item.epss_score * 100 : null;
  return (
    <div className={`${styles.row} ${sevClass}`}>
      <div className={styles.rowMain}>
        <div className={styles.rowHead}>
          <Link className={styles.cveId} to={entityProfilePath("cve", item.id)}>{item.cve_id}</Link>
          {item.is_kev ? (
            <span className={styles.statusChip} title="CISA Known Exploited Vulnerability">KEV</span>
          ) : item.exploited ? (
            <span className={styles.statusChip} title="Weaponized or actively exploited">Exploited</span>
          ) : null}
        </div>
        <div className={styles.desc}>
          {mode === "cwe" && (viaDescendant || item.products.length > 0) && (
            <>
              {viaDescendant && (
                <span
                  className={styles.prodTag}
                  title={`Tagged ${item.matched_cwe}${item.matched_cwe_name ? ` — ${item.matched_cwe_name}` : ""}, which sits below ${subjectCwe} on the abstraction ladder`}
                >
                  via {item.matched_cwe}
                </span>
              )}
              {viaDescendant && item.products.length > 0 && " · "}
              {item.products.map((p, i) => (
                <span key={p.id ?? p.cpe_product}>
                  {i > 0 && ", "}
                  {p.id ? (
                    <Link className={styles.prodTag} to={entityProfilePath("product", p.id)}>{p.name}</Link>
                  ) : (
                    <span className={styles.prodTag}>{p.name ?? p.cpe_product}</span>
                  )}
                </span>
              ))}
              {/* Same em-dash the vendor rows use — without it the chip and the
                  description run together. */}
              {" — "}
            </>
          )}
          {mode === "vendor" &&
            (item.products.length > 0 ? (
              <>
                {item.products.map((p, i) => (
                  <span key={p.id ?? p.cpe_product}>
                    {i > 0 && ", "}
                    {p.id ? (
                      <Link className={styles.prodTag} to={entityProfilePath("product", p.id)}>{p.name}</Link>
                    ) : (
                      <span className={styles.prodTag}>{p.name ?? p.cpe_product}</span>
                    )}
                  </span>
                ))}
                {" — "}
              </>
            ) : (
              <span className={styles.vendTag}>vendor-level — </span>
            ))}
          {item.description ?? "No description available."}
          {version && <span className={styles.verTag}> · {version}</span>}
        </div>
      </div>
      <div className={styles.nums}>
        <span className={styles.numsTop}>
          {item.cvss_score != null && <span className={styles.cvss}>{Number(item.cvss_score).toFixed(1)}</span>}
          {epssPct != null && (
            <span className={styles.epss}>EPSS {epssPct < 10 ? epssPct.toFixed(1) : epssPct.toFixed(0)}%</span>
          )}
        </span>
        {date && <span className={styles.date}>{date}</span>}
      </div>
    </div>
  );
}

export function VulnerabilitiesTab({
  mode,
  entityId,
  entityName,
}: {
  mode: AffectedKind;
  entityId: string;
  entityName: string;
}) {
  // "CWE-284 Improper Access Control" -> "CWE-284"
  const subjectCwe = mode === "cwe" ? entityName.split(" ")[0] : undefined;
  const [severity, setSeverity] = useState<string[]>([]);
  const [kev, setKev] = useState(false);
  const [exploited, setExploited] = useState(false);
  const [productId, setProductId] = useState<string | undefined>();
  const [vendorLevel, setVendorLevel] = useState(false);
  // Weakness mode spans the subtree by default so the list agrees with the
  // profile's headline count — NVD tags a CVE wherever the assigning analyst
  // chose, so a Class's direct list is near-empty.
  const [includeDescendants, setIncludeDescendants] = useState(true);
  const [sort, setSort] = useState<AffectedSort>("cvss");

  const filters: AffectedCveFilters = useMemo(
    () => ({ severity, kev, exploited, productId, vendorLevel, includeDescendants, sort }),
    [severity, kev, exploited, productId, vendorLevel, includeDescendants, sort],
  );
  const { data, isLoading, hasNextPage, fetchNextPage, isFetchingNextPage } = useAffectedCves(
    mode,
    entityId,
    filters,
  );

  const first = data?.pages[0];
  const items = useMemo(() => data?.pages.flatMap((p) => p.items) ?? [], [data]);
  const counts = first?.counts;
  const sevCount = (key: string) => counts?.severity?.[key.toUpperCase()] ?? 0;
  const distinctTotal = useMemo(() => {
    if (!first) return 0;
    return Object.values(first.counts.severity).reduce((a, b) => a + b, 0);
  }, [first]);
  const productLinked = first ? Math.max(distinctTotal - first.vendor_level_count, 0) : 0;

  const toggleSeverity = (key: string) =>
    setSeverity((prev) => (prev.includes(key) ? prev.filter((s) => s !== key) : [...prev, key]));

  return (
    <div className={profileStyles.tabPanel}>
      <div className={styles.summary}>
        {first ? (
          mode === "cwe" ? (
            <>
              <b>{distinctTotal.toLocaleString()} CVEs</b> carry {entityName.split(" ")[0]}
              {/* A leaf has nothing below it, so the subtree clause would be a
                  lie on most weaknesses — say it only when it is true. */}
              {includeDescendants
                ? (first.subtree_size ?? 1) > 1
                  ? ` or one of the ${((first.subtree_size ?? 1) - 1).toLocaleString()} weaknesses below it`
                  : ""
                : " directly"}
              {counts && counts.kev > 0 && (
                <Chip tone="toned" tint="var(--danger)" className={styles.kevChipGap}>
                  {counts.kev} KEV
                </Chip>
              )}
            </>
          ) : mode === "vendor" ? (
            <>
              <b>{distinctTotal.toLocaleString()} CVEs</b> affect {entityName} —{" "}
              <b>{first.vendor_level_count.toLocaleString()}</b> vendor-level ·{" "}
              <b>{productLinked.toLocaleString()}</b> via {first.by_product.length} tracked product
              {first.by_product.length === 1 ? "" : "s"}
              {counts && counts.kev > 0 && (
                <Chip tone="toned" tint="var(--danger)" className={styles.kevChipGap}>
                  {counts.kev} KEV
                </Chip>
              )}
            </>
          ) : (
            <>
              <b>{distinctTotal.toLocaleString()} CVEs</b> affect {entityName}
              {counts && counts.kev > 0 && (
                <Chip tone="toned" tint="var(--danger)" className={styles.kevChipGap}>
                  {counts.kev} KEV
                </Chip>
              )}
            </>
          )
        ) : (
          "Loading…"
        )}
      </div>

      <div className={styles.filterStrip}>
        {SEVERITIES.map((s) => (
          <Chip
            key={s.key}
            pill
            marker
            markerShape="dot"
            tint={s.dot}
            className={severity.includes(s.key) ? styles.fchipActive : undefined}
            onClick={() => toggleSeverity(s.key)}
            aria-pressed={severity.includes(s.key)}
          >
            {s.label} <span className={styles.fchipCount}>{sevCount(s.key).toLocaleString()}</span>
          </Chip>
        ))}
        <span className={styles.fsep} />
        <Chip
          pill
          className={kev ? styles.fchipActive : undefined}
          onClick={() => setKev((v) => !v)}
          aria-pressed={kev}
        >
          KEV <span className={styles.fchipCount}>{(counts?.kev ?? 0).toLocaleString()}</span>
        </Chip>
        <Chip
          pill
          className={exploited ? styles.fchipActive : undefined}
          onClick={() => setExploited((v) => !v)}
          aria-pressed={exploited}
        >
          Exploited <span className={styles.fchipCount}>{(counts?.exploited ?? 0).toLocaleString()}</span>
        </Chip>
        {mode === "cwe" && (
          <Chip
            pill
            className={!includeDescendants ? styles.fchipActive : undefined}
            onClick={() => setIncludeDescendants((v) => !v)}
            aria-pressed={!includeDescendants}
            title="Only CVEs tagged with this exact weakness, excluding everything below it on the ladder"
          >
            Direct only
          </Chip>
        )}
        <select
          className={styles.sortSel}
          value={sort}
          onChange={(e) => setSort(e.target.value as AffectedSort)}
          aria-label="Sort"
        >
          <option value="cvss">Sort · CVSS</option>
          <option value="epss">Sort · EPSS</option>
          <option value="recent">Sort · Recent</option>
        </select>
      </div>

      {mode === "vendor" && first && first.by_product.length > 0 && (
        <div className={styles.prodStrip}>
          {first.by_product.map((p) => (
            <Chip
              key={p.id}
              pill
              truncate
              title={p.name}
              className={productId === p.id ? styles.fchipActive : undefined}
              onClick={() => {
                setVendorLevel(false);
                setProductId((prev) => (prev === p.id ? undefined : p.id));
              }}
              aria-pressed={productId === p.id}
            >
              {p.name} <span className={styles.fchipCount}>{p.count.toLocaleString()}</span>
            </Chip>
          ))}
          {first.vendor_level_count > 0 && (
            <Chip
              pill
              className={vendorLevel ? styles.fchipActive : undefined}
              onClick={() => {
                setProductId(undefined);
                setVendorLevel((v) => !v);
              }}
              aria-pressed={vendorLevel}
            >
              vendor-level only{" "}
              <span className={styles.fchipCount}>{first.vendor_level_count.toLocaleString()}</span>
            </Chip>
          )}
        </div>
      )}

      <div className={styles.list}>
        {isLoading ? (
          <AsyncStateLoading label="Loading vulnerabilities…" />
        ) : items.length === 0 ? (
          <div className={styles.empty}>
            {first && distinctTotal === 0
              ? mode === "cwe"
                ? "No CVE in the corpus carries this weakness."
                : "No NVD affects-data links to this entity yet."
              : "No CVEs match the current filters."}
          </div>
        ) : (
          items.map((item) => <Row key={item.id} item={item} mode={mode} subjectCwe={subjectCwe} />)
        )}
      </div>

      {hasNextPage && (
        <button className={styles.loadMore} onClick={() => fetchNextPage()} disabled={isFetchingNextPage}>
          {isFetchingNextPage ? "Loading…" : "Load more"}
        </button>
      )}
    </div>
  );
}
