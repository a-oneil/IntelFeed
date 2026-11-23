/**
 * ReferenceLinks — links that come from reference data rather than articles:
 * a CVE's weaknesses (NVD, the vendor, CISA) and affected products (NVD CPE);
 * a weakness's place in the CWE catalog, its CAPEC attack patterns and the
 * CVEs that have it. These are published facts, so they carry no evidence
 * panel — only where they come from.
 */
import type { EntityType } from "@/stores/intelStore";
import { formatVersionRange, useAffectedCves, useCveAffectedRows } from "@/hooks/useAffectedCves";
import { useCVEWeaknesses, useCWE, useCWEFamily } from "@/hooks/useIntelligence";
import styles from "./relationships.module.css";

/** CVE record assigners, by the ids NVD reports them under. */
const ASSIGNERS: Record<string, string> = {
  "nvd@nist.gov": "NVD",
  "134c704f-9b21-4f2e-91b3-4a467353bcc0": "CISA ADP",
};

function assignerLabel(a: string | null): string {
  if (!a) return "NVD";
  if (ASSIGNERS[a]) return ASSIGNERS[a];
  // Vendor CNAs report an email (psirt@fortinet.com, secure@citrix.com).
  const domain = a.split("@")[1]?.split(".").slice(-2, -1)[0];
  return domain ? domain.charAt(0).toUpperCase() + domain.slice(1) : a;
}

type Open = (type: EntityType, id: string, label: string) => void;

export function hasReferenceLinks(entityType: EntityType): boolean {
  return entityType === "cve" || entityType === "cwe";
}

export function ReferenceLinks({ entityType, entityId, onOpen }: { entityType: EntityType; entityId: string; onOpen: Open }) {
  if (entityType === "cve") return <CveReference cveId={entityId} onOpen={onOpen} />;
  if (entityType === "cwe") return <CweReference cweId={entityId} onOpen={onOpen} />;
  return null;
}

function Section({ count, note, children }: { count?: number; note: string; children: React.ReactNode }) {
  return (
    <div>
      <div className={styles.sectionHead} style={{ marginTop: 8 }}>
        From reference data {count != null && count > 0 && <span className={styles.count}>{count}</span>}
      </div>
      <p className={styles.sectionNote}>{note}</p>
      <div style={{ borderTop: "1px solid var(--border)" }}>{children}</div>
    </div>
  );
}

function CveReference({ cveId, onOpen }: { cveId: string; onOpen: Open }) {
  const weaknesses = useCVEWeaknesses(cveId);
  const affected = useCveAffectedRows(cveId);
  const w = weaknesses.data ?? [];
  const a = affected.data ?? [];
  if (weaknesses.isLoading || affected.isLoading) return null;
  if (w.length === 0 && a.length === 0) return null;
  return (
    <Section count={w.length + a.length} note="Published by NVD, the vendor and CISA. Not inferred from articles.">
      {w.length > 0 && (
        <div className={styles.refRow}>
          <span className={styles.refKey}>Weakness</span>
          <div className={styles.refItems}>
            {w.map((x) => (
              <div key={`${x.cwe_ref}-${x.assigner}`} className={styles.refItem}>
                {x.cwe_id ? (
                  <button className={styles.articleBtn} onClick={() => onOpen("cwe", x.cwe_id!, x.cwe_ref)}>
                    <span className={styles.mono}>{x.cwe_ref}</span> {x.name}
                  </button>
                ) : (
                  // NVD-CWE-noinfo / NVD-CWE-Other: NVD declined to classify.
                  <span>{x.cwe_ref === "NVD-CWE-noinfo" ? "Not enough information to classify" : "Classified as “other” by NVD"}</span>
                )}
                {x.is_primary && <span className={styles.tag}>primary</span>}
                <span className={styles.refFrom}>{assignerLabel(x.assigner)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      {a.length > 0 && (
        <div className={styles.refRow}>
          <span className={styles.refKey}>Affects</span>
          <div className={styles.refItems}>
            {a.map((x) => {
              const name = x.product_name ?? `${x.cpe_vendor} ${x.cpe_product}`.replace(/_/g, " ");
              const range = formatVersionRange(x.version_start, x.version_end);
              return (
                <div key={`${x.cpe_vendor}/${x.cpe_product}/${x.version_start}/${x.version_end}`} className={styles.refItem}>
                  {x.product_id ? (
                    <button className={styles.articleBtn} onClick={() => onOpen("product", x.product_id!, name)}>
                      {name}
                    </button>
                  ) : (
                    <span style={{ fontSize: "var(--fs-sm)" }}>{name}</span>
                  )}
                  {range && <span className={`${styles.mono} ${styles.refFrom}`}>{range}</span>}
                  <span className={styles.refFrom}>NVD (CPE)</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </Section>
  );
}

function CweReference({ cweId, onOpen }: { cweId: string; onOpen: Open }) {
  const cwe = useCWE(cweId);
  const family = useCWEFamily(cweId);
  const kevCves = useAffectedCves("cwe", cweId, { kev: true, sort: "cvss", includeDescendants: false });
  const c = cwe.data;
  if (!c) return null;
  const f = family.data;
  const kev = kevCves.data?.pages[0]?.items.slice(0, 5) ?? [];
  const capec = c.capec_patterns ?? c.capec_ids.map((id) => ({ capec_id: id, name: null }));
  return (
    <Section note="Published by MITRE (CWE, CAPEC) and NVD. Not inferred from articles.">
      <div className={styles.refRow}>
        <span className={styles.refKey}>Place in the catalog</span>
        <div className={styles.refItems}>
          {f?.parent ? (
            <div className={styles.refItem}>
              <span className={styles.refFrom}>Child of</span>
              {f.parent.id ? (
                <button className={styles.articleBtn} onClick={() => onOpen("cwe", f.parent!.id!, f.parent!.cwe_id)}>
                  <span className={styles.mono}>{f.parent.cwe_id}</span> {f.parent.name}
                </button>
              ) : (
                <span>
                  <span className={styles.mono}>{f.parent.cwe_id}</span> {f.parent.name}
                </span>
              )}
            </div>
          ) : (
            <div className={styles.refFrom}>Top of the catalog: no parent weakness.</div>
          )}
          {f && f.children.length > 0 ? (
            <div className={styles.refItem}>
              <span className={styles.refFrom}>Children</span>
              {f.children.map((k) => (
                <button key={k.cwe_id} className={styles.articleBtn} onClick={() => k.id && onOpen("cwe", k.id, k.cwe_id)}>
                  <span className={styles.mono}>{k.cwe_id}</span> {k.name}
                </button>
              ))}
            </div>
          ) : (
            f && <div className={styles.refFrom}>No child weaknesses in the catalog.</div>
          )}
        </div>
      </div>
      {capec.length > 0 && (
        <div className={styles.refRow}>
          <span className={styles.refKey}>Attack patterns</span>
          <div>
            {capec.map((p) => (
              <span key={p.capec_id} className={styles.capec} title={p.name ?? undefined}>
                <span className={styles.mono}>{p.capec_id}</span>
                {p.name && <span>{p.name}</span>}
              </span>
            ))}
          </div>
        </div>
      )}
      {c.mitigations.length > 0 && (
        <div className={styles.refRow}>
          <span className={styles.refKey}>Mitigations</span>
          <div className={styles.refFrom} style={{ fontSize: "var(--fs-sm)" }}>
            {c.mitigations.length} listed by MITRE, on the Overview tab
          </div>
        </div>
      )}
      <div className={styles.refRow}>
        <span className={styles.refKey}>CVEs with it</span>
        <div className={styles.refItems}>
          <div>
            {c.cve_count.toLocaleString()} CVE{c.cve_count === 1 ? "" : "s"}
            {c.kev_count > 0 && <> · <span className={styles.kev}>{c.kev_count} on KEV</span></>}
            <span className={styles.refFrom}> · the full list is on the Vulnerabilities tab</span>
          </div>
          {kev.map((v) => (
            <div key={v.id} className={styles.refItem}>
              <button className={`${styles.articleBtn} ${styles.mono}`} onClick={() => onOpen("cve", v.id, v.cve_id)}>
                {v.cve_id}
              </button>
              {v.cvss_score != null && <span className={styles.refFrom}>CVSS {v.cvss_score}</span>}
              <span className={styles.kev}>KEV</span>
              {v.description && (
                <span className={styles.refFrom} style={{ flexBasis: "100%" }}>
                  {v.description.length > 140 ? `${v.description.slice(0, 139)}…` : v.description}
                </span>
              )}
            </div>
          ))}
        </div>
      </div>
    </Section>
  );
}
