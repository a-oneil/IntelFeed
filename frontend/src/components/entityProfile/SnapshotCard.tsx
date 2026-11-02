/**
 * SnapshotCard — the Overview's facts strip: the one home for the entity's
 * numbers. Header badges carry the qualitative headline (severity, KEV,
 * Active); the quantitative detail lives here only, one tile per fact across
 * the full width under the assessment.
 *
 * Per one-home-per-fact, a type contributes tiles ONLY for facts that don't
 * already live in an editable header badge or identity field — so the actor
 * strip is thin (motivation/origin/MITRE are editable badges) while the CVE
 * strip carries the full numeric read.
 */
import { Link } from "react-router-dom";
import type { EntityType } from "@/stores/intelStore";
import type { CVE, CWEResponse, EntitySearchResult, CVEWeaknessRow } from "@/api/types";
import type { ActorVictimStats, EntityCampaignRef } from "@/hooks/useEntityProfile";
import type { AffectedCVEsResponse } from "@/hooks/useAffectedCves";
import type { EntityProvenance } from "@/hooks/useEntityProvenance";
import { FieldProvenance } from "./FieldProvenance";
import { entityProfilePath, isKnownExploited } from "./entityProfileConfig";
import styles from "./entityProfile.module.css";

function Row({ k, v, mono, sub }: { k: string; v: React.ReactNode; mono?: boolean; sub?: React.ReactNode }) {
  return (
    <div className={styles.factTile}>
      <span className={styles.factKey}>{k}</span>
      <span className={`${styles.factVal} ${mono ? styles.mono : ""}`}>{v}</span>
      {sub && <span className={styles.factSub}>{sub}</span>}
    </div>
  );
}

function prettyType(raw: string | null | undefined): string | null {
  if (!raw) return null;
  return raw.replace(/[_-]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export function SnapshotCard({
  entityType,
  entity,
  cveDetail,
  cweDetail,
  cveWeaknesses,
  cvssVector,
  campaigns,
  provenance,
  victimStats,
  affected,
  techniques,
  ruleCount,
  countryStats,
  campaignStats,
  onOpenArticle,
}: {
  entityType: EntityType;
  entity: EntitySearchResult;
  cveDetail?: CVE;
  cweDetail?: CWEResponse;
  cveWeaknesses?: CVEWeaknessRow[];
  /** Parsed from the NVD blob by the caller (extractNvd). */
  cvssVector?: string | null;
  /** Campaigns this entity belongs to (any type). */
  campaigns?: EntityCampaignRef[];
  /** Field-level claims — "who says so" markers on sourced rows. */
  provenance?: EntityProvenance;
  /** Actor only: windowed leak-site victim counts from the ransomware tracker. */
  victimStats?: ActorVictimStats | null;
  /** Vendor/product only: NVD CPE affected-CVE counts (open CVEs, KEV). */
  affected?: AffectedCVEsResponse;
  /** Actor/malware only: technique + gap counts from the detection-gaps computation. */
  techniques?: { total: number; gaps: number } | null;
  /** Detection rules linked to this entity (pivot related set). */
  ruleCount?: number;
  /** Country only: origin/targeting actor counts and the EntryCountry role split. */
  countryStats?: { origins: number; targeting: number; roles: Record<string, number> } | null;
  /** Campaign counts from /campaigns/{id}/stats, joined with the pivot's totals. */
  campaignStats?: {
    entries: number;
    stories: number;
    actors: number;
    malware: number;
    cves: number;
    techniques: number;
    coveragePct: number | null;
  } | null;
  onOpenArticle?: (entryId: string) => void;
}) {
  const rows: React.ReactNode[] = [];
  const marker = (field: string, label: string) =>
    provenance ? (
      <FieldProvenance
        field={field}
        label={label}
        bucket={provenance.fields[field]}
        unsourced={provenance.unsourced_fields.includes(field)}
        onOpenArticle={onOpenArticle}
      />
    ) : null;

  if (entityType === "cve") {
    const vector = cvssVector ?? null;
    if (entity.cvss_score != null)
      rows.push(
        <Row
          key="cvss"
          k="CVSS"
          v={
            <>
              <b className={styles[`snapSeverity_${entity.severity?.toLowerCase()}`] || ""}>{entity.cvss_score}</b>
              {marker("cvss_score", "CVSS score")}
            </>
          }
          sub={vector ? <span className={styles.mono}>{vector}</span> : undefined}
        />,
      );
    if (entity.epss_score != null) {
      const cur = Number(entity.epss_score);
      const prev = cveDetail?.epss_previous_score != null ? Number(cveDetail.epss_previous_score) : null;
      const arrow = prev != null && prev !== cur ? (cur > prev ? " ▲" : " ▼") : "";
      rows.push(
        <Row
          key="epss"
          k="EPSS"
          v={
            <span title={prev != null ? `Previously ${(prev * 100).toFixed(2)}%` : undefined}>
              <b>{(cur * 100).toFixed(2)}%</b>
              {entity.epss_percentile != null ? ` · ${(Number(entity.epss_percentile) * 100).toFixed(0)}th pct` : ""}
              {arrow && <span className={cur > (prev ?? 0) ? styles.snapUp : styles.snapDown}>{arrow}</span>}
            </span>
          }
        />,
      );
    }
    const riskTier = cveDetail?.risk_tier ?? entity.risk_tier;
    if (riskTier)
      rows.push(
        <Row
          key="tier"
          k="Risk tier"
          v={<span className={`${styles.riskTier} ${styles[`riskTier_${riskTier}`] || ""}`}>{riskTier.toUpperCase()}</span>}
        />,
      );
    // One home per fact: exploitation status lives in the header badge
    // (editable, provenance-marked) and the lifecycle strip dates it; KEV
    // membership + deadline live on the strip too. The Snapshot only states
    // the negative — "Not listed" — which no other surface carries.
    const isKev = isKnownExploited({
      is_kev: cveDetail?.is_kev ?? entity.is_kev,
      exploit_status: cveDetail?.exploit_status ?? entity.exploit_status,
    });
    if (!isKev) rows.push(<Row key="kev" k="CISA KEV" v="Not listed" />);
    const weaknesses = (cveWeaknesses ?? []).slice(0, 2);
    if (weaknesses.length > 0)
      rows.push(
        <Row
          key="cwe"
          k={weaknesses.length === 1 ? "Weakness" : "Weaknesses"}
          v={
            <span className={styles.factStack}>
              {weaknesses.map((w) =>
                w.cwe_id ? (
                  <Link key={w.cwe_ref} className={`${styles.affVendorLink} ${styles.cweLink}`} to={entityProfilePath("cwe", w.cwe_id)}>
                    {w.cwe_ref} {w.name}
                  </Link>
                ) : (
                  <span key={w.cwe_ref} className={styles.affUnres}>
                    {w.cwe_ref === "NVD-CWE-noinfo" ? "Unclassified by NVD" : w.cwe_ref}
                  </span>
                ),
              )}
            </span>
          }
        />,
      );
  }

  if (entityType === "cwe") {
    const direct = cweDetail?.cve_count ?? entity.cve_count ?? 0;
    const rolled = cweDetail?.cve_count_rolled ?? entity.cve_count_rolled ?? null;
    const kev = cweDetail?.kev_count ?? entity.kev_count ?? 0;
    const kevRolled = cweDetail?.kev_count_rolled ?? null;
    const articles = cweDetail?.article_count ?? entity.article_count ?? 0;
    const abstraction = cweDetail?.abstraction ?? entity.abstraction;
    const parent = cweDetail?.parent_cwe_id ?? entity.parent_cwe_id;
    if (rolled || direct)
      rows.push(
        <Row
          key="cves"
          k="CVEs"
          v={<b>{(rolled ?? direct).toLocaleString()}</b>}
          sub={rolled != null && rolled !== direct ? `${direct.toLocaleString()} direct` : undefined}
        />,
      );
    if ((kevRolled ?? kev) > 0) {
      const n = kevRolled ?? kev;
      const base = rolled ?? direct;
      rows.push(
        <Row
          key="kev"
          k="KEV"
          v={
            <span>
              <b className={styles.snapCritical}>{n.toLocaleString()}</b>
              {base ? ` · ${((n / base) * 100).toFixed(1)}% of CVEs` : ""}
            </span>
          }
        />,
      );
    }
    if (articles > 0) rows.push(<Row key="articles" k="Articles" v={<b>{articles.toLocaleString()}</b>} />);
    if (abstraction)
      rows.push(<Row key="abs" k="Abstraction" v={abstraction} sub={parent ? `under ${parent}` : undefined} />);
  }

  if (entityType === "threat_actor") {
    if (entity.actor_type)
      rows.push(
        <Row
          key="type"
          k="Type"
          v={
            <>
              {prettyType(entity.actor_type)}
              {marker("actor_type", "Actor type")}
            </>
          }
        />,
      );
    if (victimStats && victimStats.total > 0) {
      const delta = victimStats.last_30d - victimStats.prev_30d;
      rows.push(
        <Row
          key="victims"
          k="Leak-site victims · 30d"
          v={
            <span title={`${victimStats.total} on record · ${victimStats.prev_30d} in the prior 30 days`}>
              <b>{victimStats.last_30d}</b>
              {delta !== 0 && (
                <span className={delta > 0 ? styles.snapUp : styles.snapDown}>
                  {" "}
                  {delta > 0 ? "▲" : "▼"}
                  {Math.abs(delta)}
                </span>
              )}
            </span>
          }
        />,
      );
    }
  }

  if (entityType === "malware" && entity.mitre_id) {
    rows.push(
      <Row
        key="mitre"
        k="MITRE"
        v={
          <a className={styles.affVendorLink} href={`https://attack.mitre.org/software/${entity.mitre_id}/`} target="_blank" rel="noopener noreferrer">
            {entity.mitre_id} ↗
          </a>
        }
        mono
      />,
    );
  }

  if (entityType === "tool") {
    if (entity.mitre_id)
      rows.push(
        <Row
          key="mitre"
          k="MITRE"
          v={
            <a className={styles.affVendorLink} href={`https://attack.mitre.org/software/${entity.mitre_id}/`} target="_blank" rel="noopener noreferrer">
              {entity.mitre_id} ↗
            </a>
          }
          mono
        />,
      );
    const platforms = (entity as { platforms?: string[] }).platforms;
    if (platforms?.length)
      rows.push(<Row key="platforms" k="Platforms" v={platforms.slice(0, 6).join(" · ")} />);
  }

  if (entityType === "threat_actor" || entityType === "malware") {
    if (techniques && techniques.total > 0)
      rows.push(<Row key="techniques" k="Techniques on record" v={<b>{techniques.total}</b>} />);
    if ((ruleCount ?? 0) > 0 || (techniques?.gaps ?? 0) > 0)
      rows.push(
        <Row
          key="rules"
          k="Detection rules"
          v={
            <span>
              <b>{ruleCount ?? 0}</b>
              {(techniques?.gaps ?? 0) > 0 && (
                <span className={styles.metaLabel}> · {techniques!.gaps} gaps</span>
              )}
            </span>
          }
        />,
      );
  }

  if (entityType === "campaign" && campaignStats) {
    // A campaign's snapshot is its scope: how much it holds, and of what. The
    // numbers it used to spread across an Overview tab and a stats endpoint.
    rows.push(
      <Row
        key="articles"
        k="Articles"
        v={
          <span>
            <b>{campaignStats.entries}</b>
            {campaignStats.stories > 0 && (
              <span className={styles.metaLabel}> · {campaignStats.stories} stories</span>
            )}
          </span>
        }
      />,
    );
    if (campaignStats.actors > 0) rows.push(<Row key="c-actors" k="Actors" v={<b>{campaignStats.actors}</b>} />);
    if (campaignStats.malware > 0) rows.push(<Row key="c-malware" k="Malware" v={<b>{campaignStats.malware}</b>} />);
    if (campaignStats.cves > 0) rows.push(<Row key="c-cves" k="CVEs" v={<b>{campaignStats.cves}</b>} />);
    if (campaignStats.techniques > 0)
      rows.push(<Row key="c-ttps" k="Techniques" v={<b>{campaignStats.techniques}</b>} />);
    if (campaignStats.coveragePct != null)
      rows.push(
        <Row key="c-coverage" k="Rule coverage" v={<b>{Math.round(campaignStats.coveragePct)}%</b>} />,
      );
  }

  if (entityType === "country" && countryStats) {
    if (countryStats.origins > 0)
      rows.push(<Row key="origins" k="Actor origins" v={<b>{countryStats.origins}</b>} />);
    if (countryStats.targeting > 0)
      rows.push(<Row key="targeting" k="Targeted by" v={<b>{countryStats.targeting}</b>} />);
    // Real EntryCountry role vocabulary: origin / target / infrastructure /
    // mentioned (+ slashes). "mentioned" carries no signal — show the rest.
    const roleParts = Object.entries(countryStats.roles)
      .filter(([role, n]) => n > 0 && role && !/^mentioned$|^unknown$/.test(role))
      .map(([role, n]) => [role.split("/")[0], n] as const)
      .reduce((acc, [role, n]) => acc.set(role, (acc.get(role) ?? 0) + n), new Map<string, number>());
    const roleText = [...roleParts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([role, n]) => `${role} ×${n}`)
      .join(" · ");
    if (roleText)
      rows.push(
        <Row
          key="roles"
          k="Role in coverage"
          v={<span title="How articles frame this country">{roleText}</span>}
        />,
      );
  }

  if (entityType === "vendor" || entityType === "product") {
    // NVD CPE affected-CVE counts — the numbers behind the Vulnerabilities tab.
    if (affected && affected.total > 0) {
      if (entityType === "vendor" && affected.by_product.length > 0)
        rows.push(<Row key="products" k="Products with CVEs" v={<b>{affected.by_product.length}</b>} />);
      rows.push(<Row key="cves" k="Open CVEs" v={<b>{affected.total.toLocaleString()}</b>} />);
      if (affected.counts.kev > 0)
        rows.push(<Row key="kev" k="KEV" v={<b className={styles.snapCritical}>{affected.counts.kev}</b>} />);
    }
  }

  if (entityType === "mitigation") {
    if (entity.mitre_id)
      rows.push(
        <Row
          key="mitre"
          k="MITRE"
          v={
            entity.mitre_url ? (
              <a className={styles.affVendorLink} href={entity.mitre_url} target="_blank" rel="noopener noreferrer">
                {entity.mitre_id} ↗
              </a>
            ) : (
              entity.mitre_id
            )
          }
          mono
        />,
      );
    const cis = (entity as { cis_controls?: string[] }).cis_controls ?? [];
    const nist = (entity as { nist_controls?: string[] }).nist_controls ?? [];
    if (cis.length)
      rows.push(
        <Row key="cis" k="CIS Controls" v={cis.slice(0, 4).join(" · ") + (cis.length > 4 ? ` +${cis.length - 4}` : "")} mono />,
      );
    if (nist.length)
      rows.push(
        <Row key="nist" k="NIST 800-53" v={nist.slice(0, 4).join(" · ") + (nist.length > 4 ? ` +${nist.length - 4}` : "")} mono />,
      );
  }

  // Baseline row so every type has a populated Snapshot: total linked articles
  // (all-time — the pulse line's count is window-scoped). CVE/CWE carry their
  // own richer counts above.
  if (entityType !== "cve" && entityType !== "cwe" && entity.article_count != null) {
    rows.push(<Row key="articles" k="Articles" v={<b>{entity.article_count.toLocaleString()}</b>} />);
  }

  if (campaigns && campaigns.length > 0) {
    const [first, ...rest] = campaigns;
    rows.push(
      <Row
        key="campaigns"
        k={campaigns.length === 1 ? "Campaign" : "Campaigns"}
        v={
          <span>
            <Link className={styles.snapCampaign} to={`/workbench/campaign/${first.id}`}>
              {first.name}
            </Link>
            {rest.length > 0 && (
              <span className={styles.metaLabel} title={rest.map((c) => c.name).join(", ")}>
                {" "}+{rest.length}
              </span>
            )}
          </span>
        }
      />,
    );
  }

  if (rows.length === 0) return null;
  return (
    <div className={styles.facts} aria-label="Facts">
      <span className={styles.sectionLabel}>Facts</span>
      <div className={styles.factsStrip}>{rows}</div>
    </div>
  );
}

/** Public exploit code for a CVE: GitHub PoCs, Metasploit — its own small card. */
export function ExploitPocCard({ entity, cveDetail }: { entity: EntitySearchResult; cveDetail?: CVE }) {
  const pocUrls = (cveDetail?.github_poc_urls ?? entity.github_poc_urls ?? []).slice(0, 5);
  const pocCount = cveDetail?.github_poc_count ?? entity.github_poc_count ?? 0;
  const metasploit = cveDetail?.metasploit_module ?? entity.metasploit_module;
  if (pocUrls.length === 0 && !pocCount && !metasploit) return null;
  const shortName = (u: string) => {
    try {
      const url = new URL(u);
      return url.hostname === "github.com" ? url.pathname.split("/").filter(Boolean).slice(0, 2).join("/") : url.hostname.replace(/^www\./, "");
    } catch {
      return u.slice(0, 40);
    }
  };
  return (
    <div className={styles.panel}>
      <div className={`${styles.panelTitle} ${styles.panelTitleFlex}`}>
        Exploit &amp; PoC
        {pocCount > 0 && <span className={styles.snapCountTag}>{pocCount} public</span>}
      </div>
      {pocUrls.length > 0 ? (
        <div className={styles.snapLinkList}>
          {pocUrls.map((u) => (
            <a key={u} className={`${styles.affVendorLink} ${styles.mono}`} href={u} target="_blank" rel="noopener noreferrer" title={u}>
              {shortName(u)} ↗
            </a>
          ))}
        </div>
      ) : pocCount > 0 ? (
        <div className={styles.panelRow}>
          <span className={styles.panelKey}>PoC</span>
          <span className={styles.panelVal}>{pocCount} on GitHub</span>
        </div>
      ) : null}
      <div className={styles.panelRow}>
        <span className={styles.panelKey}>Metasploit</span>
        <span className={`${styles.panelVal} ${metasploit ? styles.mono : styles.snapNone}`}>{metasploit || "none yet"}</span>
      </div>
    </div>
  );
}
