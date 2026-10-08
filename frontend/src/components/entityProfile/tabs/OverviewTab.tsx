/**
 * OverviewTab — the entity's intrinsic dashboard: per-type "signal panels"
 * (CVE: threat / exploitation / affected; TTP: MITRE + mitigations; …), the
 * description, external pivot links, and Wikipedia. Relational data lives in the
 * Relationships tab; scalar identity fields live in the header.
 */
import { useEffect, useRef, useState, useMemo } from "react";
import api from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import { Link } from "react-router-dom";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  useCVE,
  useCVEWeaknesses,
  useCWE,
  useCWEVendors,
  useCWEFamily,
  useEntityWeaknessProfile,
  useDenyObservable,
  useObservable,
  useTTPMitigations,
  useUpdateObservable,
  useTTPRelatedTechniques,
} from "@/hooks/useIntelligence";
import { useAffectedCveCount, useCveAffectedRows, formatVersionRange, type CVEAffectedEntityRow } from "@/hooks/useAffectedCves";
import { useCountryProfile } from "@/hooks/useCountryProfile";
import {
  useActorVictims,
  useActorVictimStats,
  useEntityDetectionGaps,
  useClearWikipedia,
  useEntityCampaigns,
  useFetchWikipedia,
  useGenerateEntitySummary,
  useWikipediaSearch,
} from "@/hooks/useEntityProfile";
import { useEntityWhatsNew } from "@/hooks/useEngine";
import type { EntityType } from "@/stores/intelStore";
import type { CWEFamilyRef, EntitySearchResult, TimelineEvent, TTPFamilyRef } from "@/api/types";
import { toast } from "sonner";
import { EntityNotesSection } from "@/components/EntityNotesSection";
import { ActivityFeed } from "../ActivityFeed";
import { AIAnalysisModule } from "../AIAnalysisModule";
import { ExploitPocCard, SnapshotCard } from "../SnapshotCard";
import { VictimsStrip } from "../VictimsStrip";
import { ActiveStoryCard } from "../ActiveStoryCard";
import { SourcesCard } from "../SourcesCard";
import { AssessmentBlock } from "../AssessmentBlock";
import { KnownAssociates } from "../KnownAssociates";
import { EssentialReading } from "../EssentialReading";
import { NextActionsRail } from "../NextActionsRail";
import { CampaignIntake } from "../CampaignIntake";
import { useCampaignStats } from "@/hooks/useCampaigns";
import { SinceLastVisitRibbon } from "../SinceLastVisitRibbon";
import type { PivotResponse } from "@/api/types";
import { entityDisplayName, entityProfilePath, type EntityProfileConfig, type OverviewPanelKey } from "../entityProfileConfig";
import { dedupeProducts, extractNvd, type RefLink } from "../cveRefs";
import { capturedByLabel, defangObservable, observableSourcesLabel, reputationLabel, stixBundle, STIX_PATTERNS } from "@/utils/observables";
import { Chip } from "@/components/primitives";
import {
  infrastructureCsvUrl,
  useEntityInfrastructure,
  useObservableBacklinks,
  type ClaimedObservable,
  type ReportedObservable,
} from "@/hooks/useInfrastructure";
import styles from "../entityProfile.module.css";
import { confirmDialog } from "@/utils/dialog";


function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className={styles.panel}>
      <div className={styles.panelTitle}>{title}</div>
      {children}
    </div>
  );
}

function Row({ k, v, mono }: { k: string; v: React.ReactNode; mono?: boolean }) {
  return (
    <div className={styles.panelRow}>
      <span className={styles.panelKey}>{k}</span>
      <span className={`${styles.panelVal} ${mono ? styles.mono : ""}`}>{v}</span>
    </div>
  );
}


/** First paragraph of the attached article, plain-ish, capped for the lede. */
function wikiLede(content: string): string {
  const para = content.split(/\n\s*\n/)[0] ?? content;
  const plain = para
    .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1")
    .replace(/[*_`#]/g, "")
    .trim();
  return plain.length > 420 ? `${plain.slice(0, 420).trimEnd()}…` : plain;
}

export function OverviewTab({
  entityType,
  entityId,
  entity,
  entityLabel,
  config,
  entries,
  events,
  related,
  activitySince = null,
  onShowRelationships,
  onShowDetectionGaps,
  onUpdateField,
  onOpenArticle,
  onOpenEntity,
  onOpenStory,
  provenance,
  anchor,
}: {
  entityType: EntityType;
  entityId: string;
  entity: EntitySearchResult;
  entityLabel: string;
  config: EntityProfileConfig;
  entries: Array<{ id: string; title: string; published_at: string | null }>;
  events: TimelineEvent[];
  /** Full pivot related set — powers the next-actions rail. */
  related?: PivotResponse["related"];
  /** Lower bound from the hero timeline's window picker — scopes the activity feed. */
  activitySince?: Date | null;
  onShowRelationships?: () => void;
  onShowDetectionGaps?: () => void;
  onUpdateField: (field: string, value: string | string[]) => void;
  onOpenArticle: (entryId: string) => void;
  onOpenEntity?: (type: EntityType, id: string, label?: string) => void;
  onOpenStory?: (slug: string) => void;
  /** Field-level claims, shared with the header (same query key). */
  provenance?: import("@/hooks/useEntityProvenance").EntityProvenance;
  /** Deep-link target (?tab=notes): scroll the notes module into view on mount. */
  anchor?: "notes" | null;
}) {
  const activityRef = useRef<HTMLDivElement>(null);
  const notesRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (anchor === "notes") notesRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [anchor]);
  const [wikiOpen, setWikiOpen] = useState(false);
  const [wikiSearchOpen, setWikiSearchOpen] = useState(false);
  const [wikiQuery, setWikiQuery] = useState("");
  const [debouncedWikiQuery, setDebouncedWikiQuery] = useState("");
  useEffect(() => {
    const t = setTimeout(() => setDebouncedWikiQuery(wikiQuery), 300);
    return () => clearTimeout(t);
  }, [wikiQuery]);
  const fetchWikipedia = useFetchWikipedia();
  const clearWikipedia = useClearWikipedia();
  const { data: wikiResults, isFetching: wikiSearching } = useWikipediaSearch(
    entityType,
    entityId,
    wikiSearchOpen ? debouncedWikiQuery : "",
  );
  const { data: cveDetail } = useCVE(entityType === "cve" ? entityId : undefined);
  // A campaign's scope numbers: /stats knows its entity mix and rule coverage,
  // and the story count comes from the threads on its own articles.
  const { data: campaignStatsData } = useCampaignStats(entityType === "campaign" ? entityId : undefined);
  // The page already folds story threads into the event stream as STORY rows,
  // so the count is there rather than needing its own request.
  const campaignStoryCount = useMemo(
    () => (events ?? []).filter((e) => e.event_type === "story").length,
    [events],
  );
  const { data: affectedRows } = useCveAffectedRows(entityType === "cve" ? entityId : undefined);
  const { data: ttpMitigations } = useTTPMitigations(entityType === "ttp" ? entityId : undefined);
  const { data: ttpFamily } = useTTPRelatedTechniques(entityType === "ttp" ? entityId : undefined);
  const { data: cweFamily } = useCWEFamily(entityType === "cwe" ? entityId : undefined);
  // The pivot payload has no corpus counts — they need a join, so like useCVE
  // for the CVE hero this fetches the detail record for the stat row.
  const { data: cweDetail } = useCWE(entityType === "cwe" ? entityId : undefined);
  const { data: observableDetail } = useObservable(entityType === "observable" ? entityId : undefined);
  const { data: infrastructure } = useEntityInfrastructure(entityType, entityId);
  const [infraKind, setInfraKind] = useState<string | null>(null);
  const { data: backlinks } = useObservableBacklinks(entityType === "observable" ? entityId : undefined);
  const updateObservable = useUpdateObservable();
  const denyObservable = useDenyObservable();
  const isAdmin = useAuthStore((s) => s.user?.role === "admin");
  const { data: cweVendors } = useCWEVendors(entityType === "cwe" ? entityId : undefined);
  const { data: cveWeaknesses } = useCVEWeaknesses(entityType === "cve" ? entityId : undefined);
  // Same query keys as VictimsStrip / EntityProfilePage — TanStack dedupes.
  const { data: victims } = useActorVictims(entityId, entityType === "threat_actor");
  const { data: victimStats } = useActorVictimStats(entityId, entityType === "threat_actor");
  const { data: affectedForCounts } = useAffectedCveCount(
    entityType === "vendor" || entityType === "product" ? entityType : undefined,
    entityId,
  );
  // Same query as NextActionsRail — the Snapshot's techniques/rules rows.
  const hasGaps = entityType === "threat_actor" || entityType === "malware";
  const { data: gapsForSnapshot } = useEntityDetectionGaps(
    hasGaps ? entityType : undefined,
    hasGaps ? entityId : undefined,
  );
  const { data: countryProfile } = useCountryProfile(entityType === "country" ? entityId : undefined);
  const { data: weaknessProfile } = useEntityWeaknessProfile(
    entityType === "vendor" || entityType === "product" ? entityType : undefined,
    entityId,
  );
  const nvd =
    entityType === "cve" ? extractNvd(cveDetail?.nvd_data) : { vector: null, cwe: null, references: [], published: null };
  // CVE reference set for the Sources card — structured references_ column
  // preferred, NVD blob as fallback.
  const cveRefLinks: RefLink[] =
    entityType === "cve"
      ? Array.isArray(cveDetail?.references_) && cveDetail.references_.length > 0
        ? cveDetail.references_
            .map((r) =>
              typeof r === "string"
                ? { url: r, tags: [] }
                : { url: (r as { url?: string }).url ?? "", tags: (r as { tags?: string[] }).tags ?? [] },
            )
            .filter((r) => r.url)
        : nvd.references
      : [];

  // Rail's "draft with AI" shares the same endpoint the assessment refresh runs.
  const draftAI = useGenerateEntitySummary();
  const draftAssessment = () => {
    draftAI.mutate(
      { entityType, entityId },
      {
        onSuccess: () => toast.success("Assessment drafted from linked reporting"),
        onError: () => toast.error("Failed to draft assessment"),
      },
    );
  };

  const renderPanel = (key: OverviewPanelKey): React.ReactNode => {
    switch (key) {
      case "cve_affected": {
        const products = dedupeProducts(entity.affected_products);
        // Authoritative cve_affected rows grouped by CPE vendor — resolved
        // vendors/products link to their entity profiles.
        const vendorGroups = new Map<string, { vendorId: string | null; vendorName: string | null; rows: CVEAffectedEntityRow[] }>();
        for (const row of affectedRows ?? []) {
          const group = vendorGroups.get(row.cpe_vendor) ?? { vendorId: row.vendor_id, vendorName: row.vendor_name, rows: [] };
          group.vendorId = group.vendorId ?? row.vendor_id;
          group.vendorName = group.vendorName ?? row.vendor_name;
          group.rows.push(row);
          vendorGroups.set(row.cpe_vendor, group);
        }
        if (vendorGroups.size === 0 && products.length === 0) return null;
        return (
          <Panel key={key} title={vendorGroups.size > 0 ? "Affected — from NVD CPE" : "Affected"}>
            {vendorGroups.size > 0 ? (
              [...vendorGroups.entries()].map(([cpeVendor, group]) => {
                const resolvedCount = group.rows.filter((r) => r.product_id).length;
                return (
                  <div key={cpeVendor} className={styles.affGroup}>
                    <div className={styles.affGroupHead}>
                      {group.vendorId ? (
                        <Link className={styles.affVendorLink} to={entityProfilePath("vendor", group.vendorId)}>
                          {group.vendorName}
                        </Link>
                      ) : (
                        <span className={styles.affUnres}>{cpeVendor}</span>
                      )}
                      <span className={styles.metaLabel}>
                        {group.rows.length} product{group.rows.length === 1 ? "" : "s"}
                        {resolvedCount > 0 && ` · ${resolvedCount} resolved`}
                      </span>
                    </div>
                    {group.rows.map((row) => {
                      const version = formatVersionRange(row.version_start, row.version_end);
                      return (
                        <div key={row.cpe_product} className={styles.affRow}>
                          {row.product_id ? (
                            <Link className={styles.affProdLink} to={entityProfilePath("product", row.product_id)}>
                              {row.product_name}
                            </Link>
                          ) : (
                            <span className={styles.affUnres}>{row.cpe_product}</span>
                          )}
                          {version && <span className={styles.affVer}>{version}</span>}
                        </div>
                      );
                    })}
                  </div>
                );
              })
            ) : products.length > 0 ? (
              <div className={styles.aliases}>
                {products.map((p) => <span key={p} className={styles.alias}>{p}</span>)}
              </div>
            ) : null}
          </Panel>
        );
      }
      case "ttp_mitre":
        if (!entity.platforms?.length && !entity.data_sources?.length && !entity.mitre_url && !entity.detection) return null;
        return (
          <Panel key={key} title="MITRE ATT&CK">
            {entity.mitre_url && (
              <a className={styles.mitreLink} href={entity.mitre_url} target="_blank" rel="noopener noreferrer">View on MITRE ↗</a>
            )}
            {entity.platforms?.length ? (
              <div className={styles.tagRow}><span className={styles.metaLabel}>Platforms</span>{entity.platforms.map((p) => <span key={p} className={styles.platformTag}>{p}</span>)}</div>
            ) : null}
            {entity.data_sources?.length ? (
              <div className={styles.tagRow}><span className={styles.metaLabel}>Data sources</span>{entity.data_sources.map((d) => <span key={d} className={styles.dataSourceTag}>{d}</span>)}</div>
            ) : null}
            {entity.detection && <div className={styles.description}>{entity.detection}</div>}
          </Panel>
        );
      case "ttp_family": {
        if (!ttpFamily || (!ttpFamily.parent && !ttpFamily.subtechniques.length && !ttpFamily.replacement)) return null;
        const techLink = (t: TTPFamilyRef) => (
          <Link key={t.id} className={styles.familyLink} to={entityProfilePath("ttp", t.id)}>
            <span className={styles.mono}>{t.technique_id}</span> {t.technique_name}
          </Link>
        );
        return (
          <Panel key={key} title="Technique Family">
            {ttpFamily.replacement && (
              <div className={styles.tagRow}><span className={styles.metaLabel}>Replaced by</span>{techLink(ttpFamily.replacement)}</div>
            )}
            {ttpFamily.parent && (
              <div className={styles.tagRow}><span className={styles.metaLabel}>Parent</span>{techLink(ttpFamily.parent)}</div>
            )}
            {ttpFamily.subtechniques.length > 0 && (
              <div className={styles.tagRow}>
                <span className={styles.metaLabel}>Sub-techniques ({ttpFamily.subtechniques.length})</span>
                {ttpFamily.subtechniques.map(techLink)}
              </div>
            )}
          </Panel>
        );
      }
      case "ttp_mitigations":
        if (!ttpMitigations?.length) return null;
        return (
          <Panel key={key} title={`Mitigations (${ttpMitigations.length})`}>
            {ttpMitigations.map((m) => (
              <div key={m.id} className={styles.mitiItem}>
                <div className={styles.mitiHeader}>
                  {m.mitre_id && <span className={styles.mitiId}>{m.mitre_id}</span>}
                  <span className={styles.mitiName}>{m.name}</span>
                  {m.mitre_url && <a className={styles.mitreLink} href={m.mitre_url} target="_blank" rel="noopener noreferrer">ATT&CK</a>}
                </div>
                {m.description && <div className={styles.mitiDesc}>{m.description.length > 200 ? `${m.description.slice(0, 200)}…` : m.description}</div>}
              </div>
            ))}
          </Panel>
        );
      case "cwe_family": {
        if (!cweFamily) return null;
        const { lineage, children, siblings, replacement } = cweFamily;
        if (!lineage.length && !children.length && !siblings.length && !replacement) return null;
        const cweLink = (r: CWEFamilyRef) =>
          r.id ? (
            <Link key={r.cwe_id} className={styles.familyLink} to={entityProfilePath("cwe", r.id)}>
              <span className={styles.mono}>{r.cwe_id}</span> {r.name}
            </Link>
          ) : (
            <span key={r.cwe_id} className={styles.mono}>
              {r.cwe_id}
            </span>
          );
        return (
          <Panel key={key} title="Weakness Family">
            {replacement && (
              <div className={styles.tagRow}>
                <span className={styles.metaLabel}>Replaced by</span>
                {cweLink(replacement)}
              </div>
            )}
            {lineage.length > 0 && (
              <div className={styles.tagRow}>
                {/* Root-first, so the row reads pillar → … → parent. The counts
                    are rolled up: a Pillar's own direct links are near zero. */}
                <span className={styles.metaLabel}>Lineage</span>
                {lineage.map(cweLink)}
              </div>
            )}
            {children.length > 0 && (
              <div className={styles.tagRow}>
                <span className={styles.metaLabel}>Children ({children.length})</span>
                {children.slice(0, 8).map(cweLink)}
              </div>
            )}
            {siblings.length > 0 && (
              <div className={styles.tagRow}>
                <span className={styles.metaLabel}>Siblings ({siblings.length})</span>
                {siblings.slice(0, 8).map(cweLink)}
              </div>
            )}
          </Panel>
        );
      }
      case "infrastructure": {
        const infra = infrastructure;
        if (!infra) return null;
        const claimed = infra.claimed;
        const reported = infra.reported_alongside;
        if (claimed.length === 0 && reported.length === 0) {
          const staged = infra.counts?.staged_candidate_articles ?? 0;
          return (
            <Panel key={key} title="Infrastructure">
              <div className={styles.metaLabel} style={{ textTransform: "none", letterSpacing: 0 }}>
                No infrastructure captured yet. IPs, domains and hashes found in{" "}
                {entityType === "campaign" ? "this campaign's articles" : "articles about it"} will appear here —
                ones attributed to it first, then ones merely reported alongside it.
                {staged > 0 && (
                  <>
                    {" "}
                    {staged === 1 ? "One article has" : `${staged} articles have`} indicators waiting for review —{" "}
                    <Link to="/workbench/explore?section=observables&queue=1">open the candidates queue</Link>.
                  </>
                )}
              </div>
            </Panel>
          );
        }
        const allValues = [...claimed, ...reported];
        const copyAll = async () => {
          try {
            await navigator.clipboard.writeText(allValues.map((r) => defangObservable(r.kind, r.value)).join("\n"));
            toast.success(`Copied ${allValues.length} defanged values`);
          } catch {
            toast.error("Clipboard unavailable");
          }
        };
        const exportCsv = async () => {
          try {
            const { data } = await api.get(infrastructureCsvUrl(entityType, entityId), { responseType: "blob" });
            const url = URL.createObjectURL(data as Blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `${entityType}-infrastructure.csv`;
            a.click();
            URL.revokeObjectURL(url);
          } catch {
            toast.error("Export failed");
          }
        };
        const byKind = infra.counts?.by_kind ?? {};
        const kindKeys = Object.keys(byKind).sort((a, b) => byKind[b] - byKind[a]);
        const visibleClaimed = infraKind ? claimed.filter((r) => r.kind === infraKind) : claimed;
        const visibleReported = infraKind ? reported.filter((r) => r.kind === infraKind) : reported;
        const exportStix = () => {
          const items = [...visibleClaimed, ...visibleReported].filter((r) => STIX_PATTERNS[r.kind]);
          const blob = new Blob([stixBundle(items)], { type: "application/json" });
          const a = document.createElement("a");
          a.href = URL.createObjectURL(blob);
          a.download = `${entityType}-infrastructure.stix.json`;
          a.click();
          URL.revokeObjectURL(a.href);
        };
        const trust = (c: ClaimedObservable) =>
          c.relationship_confidence === "confirmed" ? "corroborated" : c.relationship_confidence === "probable" ? "reported" : "signal";
        const renderRow = (r: ClaimedObservable | ReportedObservable, meta: string) => (
          <div key={r.id} className={styles.affRow}>
            <Link className={styles.affProdLink} to={entityProfilePath("observable", r.id)} style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
              {defangObservable(r.kind, r.value)}
            </Link>
            <span className={styles.metaLabel}>
              {[r.kind.replace(/_/g, " "), r.role?.replace(/_/g, " "), meta, r.infra_tag ? `${r.infra_tag} · dual-use` : null]
                .filter(Boolean)
                .join(" · ")}
            </span>
          </div>
        );
        return (
          <Panel key={key} title={`Infrastructure · ${allValues.length}`}>
            {kindKeys.length > 1 && (
              <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 8 }}>
                {kindKeys.map((k) => (
                  <Chip
                    key={k}
                    tone={infraKind === k ? "toned" : "default"}
                    tint={infraKind === k ? "var(--entity-observable)" : undefined}
                    aria-pressed={infraKind === k}
                    onClick={() => setInfraKind(infraKind === k ? null : k)}
                  >
                    {k.replace(/_/g, " ")} · {byKind[k]}
                  </Chip>
                ))}
              </div>
            )}
            {claimed.length > 0 && (
              <div className={styles.affGroup}>
                <div className={styles.affGroupHead}>
                  <span>Claimed</span>
                  <span className={styles.metaLabel}>attribution edges with evidence</span>
                </div>
                {visibleClaimed.map((c) => renderRow(c, `${c.relationship_type.replace(/_/g, " ")} · ${trust(c)}${c.evidence_count > 1 ? ` ×${c.evidence_count}` : ""}`))}
              </div>
            )}
            {reported.length > 0 && (
              <div className={styles.affGroup}>
                <div className={styles.affGroupHead}>
                  <span>Reported alongside</span>
                  <span className={styles.metaLabel}>same articles, not yet an attribution claim</span>
                </div>
                {visibleReported.map((r) => renderRow(r, `${r.article_count} article${r.article_count === 1 ? "" : "s"}`))}
              </div>
            )}
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 10 }}>
              <button className={styles.railBtn} onClick={copyAll}>Copy all defanged</button>
              <button className={styles.railBtn} onClick={exportCsv}>Export CSV</button>
              <button className={styles.railBtn} onClick={exportStix} title="STIX 2.1 bundle of the patternable values">Export STIX</button>
              <Link
                className={styles.railBtn}
                to={`/workbench/observables?linked_entity=${entityType}:${entityId}`}
                title="Open the observables browser filtered to this entity's infrastructure"
              >
                Open in observables browser
              </Link>
            </div>
          </Panel>
        );
      }
      case "observable_backlinks": {
        const b = backlinks;
        if (!b || (b.claimed_by.length === 0 && b.reported_with.length === 0)) return null;
        const row = (x: { entity_type: string; entity_id: string; name: string | null }, meta: string) => (
          <div key={`${x.entity_type}-${x.entity_id}`} className={styles.affRow}>
            <Link className={styles.affProdLink} to={entityProfilePath(x.entity_type as EntityType, x.entity_id)}>
              {x.name ?? x.entity_id}
            </Link>
            <span className={styles.metaLabel}>{meta}</span>
          </div>
        );
        return (
          <Panel key={key} title="Attribution">
            {b.claimed_by.length > 0 && (
              <div className={styles.affGroup}>
                <div className={styles.affGroupHead}>
                  <span>Claimed by</span>
                  <span className={styles.metaLabel}>evidence-backed edges</span>
                </div>
                {b.claimed_by.map((c) =>
                  row(c, `${c.entity_type.replace(/_/g, " ")} · ${(c.relationship_type ?? "").replace(/_/g, " ")} · ${c.relationship_confidence}`),
                )}
              </div>
            )}
            {b.reported_with.length > 0 && (
              <div className={styles.affGroup}>
                <div className={styles.affGroupHead}>
                  <span>Reported with</span>
                  <span className={styles.metaLabel}>named in the same articles</span>
                </div>
                {b.reported_with.map((r) =>
                  row(r, `${r.entity_type.replace(/_/g, " ")} · ${r.article_count} article${r.article_count === 1 ? "" : "s"}`),
                )}
              </div>
            )}
          </Panel>
        );
      }
      case "observable_provenance": {
        const o = observableDetail;
        if (!o) return null;
        const pct = (v: number) => `${Math.round(v * 100)}%`;
        return (
          <Panel key={key} title="Provenance & confidence">
            {o.created_via && <Row k="Captured by" v={capturedByLabel(o.created_via)} />}
            {o.reputation && (
              <Row
                k="Reputation"
                v={`${reputationLabel(o.reputation)}${o.reputation.enriched_at ? ` (enriched ${String(o.reputation.enriched_at).slice(0, 10)})` : ""}`}
              />
            )}
            {o.infra_tag && (
              <Row
                k="Infrastructure"
                v={`${o.infra_tag.replace(/_/g, " ")} — dual-use, excluded from publishing`}
              />
            )}
            {o.role && <Row k="Role" v={o.role} />}
            {o.evidence && (
              <Row k="Evidence" v={<span className={styles.metaLabel} style={{ fontStyle: "italic", textTransform: "none", letterSpacing: 0 }}>“{o.evidence}”</span>} />
            )}
            <Row k="Base confidence" v={pct(o.base_confidence)} />
            <Row
              k="Current"
              v={`${pct(o.current_confidence)}${o.status !== "active" ? ` · ${o.status}` : ""}${o.confidence_pinned ? " · pinned" : ""}`}
            />
            <Row
              k="Decay"
              v={
                o.decay_half_life_days
                  ? `${o.decay_half_life_days}d half-life — a new sighting resets the clock`
                  : "never — behavior and math persist"
              }
            />
            {o.expires_at && !o.confidence_pinned && (
              <Row k="Expires" v={`~${new Date(o.expires_at).toLocaleDateString()} unless re-sighted`} />
            )}
            <Row
              k="Sources"
              v={
                o.report_count || o.feed_source_count
                  ? `${observableSourcesLabel(o)} (${o.sighting_count} raw sightings)`
                  : `${o.sighting_count} raw sightings`
              }
            />
            {!o.report_count && o.feed_source_count > 0 && (
              <Row
                k="Reporting"
                v="None — this value is listed on an indicator feed; no article has reported it yet, so there is nothing to attribute"
              />
            )}
            {["ipv4", "ipv6", "domain", "url", "email"].includes(o.kind) && (
              <Row k="Defanged" v={<code style={{ fontSize: 11 }}>{defangObservable(o.kind, o.value)}</code>} />
            )}
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 10 }}>
              <button className={styles.railBtn} onClick={() => navigator.clipboard.writeText(o.value)}>
                Copy value
              </button>
              <button className={styles.railBtn} onClick={() => navigator.clipboard.writeText(defangObservable(o.kind, o.value))}>
                Copy defanged
              </button>
              <button
                className={styles.railBtn}
                onClick={async () => {
                  try {
                    const resp = await api.get(`/observables/${o.id}/sightings.csv`, { responseType: "blob" });
                    const url = URL.createObjectURL(resp.data as Blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = `sightings-${o.value.slice(0, 40).replace(/[^\w.-]/g, "_")}.csv`;
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    setTimeout(() => URL.revokeObjectURL(url), 1000);
                  } catch {
                    toast.error("Sightings export failed");
                  }
                }}
              >
                Export sightings CSV
              </button>
              <button
                className={styles.railBtn}
                disabled={updateObservable.isPending}
                onClick={() => updateObservable.mutate({ observableId: o.id, confidence_pinned: !o.confidence_pinned })}
                title="Pinned confidence never decays"
              >
                {o.confidence_pinned ? "Unpin confidence" : "Pin confidence"}
              </button>
              {isAdmin && !o.is_denied && (
                <button
                  className={styles.railBtn}
                  disabled={denyObservable.isPending}
                  onClick={async () => {
                    if (
                      await confirmDialog({
                        title: "Never capture this value",
                        message: `Never capture or export ${o.value} again?`,
                        confirmLabel: "Never capture",
                        destructive: true,
                      })
                    )
                      denyObservable.mutate(o.id);
                  }}
                  title="Tombstone: never capture or export this value"
                >
                  Never capture
                </button>
              )}
            </div>
            {o.kind === "script" && o.content && (
              <pre style={{ marginTop: 8, maxHeight: 180, overflow: "auto", fontSize: 11, fontFamily: "var(--font-mono)" }}>
                {o.content.slice(0, 2000)}
              </pre>
            )}
          </Panel>
        );
      }
      case "cwe_catalog": {
        const consequences = (entity.consequences ?? []).filter((c) => c.scope || c.impacts?.length);
        if (!entity.cwe_url && !consequences.length && !entity.alternate_terms?.length) return null;
        return (
          <Panel key={key} title="MITRE CWE">
            {entity.cwe_url && (
              <a className={styles.mitreLink} href={entity.cwe_url} target="_blank" rel="noopener noreferrer">
                View on cwe.mitre.org ↗
              </a>
            )}
            {entity.status && <Row k="Status" v={entity.status} />}
            {entity.mapping_usage && (
              <Row
                k="Mapping"
                v={
                  <span title="MITRE guidance on whether a CVE should be tagged with this id">
                    {entity.mapping_usage}
                  </span>
                }
              />
            )}
            {entity.alternate_terms && entity.alternate_terms.length > 0 && (
              <div className={styles.tagRow}>
                <span className={styles.metaLabel}>Also called</span>
                {entity.alternate_terms.map((t) => (
                  <span key={t} className={styles.platformTag}>
                    {t}
                  </span>
                ))}
              </div>
            )}
            {consequences.length > 0 && (
              <div className={styles.tagRow}>
                <span className={styles.metaLabel}>Consequences</span>
                {consequences.map((c, i) => (
                  <span key={`${c.scope}-${i}`} className={styles.dataSourceTag} title={c.impacts?.join(" · ")}>
                    {c.scope}
                  </span>
                ))}
              </div>
            )}
            {entity.capec_ids && entity.capec_ids.length > 0 && (
              <div className={styles.tagRow}>
                <span className={styles.metaLabel}>CAPEC</span>
                {entity.capec_ids.slice(0, 6).map((c) => (
                  <span key={c} className={styles.platformTag}>
                    {c}
                  </span>
                ))}
              </div>
            )}
          </Panel>
        );
      }
      case "cwe_mitigations": {
        // Same markup as ttp_mitigations — the catalog's phase plays the part
        // the M-ID plays there, and the strategy the part the name plays.
        const mitigations = entity.mitigations ?? [];
        if (!mitigations.length) return null;
        return (
          <Panel key={key} title={`Mitigations (${mitigations.length})`}>
            {mitigations.slice(0, 5).map((m, i) => (
              <div key={`${m.phase}-${i}`} className={styles.mitiItem}>
                <div className={styles.mitiHeader}>
                  {m.phase && <span className={styles.mitiId}>{m.phase}</span>}
                  {m.strategy && <span className={styles.mitiName}>{m.strategy}</span>}
                </div>
                {m.description && (
                  <div className={styles.mitiDesc}>
                    {m.description.length > 200 ? `${m.description.slice(0, 200)}…` : m.description}
                  </div>
                )}
              </div>
            ))}
          </Panel>
        );
      }
      case "cwe_affected_vendors": {
        if (!cweVendors?.length) return null;
        return (
          <Panel key={key} title="Most-affected vendors — from NVD CPE">
            {cweVendors.map((v) => (
              <div key={v.vendor_id} className={styles.affRow}>
                <Link className={styles.affProdLink} to={entityProfilePath("vendor", v.vendor_id)}>
                  {v.name}
                </Link>
                <span className={styles.affVer}>
                  {v.cve_count} CVE{v.cve_count === 1 ? "" : "s"}
                  {v.kev_count > 0 ? ` · ${v.kev_count} KEV` : ""}
                </span>
              </div>
            ))}
          </Panel>
        );
      }
      case "cwe_vendors": {
        if (!weaknessProfile?.length) return null;
        return (
          <Panel key={key} title="Weakness profile — from NVD">
            {weaknessProfile.map((w) => (
              <div key={w.cwe_id} className={styles.affRow}>
                <span className={styles.mono}>{w.cwe_id}</span>
                <span className={styles.affProdLink}>{w.name}</span>
                <span className={styles.affVer}>
                  {w.cve_count} CVE{w.cve_count === 1 ? "" : "s"} · {Math.round(w.share * 100)}%
                </span>
              </div>
            ))}
          </Panel>
        );
      }
      default:
        return null;
    }
  };

  const panels = config.overviewPanels.map(renderPanel).filter(Boolean);
  // scoped=true: the profile's Latest Developments list only carries events
  // about THIS entity, not first-mentions of co-occurring ones.
  const { data: whatsNew } = useEntityWhatsNew(entityType, entityId, true, true);
  const { data: campaigns } = useEntityCampaigns(entityType, entityId);

  return (
    <div className={styles.tabPanel}>
      <SinceLastVisitRibbon
        key={entityId}
        entityId={entityId}
        entries={entries}
        events={events}
        kevAddedAt={entityType === "cve" ? (cveDetail?.kev_date_added ?? entity.kev_date_added) : undefined}
        victimDates={entityType === "threat_actor" ? (victims?.items ?? []).map((v) => v.last_seen_at) : undefined}
        onCatchUp={() => activityRef.current?.scrollIntoView({ behavior: "smooth", block: "start" })}
      />
      {/* Associates open the Overview (moved out of the fixed header so other
          tabs don't pay for the strip). */}
      {related && onOpenEntity && onShowRelationships && (
        <KnownAssociates
          entityType={entityType}
          entityLabel={entityLabel}
          related={related}
          onOpenEntity={onOpenEntity}
          onShowRelationships={onShowRelationships}
        />
      )}
      {/* Catalog-keyed types retire entries, and CWE additionally publishes
          categories that are never valid mapping targets — a Draft-status
          category is not "deprecated" but carries the same warning, so the
          CWE branch checks kind as well. */}
      {((entityType === "ttp" && entity.is_deprecated) ||
        (entityType === "cwe" && (entity.is_deprecated || entity.kind === "category"))) && (
        <div className={styles.deprecationNotice}>
          {entityType === "cwe" ? (
            entity.kind === "category" ? (
              <>
                This is a MITRE <em>category</em>, not a weakness. Categories group weaknesses
                sideways and every one is marked <span className={styles.mono}>Prohibited</span> for
                mapping, so a CVE should never carry this id — the ones that do were tagged back when
                NVD mapped against categories.
              </>
            ) : entity.superseded_by ? (
              <>
                This weakness was retired from the CWE catalog and replaced by{" "}
                {cweFamily?.replacement?.id ? (
                  <Link className={styles.familyLink} to={entityProfilePath("cwe", cweFamily.replacement.id)}>
                    <span className={styles.mono}>{cweFamily.replacement.cwe_id}</span> {cweFamily.replacement.name}
                  </Link>
                ) : (
                  <span className={styles.mono}>{entity.superseded_by}</span>
                )}
                . CVEs already tagged with the old id keep it — NVD does not rewrite history.
              </>
            ) : (
              <>This entry is retired from the CWE catalog and no longer maintained.</>
            )
          ) : entity.superseded_by ? (
            <>
              This technique was revoked by MITRE and replaced by{" "}
              {ttpFamily?.replacement ? (
                <Link className={styles.familyLink} to={entityProfilePath("ttp", ttpFamily.replacement.id)}>
                  <span className={styles.mono}>{ttpFamily.replacement.technique_id}</span> {ttpFamily.replacement.technique_name}
                </Link>
              ) : (
                <span className={styles.mono}>{entity.superseded_by}</span>
              )}
              . New extractions map to the replacement automatically.
            </>
          ) : (
            <>This technique is deprecated in the MITRE ATT&CK catalog and no longer maintained.</>
          )}
        </div>
      )}
      <div className={styles.briefingGrid}>
        <div className={styles.briefingCol}>
          {config.hasDescription && (
            <AssessmentBlock
              entityType={entityType}
              entityId={entityId}
              entity={entity}
              editable={entityType !== "mitigation"}
              whatsNew={whatsNew ?? []}
              onUpdateField={onUpdateField}
              onOpenArticle={onOpenArticle}
            />
          )}
          <AIAnalysisModule entityType={entityType} entityId={entityId} />
          {entityType === "threat_actor" && <VictimsStrip entityId={entityId} />}
          <EssentialReading entityType={entityType} entityId={entityId} onOpenArticle={onOpenArticle} />

          {/* Wikipedia renders only when an article is attached — collapsed to
              its lede; the attach flow starts from the Sources card. */}
          {entity.wikipedia_content && (
            <div className={styles.wikiSection}>
              <div className={styles.wikiHeader}>
                <span className={styles.wikiTitleLabel}>Wikipedia</span>
                {entity.wikipedia_url && (
                  <a className={styles.wikiLink} href={entity.wikipedia_url} target="_blank" rel="noopener noreferrer">
                    View article ↗
                  </a>
                )}
                <button
                  className={styles.wikiSearchBtn}
                  onClick={() => {
                    setWikiSearchOpen((o) => !o);
                    if (!wikiSearchOpen) setWikiQuery(entity.name || entity.cve_id || "");
                  }}
                >
                  Wrong article?
                </button>
              </div>
              {wikiOpen ? (
                <div className={styles.wikiContent}>
                  <Markdown remarkPlugins={[remarkGfm]}>{entity.wikipedia_content}</Markdown>
                  <button className={styles.wikiLedeMore} onClick={() => setWikiOpen(false)}>
                    show less <span className="caret-glyph">▴</span>
                  </button>
                </div>
              ) : (
                <div className={styles.wikiLede}>
                  {wikiLede(entity.wikipedia_content)}{" "}
                  <button className={styles.wikiLedeMore} onClick={() => setWikiOpen(true)}>
                    read more <span className="caret-glyph">▾</span>
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Analyst notes — folded in from the old Notes tab; ?tab=notes lands here. */}
          <div ref={notesRef} className={styles.notesModule}>
            <EntityNotesSection entityType={entityType} entityId={entityId} />
          </div>

          <div ref={activityRef}>
            <ActiveStoryCard entityType={entityType} entityId={entityId} />
            {/* Wide column, not the rail: the rail could say that something
                would be added without ever saying what. */}
            {entityType === "campaign" && (
              <CampaignIntake campaignId={entityId} onOpenArticle={onOpenArticle} />
            )}
            <ActivityFeed
              entityType={entityType}
              entityId={entityId}
              entries={entries}
              events={events}
              since={activitySince}
              onOpenArticle={onOpenArticle}
              onOpenStory={onOpenStory}
            />
          </div>
        </div>

        <div className={styles.railCol}>
          <SnapshotCard
            entityType={entityType}
            entity={entity}
            cveDetail={cveDetail}
            cweDetail={cweDetail}
            cveWeaknesses={cveWeaknesses}
            cvssVector={nvd.vector}
            campaigns={campaigns}
            provenance={provenance}
            victimStats={victimStats}
            affected={affectedForCounts}
            techniques={
              gapsForSnapshot && gapsForSnapshot.total_ttps > 0
                ? { total: gapsForSnapshot.total_ttps, gaps: gapsForSnapshot.gap_count }
                : null
            }
            ruleCount={related?.detection_rules?.length ?? 0}
            campaignStats={
              campaignStatsData
                ? {
                    entries: campaignStatsData.entry_count,
                    stories: campaignStoryCount,
                    actors: campaignStatsData.entity_counts?.threat_actor ?? 0,
                    malware: campaignStatsData.entity_counts?.malware ?? 0,
                    cves: campaignStatsData.entity_counts?.cve ?? 0,
                    techniques: campaignStatsData.entity_counts?.ttp ?? 0,
                    coveragePct: campaignStatsData.detection_coverage_pct ?? null,
                  }
                : null
            }
            countryStats={
              countryProfile
                ? {
                    origins: countryProfile.origin_actors.length,
                    targeting: countryProfile.targeting_actors.length,
                    roles: countryProfile.role_breakdown ?? {},
                  }
                : null
            }
            onOpenArticle={onOpenArticle}
          />
          {entityType === "cve" && <ExploitPocCard entity={entity} cveDetail={cveDetail} />}
          {/* Sources ahead of the per-type panels — on panel-heavy types (CWE)
              it was landing below the fold. */}
          <SourcesCard
            entityType={entityType}
            entityId={entityId}
            entity={entity}
            config={config}
            cveReferences={entityType === "cve" ? cveRefLinks : undefined}
            // Gated on the config's own declaration rather than "has no wiki
            // content yet": a campaign is an internal object with nothing to
            // look up, and offering the search returned an error on click.
            onFindWikipedia={
              entity.wikipedia_content || !config.actions.includes("fetch_wikipedia")
                ? undefined
                : () => {
                    setWikiSearchOpen((o) => !o);
                    if (!wikiSearchOpen) setWikiQuery(entity.name || entity.cve_id || "");
                  }
            }
          />
          {panels}
        {wikiSearchOpen && (
          <div className={styles.wikiSearchPop}>
            <input
              className={styles.wikiSearchInput}
              value={wikiQuery}
              onChange={(e) => setWikiQuery(e.target.value)}
              placeholder="Search Wikipedia…"
              autoFocus
            />
            {wikiSearching && <div className={styles.wikiSearchStatus}>Searching…</div>}
            {!wikiSearching && wikiResults && wikiResults.length === 0 && (
              <div className={styles.wikiSearchStatus}>No articles found</div>
            )}
            {wikiResults && wikiResults.length > 0 && (
              <div className={styles.wikiSearchResults}>
                {wikiResults.map((r) => (
                  <button
                    key={r.title}
                    className={styles.wikiSearchResult}
                    disabled={fetchWikipedia.isPending}
                    onClick={() => {
                      fetchWikipedia.mutate(
                        { entityType, entityId, title: r.title },
                        { onSuccess: () => { setWikiSearchOpen(false); setWikiOpen(true); } },
                      );
                    }}
                  >
                    <span className={styles.wikiSearchResultTitle}>{r.title}</span>
                    {r.snippet && <span className={styles.wikiSearchResultSnippet}>{r.snippet}</span>}
                  </button>
                ))}
              </div>
            )}
            {fetchWikipedia.isPending && <div className={styles.wikiSearchStatus}>Applying…</div>}
            <button
              className={styles.wikiSearchNone}
              disabled={clearWikipedia.isPending || fetchWikipedia.isPending}
              onClick={() => {
                clearWikipedia.mutate(
                  { entityType, entityId },
                  { onSuccess: () => { setWikiSearchOpen(false); setWikiOpen(false); } },
                );
              }}
            >
              {clearWikipedia.isPending ? "Clearing…" : "None — no Wikipedia article"}
            </button>
          </div>
        )}
          {related && onShowRelationships && (
            <NextActionsRail
              entityType={entityType}
              entityId={entityId}
              entity={entity}
              displayName={entityDisplayName(entity, entityId)}
              related={related}
              entries={entries}
              onShowRelationships={onShowRelationships}
              onShowDetectionGaps={onShowDetectionGaps ?? onShowRelationships}
              onDraftAssessment={draftAssessment}
              draftPending={draftAI.isPending}
            />
          )}
        </div>
      </div>
    </div>
  );
}
