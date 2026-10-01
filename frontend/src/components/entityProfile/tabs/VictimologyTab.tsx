/**
 * VictimologyTab — what the generic pivot can't say about a sector: who targets
 * it split into *reported* (co-occurs on articles the AI judged to describe the
 * sector as hit) and *asserted* (a targets-sector claim with its source), the
 * leak-site victims posted in it, the country cross-tab, campaigns scoped to it
 * and the intel profiles that include the vertical. Backed by
 * GET /sectors/{id}/profile (useSectorProfile).
 */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useSectorProfile } from "@/hooks/useSectorProfile";
import { formatDate } from "@/utils/formatDate";
import type { EntityType } from "@/stores/intelStore";
import type { EntitySearchResult, MonthCount } from "@/api/types";
import type { RelRow } from "@/utils/relationshipBrowser";
import { RelationshipRow } from "../RelationshipRow";
import styles from "../entityProfile.module.css";
import { AsyncStateLoading } from "@/components/AsyncState";

const STATUS_COLORS: Record<string, string> = {
  active: "#38a169",
  monitoring: "#3182ce",
  closed: "#718096",
  historical: "#a0aec0",
};

const WINDOWS = [30, 90, 180, 365] as const;

const CLAIM_SOURCE_LABEL: Record<string, string> = {
  rollup: "rolled up from articles",
  enrichment: "MISP / CFR",
  seed: "curated",
  analyst: "analyst",
};

function MonthBars({ series, label }: { series: MonthCount[]; label: string }) {
  if (!series.length) return null;
  const max = Math.max(...series.map((m) => m.count), 1);
  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader}>{label}</div>
      <div
        style={{ display: "flex", alignItems: "flex-end", gap: 3, height: 48 }}
        role="img"
        aria-label={`${label}: ${series.map((m) => `${m.month.slice(0, 7)} ${m.count}`).join(", ")}`}
      >
        {series.map((m) => (
          <div
            key={m.month}
            title={`${m.month.slice(0, 7)}: ${m.count}`}
            style={{
              flex: 1,
              height: `${Math.max(4, Math.round((m.count / max) * 100))}%`,
              background: "var(--entity-sector)",
              opacity: 0.75,
              borderRadius: 2,
            }}
          />
        ))}
      </div>
    </div>
  );
}

export function VictimologyTab({
  entityId,
  entityLabel,
  onOpenEntity,
  onOpenArticle,
}: {
  entityId: string;
  entityLabel?: string;
  onOpenEntity: (type: EntityType, id: string, label?: string) => void;
  onOpenArticle: (entryId: string) => void;
}) {
  const navigate = useNavigate();
  const [windowDays, setWindowDays] = useState<number>(90);
  const { data: profile, isLoading } = useSectorProfile(entityId, windowDays);

  if (isLoading && !profile) {
    return <div className={styles.tabPanel}><AsyncStateLoading label="Loading victimology…" /></div>;
  }
  if (!profile) {
    return <div className={styles.tabPanel}><div className={styles.emptySection}>No victimology data.</div></div>;
  }

  const viewedLabel = entityLabel || profile.sector.name || "this sector";
  const { victims, countries, campaigns, intel_profiles } = profile;

  const reportedActorRows: RelRow[] = profile.reported_actors.map((a) => ({
    type: "threat_actor" as EntityType, label: a.name, meta: `${a.article_count} article${a.article_count === 1 ? "" : "s"}`,
    item: { id: a.id } as EntitySearchResult,
  }));
  const reportedMalwareRows: RelRow[] = profile.reported_malware.map((m) => ({
    type: "malware" as EntityType, label: m.name, meta: `${m.article_count} article${m.article_count === 1 ? "" : "s"}`,
    item: { id: m.id } as EntitySearchResult,
  }));
  const claimMeta = (source: string, n: number) =>
    `${CLAIM_SOURCE_LABEL[source] ?? source}${n ? ` · ${n} article${n === 1 ? "" : "s"}` : ""}`;
  const assertedActorRows: RelRow[] = profile.asserted_actors.map((a) => ({
    type: "threat_actor" as EntityType, label: a.name, meta: claimMeta(a.source, a.article_count),
    item: { id: a.id } as EntitySearchResult,
  }));
  const assertedMalwareRows: RelRow[] = profile.asserted_malware.map((m) => ({
    type: "malware" as EntityType, label: m.name, meta: claimMeta(m.source, m.article_count),
    item: { id: m.id } as EntitySearchResult,
  }));

  const renderRows = (title: string, rows: RelRow[], emptyText: string) => (
    <div className={styles.section}>
      <div className={styles.sectionHeader}>
        {title} <span className={styles.sectionCount}>{rows.length}</span>
      </div>
      {rows.length === 0 ? (
        <div className={styles.emptySection}>{emptyText}</div>
      ) : (
        rows.map((row) => (
          <RelationshipRow key={`${row.type}-${row.item.id}`} row={row} viewedLabel={viewedLabel} onOpen={onOpenEntity} />
        ))
      )}
    </div>
  );

  return (
    <div className={styles.tabPanel}>
      <div className={styles.statGrid}>
        <span className={styles.statChip}>{profile.sector.article_count} articles</span>
        <span className={styles.statChip}>{victims.total} leak-site victims all time</span>
        <span className={styles.statChip}>{victims.in_window} in the last {profile.window_days} days</span>
        <span className={styles.statChip} style={{ marginLeft: "auto" }}>
          window{" "}
          {WINDOWS.map((w) => (
            <button
              key={w}
              type="button"
              onClick={() => setWindowDays(w)}
              aria-pressed={windowDays === w}
              style={{
                background: "none",
                border: "none",
                cursor: "pointer",
                padding: "0 4px",
                color: windowDays === w ? "var(--entity-sector)" : "inherit",
                fontWeight: windowDays === w ? 600 : 400,
              }}
            >
              {w}d
            </button>
          ))}
        </span>
      </div>

      <div className={styles.relGroups}>
        {renderRows("Threat Actors — reported", reportedActorRows, "No articles describe an actor hitting this sector yet.")}
        {renderRows("Malware — reported", reportedMalwareRows, "No articles describe a family hitting this sector yet.")}
        {renderRows("Threat Actors — asserted", assertedActorRows, "No targets-sector claims on actors.")}
        {renderRows("Malware — asserted", assertedMalwareRows, "No targets-sector claims on malware.")}
      </div>

      <MonthBars series={victims.monthly} label="Leak-site victims by month" />
      <MonthBars series={profile.articles_monthly} label="Articles by month" />

      {victims.top_groups.length > 0 && (
        <div className={styles.section}>
          <div className={styles.sectionHeader}>
            Ransomware groups posting victims <span className={styles.sectionCount}>{victims.top_groups.length}</span>
          </div>
          <div className={styles.statGrid}>
            {victims.top_groups.map((g) => (
              <span key={g.group} className={styles.statChip} title={`${g.victims} victims in ${profile.window_days} days`}>
                {g.group} <span className={styles.entityMeta}>×{g.victims}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {victims.recent.length > 0 && (
        <div className={styles.section}>
          <div className={styles.sectionHeader}>
            Recent disclosures <span className={styles.sectionCount}>{victims.recent.length}</span>
          </div>
          <div className={styles.entityList}>
            {victims.recent.map((v) => (
              <div key={v.id} className={styles.entityItem}>
                <button
                  className={styles.entityItemInner}
                  onClick={() => navigate(`/workbench/explore?section=ransomware&victim=${v.victim_id}`)}
                  title="Open in Leak Watch"
                >
                  <span className={styles.entityLabel}>{v.victim_name}</span>
                  {v.group && <span className={styles.entityMeta}>{v.group}</span>}
                  {v.country_code && <span className={styles.entityMeta}>{v.country_code}</span>}
                  {v.posted_at && <span className={styles.entityMeta}>{formatDate(v.posted_at)}</span>}
                </button>
              </div>
            ))}
          </div>
          <div className={styles.emptySection}>Leak-site claims are the gang's claims, not confirmed breaches.</div>
        </div>
      )}

      {countries.length > 0 && (
        <div className={styles.section}>
          <div className={styles.sectionHeader}>
            Where it is hit <span className={styles.sectionCount}>{countries.length}</span>
          </div>
          <div className={styles.entityList}>
            {countries.map((c) => (
              <div key={c.id} className={styles.entityItem}>
                <button className={styles.entityItemInner} onClick={() => onOpenEntity("country", c.id, c.name)}>
                  <span className={styles.entityLabel}>{c.name}</span>
                  {c.article_count > 0 && <span className={styles.entityMeta}>{c.article_count} articles</span>}
                  {c.victim_count > 0 && <span className={styles.entityMeta}>{c.victim_count} victims</span>}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {campaigns.length > 0 && (
        <div className={styles.section}>
          <div className={styles.sectionHeader}>
            Campaigns <span className={styles.sectionCount}>{campaigns.length}</span>
          </div>
          <div className={styles.entityList}>
            {campaigns.map((c) => (
              <div key={c.id} className={styles.entityItem}>
                <button className={styles.entityItemInner} onClick={() => navigate(`/workbench/campaign/${c.id}`)}>
                  <span className={styles.statDot} style={{ background: STATUS_COLORS[c.status] || "#718096" }} />
                  <span className={styles.entityLabel}>{c.name}</span>
                  {c.start_date && <span className={styles.entityMeta}>{formatDate(c.start_date)}</span>}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {intel_profiles.length > 0 && (
        <div className={styles.section}>
          <div className={styles.sectionHeader}>
            Intel profiles scoping this vertical <span className={styles.sectionCount}>{intel_profiles.length}</span>
          </div>
          <div className={styles.statGrid}>
            {intel_profiles.map((p) => (
              <span key={p.id} className={styles.statChip}>{p.name}</span>
            ))}
          </div>
        </div>
      )}

      {profile.recent_entries.length > 0 && (
        <div className={styles.section}>
          <div className={styles.sectionHeader}>
            Recent articles <span className={styles.sectionCount}>{profile.recent_entries.length}</span>
          </div>
          <div className={styles.entityList}>
            {profile.recent_entries.map((e) => (
              <div key={e.id} className={styles.entityItem}>
                <button className={styles.entityItemInner} onClick={() => onOpenArticle(e.id)}>
                  <span className={styles.entityLabel}>{e.title}</span>
                  {e.published_at && <span className={styles.entityMeta}>{formatDate(e.published_at)}</span>}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
