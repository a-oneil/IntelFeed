/**
 * GeographyTab — country-specific intelligence that the generic pivot doesn't
 * capture: role breakdown (origin/target/infrastructure/mentioned), threat
 * actors attributed to vs. targeting this country, related countries, and linked
 * campaigns. Backed by the country-profile endpoint (useCountryProfile). Folds in
 * the retired CountryProfilePage.
 */
import { useNavigate } from "react-router-dom";
import { useCountryProfile } from "@/hooks/useCountryProfile";
import { formatDate } from "@/utils/formatDate";
import type { EntityType } from "@/stores/intelStore";
import type { EntitySearchResult } from "@/api/types";
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

export function GeographyTab({
  entityId,
  entityLabel,
  onOpenEntity,
}: {
  entityId: string;
  entityLabel?: string;
  onOpenEntity: (type: EntityType, id: string, label?: string) => void;
}) {
  const navigate = useNavigate();
  const { data: profile, isLoading } = useCountryProfile(entityId);

  if (isLoading) {
    return <div className={styles.tabPanel}><AsyncStateLoading label="Loading geography…" /></div>;
  }
  if (!profile) {
    return <div className={styles.tabPanel}><div className={styles.emptySection}>No geographic data.</div></div>;
  }

  const { origin_actors, targeting_actors, campaigns, role_breakdown, related_countries } = profile;
  const totalMentions = Object.values(role_breakdown).reduce((a, b) => a + b, 0);

  const originRows: RelRow[] = origin_actors.map((a) => ({
    type: "threat_actor" as EntityType, label: a.name, meta: a.motivation || undefined,
    item: { id: a.id, country_relationship: "operates_from" } as EntitySearchResult,
  }));
  const targetingRows: RelRow[] = targeting_actors.map((a) => ({
    type: "threat_actor" as EntityType, label: a.name, meta: a.motivation || undefined,
    item: { id: a.id, country_relationship: "targets" } as EntitySearchResult,
  }));
  const relatedRows: RelRow[] = related_countries.map((c) => ({
    type: "country" as EntityType, label: c.name, meta: `${c.shared_entries} shared`,
    item: { id: c.id } as EntitySearchResult,
  }));

  const viewedLabel = entityLabel || "this country";
  const renderRows = (title: string, rows: RelRow[], emptyText: string) => (
    <div className={styles.section}>
      <div className={styles.sectionHeader}>
        {title} <span className={styles.sectionCount}>{rows.length}</span>
      </div>
      {rows.length === 0 ? (
        <div className={styles.emptySection}>{emptyText}</div>
      ) : (
        rows.map((row) => (
          <RelationshipRow
            key={`${row.type}-${row.item.id}`}
            row={row}
            viewedLabel={viewedLabel}
            onOpen={onOpenEntity}
          />
        ))
      )}
    </div>
  );

  return (
    <div className={styles.tabPanel}>
      {totalMentions > 0 && (
        <div className={styles.statGrid}>
          <span className={styles.statChip}>{totalMentions} total mentions</span>
          {Object.entries(role_breakdown).map(([role, count]) => (
            <span key={role} className={styles.statChip}>
              {count} {role}
            </span>
          ))}
        </div>
      )}

      <div className={styles.relGroups}>
        {renderRows("Threat Actors — Origin", originRows, "No attributed actors")}
        {renderRows("Threat Actors — Targeting", targetingRows, "No targeting actors")}
        {renderRows("Related Countries", relatedRows, "No related countries")}
      </div>

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
                  {c.role && <span className={styles.entityMeta}>{c.role}</span>}
                  {c.start_date && <span className={styles.entityMeta}>{formatDate(c.start_date)}</span>}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
