/**
 * Co-mentions and unmatched names — the two parts of the Relationships tab
 * that are not relationships: entities named in the same articles (no
 * relationship stated), and names a source gave that no entity matches.
 */
import { useMemo, useState } from "react";
import type { EntityType } from "@/stores/intelStore";
import type { RelationClaims } from "@/hooks/useRelationships";
import { getEntityColor, getEntityPluralLabel } from "@/utils/entityTheme";
import { rowKey, TYPE_ORDER, type RelRow } from "@/utils/relationshipBrowser";
import styles from "./relationships.module.css";

const CARD_PREVIEW = 5;

/** Articles naming both the profile and this entity. */
export const articleCount = (row: RelRow) => row.item.strength?.articles ?? row.item.co_occurrence_count ?? 0;

export function CoMentions({
  rows,
  reporting,
  onOpen,
}: {
  rows: RelRow[];
  /** Vendors and products named across most coverage. */
  reporting: RelRow[];
  onOpen: (type: EntityType, id: string, label: string) => void;
}) {
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [reportingOpen, setReportingOpen] = useState(false);

  const groups = useMemo(() => {
    const byType = new Map<EntityType, RelRow[]>();
    for (const r of rows) (byType.get(r.type) ?? byType.set(r.type, []).get(r.type)!).push(r);
    return TYPE_ORDER.filter((t) => byType.has(t)).map((t) => {
      const list = [...byType.get(t)!].sort((a, b) => articleCount(b) - articleCount(a));
      // Two entities with one name are almost always a duplicate to merge.
      const seen = new Map<string, number>();
      for (const r of list) seen.set(r.label.toLowerCase(), (seen.get(r.label.toLowerCase()) ?? 0) + 1);
      return { type: t, rows: list, dup: (r: RelRow) => (seen.get(r.label.toLowerCase()) ?? 0) > 1 };
    });
  }, [rows]);

  if (rows.length === 0 && reporting.length === 0) {
    return <div className={styles.empty}>No other entities are named in its articles.</div>;
  }

  return (
    <>
      <div className={styles.cards}>
        {groups.map((g) => {
          const isOpen = open.has(g.type);
          const shown = isOpen ? g.rows : g.rows.slice(0, CARD_PREVIEW);
          const max = Math.max(articleCount(g.rows[0]), 1);
          const color = getEntityColor(g.type);
          return (
            <div key={g.type} className={styles.card}>
              <div className={styles.cardHead}>
                <span className={styles.dot} style={{ background: color }} />
                {getEntityPluralLabel(g.type)}
                <span className={styles.count}>{g.rows.length}</span>
              </div>
              <div style={isOpen ? { maxHeight: 360, overflowY: "auto" } : undefined}>
                {shown.map((r) => {
                  const n = articleCount(r);
                  return (
                    <button
                      key={rowKey(r)}
                      className={styles.cardRow}
                      onClick={() => onOpen(r.type, r.item.id, r.label)}
                      title={`${r.label}: named in ${n} of the same article${n === 1 ? "" : "s"}`}
                    >
                      <span className={styles.cardMain}>
                        <span className={styles.cardLine}>
                          <span className={styles.cardName}>{r.label}</span>
                          {g.dup(r) && (
                            <span className={styles.dup} title="Another entity of this type has the same name">
                              duplicate name
                            </span>
                          )}
                        </span>
                        <span className={styles.bar}>
                          <i style={{ width: `${(n / max) * 100}%`, background: color }} />
                        </span>
                      </span>
                      <span className={styles.rowCount}>{n}</span>
                    </button>
                  );
                })}
              </div>
              {g.rows.length > CARD_PREVIEW && (
                <button
                  className={styles.linkBtn}
                  style={{ paddingLeft: 0 }}
                  onClick={() =>
                    setOpen((prev) => {
                      const next = new Set(prev);
                      if (next.has(g.type)) next.delete(g.type);
                      else next.add(g.type);
                      return next;
                    })
                  }
                >
                  {isOpen ? "Show fewer" : `Show all ${g.rows.length}`}
                </button>
              )}
            </div>
          );
        })}
      </div>
      {reporting.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <button className={styles.linkBtn} style={{ paddingLeft: 0 }} onClick={() => setReportingOpen((o) => !o)}>
            <span className="caret-glyph">{reportingOpen ? "▾" : "▸"}</span> {reporting.length} vendors and products
            named across most coverage
          </button>
          {reportingOpen && (
            <div className={styles.chips} style={{ marginTop: 6 }}>
              {reporting.map((r) => (
                <button
                  key={rowKey(r)}
                  className={`${styles.chip} ${styles.cardRow}`}
                  style={{ width: "auto" }}
                  onClick={() => onOpen(r.type, r.item.id, r.label)}
                >
                  {r.label}
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </>
  );
}

export function NotMatched({ held }: { held: RelationClaims["held"] }) {
  const bySource = new Map<string, typeof held>();
  for (const h of held) (bySource.get(h.source_label) ?? bySource.set(h.source_label, []).get(h.source_label)!).push(h);
  return (
    <>
      {[...bySource.entries()].map(([source, items]) => (
        <div key={source} style={{ marginBottom: 12 }}>
          <p className={styles.sectionNote}>
            {source} lists these, but no IntelFeed entity has the name
            {items.some((h) => h.held_reason === "ambiguous") ? " (or more than one does)" : ""}.
          </p>
          <div className={styles.chips}>
            {items.map((h) => (
              <span
                key={`${h.relation}-${h.target_name}`}
                className={styles.chip}
                title={`${h.relation.replace(/_/g, " ")}${h.target_type ? ` · ${h.target_type.replace(/_/g, " ")}` : ""} · ${
                  h.held_reason === "ambiguous" ? "matches more than one entity" : "no entity has this name yet"
                }`}
              >
                {h.target_name}
              </span>
            ))}
          </div>
        </div>
      ))}
    </>
  );
}
