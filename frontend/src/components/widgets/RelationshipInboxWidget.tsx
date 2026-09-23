import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import api from "@/api/client";
import { useRelationshipInbox } from "@/hooks/useWidgetBoardData";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { entityColorVar } from "./boardShared";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

export default function RelationshipInboxWidget({ config }: Props) {
  const limit = (config.limit as number) || 5;
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const { data, isLoading } = useRelationshipInbox({ date_from, date_to, limit });
  const [pending, setPending] = useState<Record<string, boolean>>({});
  const queryClient = useQueryClient();

  async function adjudicate(id: string, action: "confirm" | "reject") {
    setPending((p) => ({ ...p, [id]: true }));
    try {
      await api.post(`/entity-relationships/${id}/${action}`);
      toast.success(action === "confirm" ? "Relationship confirmed" : "Relationship rejected");
      await queryClient.invalidateQueries({ queryKey: ["widgets", "relationship-inbox"] });
    } catch {
      toast.error(`Could not ${action} relationship`);
      setPending((p) => ({ ...p, [id]: false }));
    }
  }

  if (isLoading) return <WidgetListSkeleton />;
  if (!data) return <div className={styles.noData}>No relationship data</div>;

  const { claimed, adjudicated, confirmed } = data.ladder;
  const max = Math.max(claimed, 1);

  return (
    <div>
      <div className={styles.ladderBar}>
        <div
          className={styles.ladderSeg}
          style={{ background: "var(--bg-tertiary)", flex: Math.max(1, (claimed / max) * 3) }}
        >
          <span className={styles.ladderSegValue}>{claimed.toLocaleString()}</span>
          claimed
        </div>
        <div
          className={styles.ladderSeg}
          style={{ background: "rgba(57,135,229,0.15)", flex: Math.max(1, (adjudicated / max) * 3) }}
        >
          <span className={styles.ladderSegValue}>{adjudicated.toLocaleString()}</span>
          adjudicated
        </div>
        <div
          className={styles.ladderSeg}
          style={{ background: "rgba(63,185,80,0.12)", flex: Math.max(1, (confirmed / max) * 3) }}
        >
          <span className={styles.ladderSegValue}>{confirmed.toLocaleString()}</span>
          confirmed
        </div>
      </div>

      {data.items.length === 0 ? (
        <div className={styles.noData}>No relationship claims awaiting review</div>
      ) : (
        <div className={styles.list}>
          {data.items.map((rel) => (
            <div key={rel.id} className={`${styles.boardRow} ${styles.boardRowStatic}`}>
              <div className={styles.boardGrow}>
                <div style={{ display: "flex", gap: 5, alignItems: "center", flexWrap: "wrap" }}>
                  <span className={styles.entityDot} style={{ background: entityColorVar(rel.source_type) }} />
                  <span style={{ fontSize: 13 }}>{rel.source_name}</span>
                  <span className={styles.boardMeta} style={{ display: "inline" }}>
                    —{rel.relationship_type}→
                  </span>
                  <span className={styles.entityDot} style={{ background: entityColorVar(rel.target_type) }} />
                  <span style={{ fontSize: 13 }}>{rel.target_name}</span>
                </div>
                <span className={styles.boardMeta}>
                  evidence: {rel.evidence_count} {rel.evidence_count === 1 ? "entry" : "entries"}
                </span>
              </div>
              <div className={styles.relActions}>
                <button
                  className={`${styles.relActionBtn} ${styles.relConfirm}`}
                  disabled={pending[rel.id]}
                  onClick={() => adjudicate(rel.id, "confirm")}
                  title="Confirm relationship"
                >
                  ✓
                </button>
                <button
                  className={`${styles.relActionBtn} ${styles.relReject}`}
                  disabled={pending[rel.id]}
                  onClick={() => adjudicate(rel.id, "reject")}
                  title="Reject relationship"
                >
                  ✕
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
