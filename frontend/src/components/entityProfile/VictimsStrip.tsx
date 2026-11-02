/**
 * VictimsStrip — recent leak-site victims for a ransomware actor, from the
 * ransomware tracker, inside the Overview's Recent victims section (whose row
 * carries the title and count). The facts strip counts them; this is the
 * victimology: who, in what sector, where, when. Renders nothing when the
 * tracker has no disclosures for this actor (or is disabled).
 */
import { useNavigate } from "react-router-dom";
import { useActorVictims } from "@/hooks/useEntityProfile";
import { useIntelStore } from "@/stores/intelStore";
import { formatDate } from "@/utils/formatDate";
import styles from "./entityProfile.module.css";

export function VictimsStrip({ entityId }: { entityId: string }) {
  const { data } = useActorVictims(entityId, true);
  const navigate = useNavigate();
  if (!data || data.items.length === 0) return null;

  return (
    <div className={styles.victimsStrip}>
      <div className={styles.victimsTable}>
        {data.items.map((v) => (
          <div key={v.id} className={styles.victimRow}>
            <span className={styles.victimName}>{v.name}</span>
            <span className={styles.victimSector}>{v.sector_label ?? v.sector ?? "—"}</span>
            <span className={`${styles.victimCountry} ${styles.mono}`} title={v.country_name ?? undefined}>
              {v.country_code ?? "—"}
            </span>
            <span className={styles.victimDate}>{v.last_seen_at ? formatDate(v.last_seen_at) : "—"}</span>
          </div>
        ))}
      </div>
      <button
        className={styles.victimsAll}
        onClick={() => {
          // The ransomware tracker is a workbench section, not a route.
          useIntelStore.getState().setActiveSection("ransomware");
          navigate("/workbench/explore");
        }}
      >
        all {data.total} victims →
      </button>
    </div>
  );
}
