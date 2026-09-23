/**
 * EnrichmentSection — the enrichment controls as the footer of the Overview
 * rail's Sources card, where the rest of "where these facts came from" lives.
 * Collapsed it is one line: per-source status dots plus a run/expand toggle;
 * expanded it is the full per-source panel (status, ages, re-run). Renders even
 * with zero results so enrichment can be run the first time from here.
 */
import { useState } from "react";
import { EnrichmentPanel } from "@/components/EnrichmentPanel";
import { EnrichmentStatusIndicator } from "@/components/EnrichmentStatusIndicator";
import { useEnrichmentSources } from "@/hooks/useEnrichment";
import { Hint } from "@/components/primitives";
import type { EntityType } from "@/stores/intelStore";
import styles from "./entityProfile.module.css";

/**
 * Nothing enriches a campaign: it is an internal object, and every source
 * declares the entity types it serves. Asking the registry rather than naming
 * the type keeps this right if a campaign source is ever added.
 */
export function useEnrichmentSupported(entityType: EntityType): boolean {
  const { data: sources } = useEnrichmentSources();
  // Unknown while sources load — treat as supported so the row doesn't flash out.
  if (!sources) return true;
  return sources.some((s) => s.supported_entity_types?.includes(entityType));
}

export function EnrichmentSection({ entityType, entityId }: { entityType: EntityType; entityId: string }) {
  const [open, setOpen] = useState(false);
  const supported = useEnrichmentSupported(entityType);
  if (!supported) return null;

  return (
    <div className={styles.enrichSection}>
      <div className={styles.enrichRow}>
        <Hint
          title="Enrichment"
          body="Outside lookups that fill a dossier in — MITRE, NVD, leak-site trackers."
          aside="Each source is rate-limited on its own and can be re-run by hand."
        >
          <button
            className={styles.enrichBtn}
            onClick={() => setOpen((o) => !o)}
            aria-expanded={open}
          >
            <span className={styles.enrichBtnLabel}>Enrichment <span className="caret-glyph">{open ? "▴" : "▾"}</span></span>
          </button>
        </Hint>
        {/* The status dots sit beside the toggle, not inside it — the indicator
            renders tooltip divs that don't belong in a button. */}
        <EnrichmentStatusIndicator entityType={entityType} entityId={entityId} />
      </div>
      {open && (
        <div className={styles.enrichInline}>
          <EnrichmentPanel entityType={entityType} entityId={entityId} />
        </div>
      )}
    </div>
  );
}
