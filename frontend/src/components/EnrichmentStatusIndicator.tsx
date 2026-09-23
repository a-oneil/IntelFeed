import { Tooltip } from "@/components/Tooltip";
import { useEnrichmentResults } from "@/hooks/useEnrichment";
import { formatDateTime } from "@/utils/formatDate";
import type { EnrichmentResult } from "@/api/types";
import styles from "./EnrichmentStatusIndicator.module.css";

export interface EnrichmentSourceStatus {
  name: string;
  status: "enriched" | "partial" | "pending" | "none";
  lastUpdated?: string;
}

interface Props {
  sources?: EnrichmentSourceStatus[];
  entityType?: string;
  entityId?: string;
}

const STATUS_CLASS: Record<EnrichmentSourceStatus["status"], string> = {
  enriched: styles.dotEnriched,
  partial: styles.dotPartial,
  pending: styles.dotPending,
  none: styles.dotNone,
};

const STATUS_LABEL: Record<EnrichmentSourceStatus["status"], string> = {
  enriched: "Enriched",
  partial: "Partial",
  pending: "Pending",
  none: "Not enriched",
};

function formatLastUpdated(iso: string | undefined): string {
  if (!iso) return "Never";
  return formatDateTime(iso);
}

function deriveStatus(result: EnrichmentResult): EnrichmentSourceStatus["status"] {
  if (result.status === "success") {
    return new Date(result.expires_at).getTime() > Date.now() ? "enriched" : "partial";
  }
  if (result.status === "rate_limited") return "pending";
  return "none";
}

function resultsToSources(results: EnrichmentResult[]): EnrichmentSourceStatus[] {
  const bySource = new Map<string, EnrichmentResult>();
  for (const r of results) {
    if (!bySource.has(r.source_type)) {
      bySource.set(r.source_type, r);
    }
  }
  return Array.from(bySource.values()).map((r) => ({
    name: r.source_type,
    status: deriveStatus(r),
    lastUpdated: r.enriched_at,
  }));
}

export function EnrichmentStatusIndicator({ sources, entityType, entityId }: Props) {
  const { data: results } = useEnrichmentResults(
    sources ? undefined : entityType,
    sources ? undefined : entityId,
  );

  const displaySources = sources ?? (results ? resultsToSources(results) : []);

  if (displaySources.length === 0) return null;

  return (
    <div className={styles.container}>
      {displaySources.map((src) => (
        <Tooltip
          key={src.name}
          position="bottom"
          content={
            <span>
              <strong>{src.name}</strong>
              <br />
              Status: {STATUS_LABEL[src.status]}
              <br />
              Last updated: {formatLastUpdated(src.lastUpdated)}
            </span>
          }
        >
          <span className={styles.source}>
            <span className={`${styles.dot} ${STATUS_CLASS[src.status]}`} />
            <span className={styles.label}>{src.name}</span>
          </span>
        </Tooltip>
      ))}
    </div>
  );
}
