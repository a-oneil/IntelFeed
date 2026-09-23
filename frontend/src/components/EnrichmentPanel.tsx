import { useState, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  useEnrichmentResults,
  useEnrichEntity,
  useEnrichmentSources,
} from "@/hooks/useEnrichment";
import styles from "./EnrichmentPanel.module.css";
import { AsyncStateLoading } from "@/components/AsyncState";

interface EnrichmentPanelProps {
  entityType: string;
  entityId: string;
  adapterEntityType?: string;
}

function formatAge(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const hours = Math.floor(diff / 3600000);
  if (hours < 1) return "just now";
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function statusColor(status: string): string {
  switch (status) {
    case "success":
      return "var(--success)";
    case "error":
      return "var(--danger)";
    case "rate_limited":
      return "var(--warning)";
    // No token maps to "budget exhausted" — a job status is not a severity, and
    // it must stay distinguishable from rate_limited, so this one keeps its
    // literal until the palette grows a second caution step.
    case "budget_exhausted":
      return "#ea580c";
    case "skipped_low_confidence":
      return "var(--text-muted)";
    case "not_found":
      return "var(--text-muted)";
    default:
      return "var(--text-muted)";
  }
}

function statusLabel(status: string): string {
  switch (status) {
    case "budget_exhausted":
      return "Budget exhausted";
    case "skipped_low_confidence":
      return "Skipped (low confidence)";
    case "rate_limited":
      return "Rate limited";
    case "not_found":
      return "Not found";
    case "error":
      return "Enrichment failed";
    default:
      return status;
  }
}

function isExpired(expiresAt: string): boolean {
  return new Date(expiresAt).getTime() < Date.now();
}

export function EnrichmentPanel({
  entityType,
  entityId,
  adapterEntityType,
}: EnrichmentPanelProps) {
  const navigate = useNavigate();
  const { data: results, isLoading } = useEnrichmentResults(
    entityType,
    entityId
  );
  const { data: sources } = useEnrichmentSources();
  const enrichEntity = useEnrichEntity();
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [showPicker, setShowPicker] = useState(false);
  const [selectedSources, setSelectedSources] = useState<Set<string>>(
    new Set()
  );
  const pickerRef = useRef<HTMLDivElement>(null);

  // Close picker on outside click
  useEffect(() => {
    if (!showPicker) return;
    const handler = (e: MouseEvent) => {
      if (pickerRef.current && !pickerRef.current.contains(e.target as Node)) {
        setShowPicker(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [showPicker]);

  // Filter sources to those supporting this entity type
  const matchType = adapterEntityType || entityType;
  const applicableSources =
    sources?.filter(
      (s) =>
        s.is_enabled &&
        s.supported_entity_types.some(
          (t) => t === matchType || t === entityType
        )
    ) ?? [];

  const handleEnrichAll = () => {
    enrichEntity.mutate({ entityType, entityId });
  };

  const handleEnrichSelected = () => {
    const sourceTypes = Array.from(selectedSources);
    if (sourceTypes.length === 0) return;
    enrichEntity.mutate({ entityType, entityId, sourceTypes });
    setShowPicker(false);
    setSelectedSources(new Set());
  };

  const handleRefreshSource = (sourceType: string) => {
    enrichEntity.mutate({
      entityType,
      entityId,
      sourceTypes: [sourceType],
    });
  };

  const toggleSource = (sourceType: string) => {
    setSelectedSources((prev) => {
      const next = new Set(prev);
      if (next.has(sourceType)) next.delete(sourceType);
      else next.add(sourceType);
      return next;
    });
  };

  const toggleExpand = (id: string) => {
    setExpanded((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  // Deduplicate: show only the latest result per source_type
  const latestBySource = new Map<
    string,
    (typeof results extends (infer T)[] | undefined ? T : never)
  >();
  if (results) {
    for (const r of results) {
      if (!latestBySource.has(r.source_type)) {
        latestBySource.set(r.source_type, r);
      }
    }
  }
  const dedupedResults = Array.from(latestBySource.values());

  return (
    <div className={styles.panel}>
      <div className={styles.panelHeader}>
        <span>Enrichment Data</span>
        <div className={styles.headerActions}>
          <button
            className={styles.configLink}
            onClick={() => navigate("/settings?section=engine&tab=pipeline&stage=enrich")}
            title="Configure enrichment sources"
          >
            Configure
          </button>
          <div className={styles.pickerWrapper} ref={pickerRef}>
            <button
              className={styles.enrichBtn}
              onClick={handleEnrichAll}
              disabled={enrichEntity.isPending}
            >
              {enrichEntity.isPending ? "Enriching..." : "Enrich All"}
            </button>
            <button
              className={styles.pickerToggle}
              onClick={() => setShowPicker(!showPicker)}
              title="Pick specific sources"
            >
              {"\u25BC"}
            </button>
            {showPicker && (
              <div className={styles.pickerDropdown}>
                <div className={styles.pickerTitle}>Select Sources</div>
                {applicableSources.length === 0 && (
                  <div className={styles.pickerEmpty}>
                    No enabled sources for this entity type
                  </div>
                )}
                {applicableSources.map((s) => (
                  <label key={s.id} className={styles.pickerItem}>
                    <input
                      type="checkbox"
                      checked={selectedSources.has(s.source_type)}
                      onChange={() => toggleSource(s.source_type)}
                    />
                    <span>{s.display_name}</span>
                    {s.requires_api_key && !s.has_api_key && (
                      <span className={styles.pickerNoKey}>No key</span>
                    )}
                  </label>
                ))}
                {applicableSources.length > 0 && (
                  <button
                    className={styles.pickerRun}
                    onClick={handleEnrichSelected}
                    disabled={
                      selectedSources.size === 0 || enrichEntity.isPending
                    }
                  >
                    Run Selected ({selectedSources.size})
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      <div className={styles.panelBody}>
        {isLoading && <AsyncStateLoading label="Loading enrichment results…" compact />}
        {!isLoading && dedupedResults.length === 0 && (
          <div className={styles.empty}>
            No enrichment data yet. Click Enrich All to look up this entity.
          </div>
        )}
        {dedupedResults.map((result) => (
          <div key={result.id} className={styles.resultCard}>
            {/* div, not button: the row hosts a real refresh <button>, and
                button-in-button is invalid DOM. */}
            <div
              className={styles.resultHeader}
              role="button"
              tabIndex={0}
              onClick={() => toggleExpand(result.id)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  toggleExpand(result.id);
                }
              }}
            >
              <div className={styles.resultInfo}>
                <span
                  className={styles.statusDot}
                  style={{ background: statusColor(result.status) }}
                />
                <span className={styles.resultSource}>
                  {result.source_type}
                </span>
                <span className={styles.resultAge}>
                  {formatAge(result.enriched_at)}
                  {isExpired(result.expires_at) && (
                    <span className={styles.stale}> (stale)</span>
                  )}
                </span>
              </div>
              <div className={styles.resultActions}>
                <button
                  className={styles.refreshBtn}
                  onClick={(e) => {
                    e.stopPropagation();
                    handleRefreshSource(result.source_type);
                  }}
                  disabled={enrichEntity.isPending}
                  title={`Re-enrich from ${result.source_type}`}
                >
                  {"\u21BB"}
                </button>
                <span className={styles.expandIcon}>
                  {expanded[result.id] ? "\u25B2" : "\u25BC"}
                </span>
              </div>
            </div>

            {expanded[result.id] && (
              <div className={styles.resultBody}>
                {result.status === "success" && result.parsed_data ? (
                  <dl className={styles.dataList}>
                    {Object.entries(result.parsed_data).map(([key, value]) => (
                      <div key={key} className={styles.dataRow}>
                        <dt className={styles.dataKey}>{key}</dt>
                        <dd className={styles.dataValue}>
                          {typeof value === "object" && value !== null
                            ? JSON.stringify(value, null, 2)
                            : String(value ?? "")}
                        </dd>
                      </div>
                    ))}
                  </dl>
                ) : (
                  <div className={styles.errorMsg}>
                    {statusLabel(result.status)}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
