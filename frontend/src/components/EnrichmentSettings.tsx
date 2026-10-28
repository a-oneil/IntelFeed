import { useState } from "react";
import {
  useEnrichmentSources,
  useUpdateEnrichmentSource,
  useTestEnrichmentSource,
  useEnrichmentStatus,
  useEnrichmentBudgetSummary,
  useUserEnrichmentOverrides,
  useUpsertUserOverride,
  useDeleteUserOverride,
} from "@/hooks/useEnrichment";
import type { EnrichmentSource, UserEnrichmentOverride } from "@/api/types";
import { formatDate } from "@/utils/formatDate";
import { Chip } from "@/components/primitives/Chip";
import styles from "./EnrichmentSettings.module.css";
import { AsyncStateLoading } from "@/components/AsyncState";

const CONFIDENCE_LABELS: Record<string, string> = {
  high: "High only",
  medium: "Medium+",
  low: "All",
};

function healthColor(h: string) {
  switch (h) {
    case "healthy":
      return "var(--success, #16a34a)";
    case "degraded":
      return "#ca8a04";
    case "down":
      return "var(--error, #ef4444)";
    default:
      return "var(--text-muted)";
  }
}

function BudgetBar({ used, total }: { used: number; total: number }) {
  const pct = Math.min(100, Math.round((used / total) * 100));
  const color =
    pct >= 90
      ? "var(--error, #ef4444)"
      : pct >= 70
        ? "#ca8a04"
        : "var(--accent)";

  return (
    <div className={styles.budgetBar}>
      <div
        className={styles.budgetBarFill}
        style={{ width: `${pct}%`, background: color }}
      />
      <span className={styles.budgetBarLabel}>
        {used}/{total}
      </span>
    </div>
  );
}

function SourceRow({
  source,
  isExpanded,
  onToggleExpand,
  testResult,
  userOverride,
}: {
  source: EnrichmentSource;
  isExpanded: boolean;
  onToggleExpand: () => void;
  testResult?: string;
  userOverride?: UserEnrichmentOverride;
}) {
  const updateSource = useUpdateEnrichmentSource();
  const testSource = useTestEnrichmentSource();
  const upsertOverride = useUpsertUserOverride();
  const deleteOverride = useDeleteUserOverride();
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [editingKey, setEditingKey] = useState(false);
  const [editingUserKey, setEditingUserKey] = useState(false);
  const [userKeyInput, setUserKeyInput] = useState("");
  const [budgetInput, setBudgetInput] = useState(
    source.daily_budget?.toString() ?? ""
  );
  const [localTestResult, setLocalTestResult] = useState(testResult);

  const handleToggle = () => {
    updateSource.mutate({
      sourceId: source.id,
      is_enabled: !source.is_enabled,
    });
  };

  const handleTriggerMode = (mode: string) => {
    updateSource.mutate({ sourceId: source.id, trigger_mode: mode });
  };

  const handleConfidence = (threshold: string) => {
    updateSource.mutate({
      sourceId: source.id,
      min_confidence_threshold: threshold,
    });
  };

  const handleSaveBudget = () => {
    const val = budgetInput.trim();
    if (val === "" || val === "0") {
      updateSource.mutate({
        sourceId: source.id,
        clear_daily_budget: true,
      });
    } else {
      const num = parseInt(val, 10);
      if (!isNaN(num) && num > 0) {
        updateSource.mutate({ sourceId: source.id, daily_budget: num });
      }
    }
  };

  const handleSaveApiKey = () => {
    updateSource.mutate(
      { sourceId: source.id, api_key: apiKeyInput },
      {
        onSuccess: () => {
          setEditingKey(false);
          setApiKeyInput("");
        },
      }
    );
  };

  const handleTest = async () => {
    try {
      const result = await testSource.mutateAsync(source.id);
      setLocalTestResult(result.health_status);
    } catch {
      setLocalTestResult("error");
    }
  };

  const displayHealth = localTestResult || testResult || source.health_status;

  return (
    <div
      className={`${styles.sourceCard} ${!source.is_enabled ? styles.sourceDisabled : ""}`}
    >
      <div className={styles.sourceRow} onClick={onToggleExpand}>
        <label
          className={styles.toggle}
          onClick={(e) => e.stopPropagation()}
        >
          <input
            type="checkbox"
            checked={source.is_enabled}
            onChange={handleToggle}
          />
        </label>
        <span
          className={styles.healthDot}
          style={{ background: healthColor(displayHealth) }}
          title={displayHealth}
        />
        <span className={styles.sourceName}>{source.display_name}</span>

        <div className={styles.rowMeta}>
          <Chip pill truncate className={styles.rowBadge}>
            {source.trigger_mode}
          </Chip>

          {source.daily_budget != null && (
            <Chip pill className={`${styles.rowBadge} ${styles.budgetBadge}`}>
              {source.daily_budget_used}/{source.daily_budget}
            </Chip>
          )}

          <Chip pill truncate className={styles.rowBadge}>
            {CONFIDENCE_LABELS[source.min_confidence_threshold] ?? "All"}
          </Chip>

          {source.requires_api_key && (
            <Chip tone="quiet" pill>
              {source.has_api_key ? "Key set" : "No key"}
            </Chip>
          )}
        </div>

        <span className={styles.expandIcon}>{isExpanded ? "\u25BC" : "\u25B6"}</span>
      </div>

      {isExpanded && (
        <div className={styles.expandedDetail}>
          <div className={styles.detailGrid}>
            {/* Trigger Mode */}
            <div className={styles.detailField}>
              <label className={styles.detailLabel}>Trigger Mode</label>
              <select
                value={source.trigger_mode}
                onChange={(e) => handleTriggerMode(e.target.value)}
                className={styles.modeSelect}
              >
                <option value="auto">Auto</option>
                <option value="manual">Manual</option>
              </select>
            </div>

            {/* Confidence Threshold */}
            <div className={styles.detailField}>
              <label className={styles.detailLabel}>Min Confidence</label>
              <select
                value={source.min_confidence_threshold}
                onChange={(e) => handleConfidence(e.target.value)}
                className={styles.modeSelect}
              >
                <option value="low">All (Low+)</option>
                <option value="medium">Medium+</option>
                <option value="high">High only</option>
              </select>
              <span className={styles.detailHint}>
                Skip auto-enrichment for entities below this confidence
              </span>
            </div>

            {/* Daily Budget */}
            <div className={styles.detailField}>
              <label className={styles.detailLabel}>Daily Budget</label>
              <div className={styles.budgetInputRow}>
                <input
                  type="number"
                  min="0"
                  placeholder="Unlimited"
                  value={budgetInput}
                  onChange={(e) => setBudgetInput(e.target.value)}
                  className={styles.keyInput}
                />
                <button
                  className={styles.saveBtn}
                  onClick={handleSaveBudget}
                  disabled={updateSource.isPending}
                >
                  Save
                </button>
              </div>
              <span className={styles.detailHint}>
                {source.daily_budget != null
                  ? `${source.daily_budget_used} used today`
                  : "No limit set (unlimited)"}
              </span>
            </div>

            {/* API Key (Global / Admin) */}
            <div className={styles.detailField}>
              <label className={styles.detailLabel}>Global API Key</label>
              {editingKey ? (
                <div className={styles.keyForm}>
                  <input
                    type="password"
                    placeholder="Paste API key"
                    value={apiKeyInput}
                    onChange={(e) => setApiKeyInput(e.target.value)}
                    className={styles.keyInput}
                  />
                  <button
                    className={styles.saveBtn}
                    onClick={handleSaveApiKey}
                    disabled={!apiKeyInput || updateSource.isPending}
                  >
                    Save
                  </button>
                  <button
                    className={styles.cancelBtn}
                    onClick={() => {
                      setEditingKey(false);
                      setApiKeyInput("");
                    }}
                  >
                    Cancel
                  </button>
                </div>
              ) : (
                <div className={styles.keyRow}>
                  <span className={styles.keyStatus}>
                    {source.has_api_key ? "Key configured" : "Not set"}
                  </span>
                  <button
                    className={styles.editKeyBtn}
                    onClick={() => setEditingKey(true)}
                  >
                    {source.has_api_key ? "Change" : "Set Key"}
                  </button>
                </div>
              )}
              {source.shared_key_group && (
                <span className={styles.detailHint}>
                  Shared key group: {source.shared_key_group}
                </span>
              )}
            </div>

            {/* Personal API Key Override */}
            {source.requires_api_key && (
              <div className={styles.detailField}>
                <label className={styles.detailLabel}>My API Key</label>
                {editingUserKey ? (
                  <div className={styles.keyForm}>
                    <input
                      type="password"
                      placeholder="Your personal API key"
                      value={userKeyInput}
                      onChange={(e) => setUserKeyInput(e.target.value)}
                      className={styles.keyInput}
                    />
                    <button
                      className={styles.saveBtn}
                      onClick={() => {
                        upsertOverride.mutate(
                          { sourceId: source.id, api_key: userKeyInput },
                          {
                            onSuccess: () => {
                              setEditingUserKey(false);
                              setUserKeyInput("");
                            },
                          }
                        );
                      }}
                      disabled={!userKeyInput || upsertOverride.isPending}
                    >
                      Save
                    </button>
                    <button
                      className={styles.cancelBtn}
                      onClick={() => {
                        setEditingUserKey(false);
                        setUserKeyInput("");
                      }}
                    >
                      Cancel
                    </button>
                  </div>
                ) : (
                  <div className={styles.keyRow}>
                    <span className={styles.keyStatus}>
                      {userOverride?.has_api_key
                        ? "Your key set"
                        : "Using global key"}
                    </span>
                    <button
                      className={styles.editKeyBtn}
                      onClick={() => setEditingUserKey(true)}
                    >
                      {userOverride?.has_api_key ? "Change" : "Set My Key"}
                    </button>
                    {userOverride?.has_api_key && (
                      <button
                        className={styles.cancelBtn}
                        onClick={() => deleteOverride.mutate(source.id)}
                        disabled={deleteOverride.isPending}
                      >
                        Remove
                      </button>
                    )}
                  </div>
                )}
                <span className={styles.detailHint}>
                  Override the global key with your own personal API key
                </span>
              </div>
            )}
          </div>

          {/* Footer: meta info + test */}
          <div className={styles.detailFooter}>
            <Chip truncate className={styles.sourceType}>
              {source.source_type}
            </Chip>
            {source.last_synced_at && (
              <span className={styles.lastSync}>
                Last sync: {formatDate(source.last_synced_at)}
              </span>
            )}
            {source.supported_entity_types.length > 0 && (
              <span className={styles.entityTypes}>
                {source.supported_entity_types.join(", ")}
              </span>
            )}
            <button
              className={styles.testBtn}
              onClick={handleTest}
              disabled={testSource.isPending}
            >
              {testSource.isPending ? "Testing..." : "Test Connection"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function EnrichmentSettings() {
  const { data: sources, isLoading } = useEnrichmentSources();
  const { data: status } = useEnrichmentStatus();
  const { data: budgetSummary } = useEnrichmentBudgetSummary();
  const { data: userOverrides } = useUserEnrichmentOverrides();
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [testResults] = useState<Record<string, string>>({});

  // Build override lookup by source_id
  const overrideMap = new Map<string, UserEnrichmentOverride>();
  for (const o of userOverrides ?? []) {
    overrideMap.set(o.source_id, o);
  }

  if (isLoading)
    return (
      <AsyncStateLoading label="Loading enrichment sources…" />
    );

  // Group sources: free (no key required) vs API key sources
  const freeSources =
    sources?.filter((s) => !s.requires_api_key) ?? [];
  const paidSources =
    sources?.filter((s) => s.requires_api_key) ?? [];

  return (
    <div className={styles.container}>
      <h2 className={styles.title}>Enrichment Sources</h2>

      {/* Status bar */}
      {status && (
        <div className={styles.statusBar}>
          <span>
            {status.enabled_sources}/{status.total_sources} enabled
          </span>
          <span>{status.healthy_sources} healthy</span>
          <span>{status.enrichments_today} enrichments today</span>
        </div>
      )}

      {/* Budget overview */}
      {budgetSummary && budgetSummary.length > 0 && (
        <div className={styles.budgetOverview}>
          <h3 className={styles.sectionSubtitle}>Daily Budget Usage</h3>
          <div className={styles.budgetGrid}>
            {budgetSummary.map((b) => (
              <div key={b.source_type} className={styles.budgetItem}>
                <span className={styles.budgetName}>{b.display_name}</span>
                <BudgetBar used={b.used_today} total={b.daily_budget} />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Free sources */}
      {freeSources.length > 0 && (
        <div className={styles.sourceGroup}>
          <h3 className={styles.sectionSubtitle}>
            Free Sources
            <span className={styles.groupCount}>({freeSources.length})</span>
          </h3>
          <div className={styles.sourceList}>
            {freeSources.map((source) => (
              <SourceRow
                key={source.id}
                source={source}
                isExpanded={expandedId === source.id}
                onToggleExpand={() =>
                  setExpandedId(expandedId === source.id ? null : source.id)
                }
                testResult={testResults[source.id]}
                userOverride={overrideMap.get(source.id)}
              />
            ))}
          </div>
        </div>
      )}

      {/* Paid / API key sources */}
      {paidSources.length > 0 && (
        <div className={styles.sourceGroup}>
          <h3 className={styles.sectionSubtitle}>
            API Key Sources
            <span className={styles.groupCount}>({paidSources.length})</span>
          </h3>
          <div className={styles.sourceList}>
            {paidSources.map((source) => (
              <SourceRow
                key={source.id}
                source={source}
                isExpanded={expandedId === source.id}
                onToggleExpand={() =>
                  setExpandedId(expandedId === source.id ? null : source.id)
                }
                testResult={testResults[source.id]}
                userOverride={overrideMap.get(source.id)}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
