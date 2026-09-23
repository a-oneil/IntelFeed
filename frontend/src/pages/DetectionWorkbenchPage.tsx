import { useState, useCallback, useEffect } from "react";
import type {
  DetectionSummaryRequest,
  DetectionSummaryResponse,
  AttackChainStep,
  DetectionIndicator,
  GeneratedRule,
} from "@/api/types";
import { Panel } from "@/components/primitives";
import { useDetectionSummary, useEntitySearch } from "@/hooks/useCorrelation";
import { useUIStore } from "@/stores/uiStore";
import { formatDate } from "@/utils/formatDate";
import styles from "./DetectionWorkbenchPage.module.css";

const RULE_FORMAT_OPTIONS = [
  { value: "sigma", label: "SIGMA" },
  { value: "splunk_spl", label: "Splunk SPL" },
  { value: "crowdstrike_ql", label: "CrowdStrike QL" },
  { value: "elastic_ql", label: "Elastic QL" },
  { value: "kql", label: "KQL" },
  { value: "snort_suricata", label: "Snort/Suricata" },
  { value: "yara", label: "YARA" },
] as const;

const FOCUS_OPTIONS = [
  { value: "", label: "Auto-detect" },
  { value: "campaign", label: "Campaign" },
  { value: "vulnerability", label: "Vulnerability" },
  { value: "malware", label: "Malware" },
  { value: "actor", label: "Threat Actor" },
] as const;

type IndicatorTab = "network" | "host" | "behavioral";

function getFeasibilityClass(feasibility: "high" | "medium" | "low"): string {
  switch (feasibility) {
    case "high":
      return styles.feasibilityHigh;
    case "medium":
      return styles.feasibilityMedium;
    case "low":
      return styles.feasibilityLow;
  }
}

function getFeasibilityLabel(feasibility: "high" | "medium" | "low"): string {
  switch (feasibility) {
    case "high":
      return "High Feasibility";
    case "medium":
      return "Medium Feasibility";
    case "low":
      return "Low Feasibility";
  }
}

function copyToClipboard(text: string): Promise<void> {
  return navigator.clipboard.writeText(text);
}

function downloadTextFile(filename: string, content: string, mimeType: string = "text/plain") {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export function DetectionWorkbenchPage() {
  const [entrySearch, setEntrySearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [selectedEntries, setSelectedEntries] = useState<Array<{ id: string; title: string }>>([]);
  const [showSearchResults, setShowSearchResults] = useState(false);
  const [ruleFormats, setRuleFormats] = useState<string[]>(["sigma"]);
  const [focus, setFocus] = useState("");
  const [activeIndicatorTab, setActiveIndicatorTab] = useState<IndicatorTab>("network");
  const [copiedRuleIndex, setCopiedRuleIndex] = useState<number | null>(null);
  const openCopilotWith = useUIStore((s) => s.openCopilotWith);

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(entrySearch.trim()), 300);
    return () => clearTimeout(timer);
  }, [entrySearch]);

  const { data: searchData } = useEntitySearch(debouncedSearch);
  const entryResults = (searchData?.results ?? []).filter((r) => r.type === "entry");

  const detectionSummary = useDetectionSummary();
  const result = detectionSummary.data as DetectionSummaryResponse | undefined;

  const parseEntryIds = useCallback((): string[] => {
    return selectedEntries.map((e) => e.id);
  }, [selectedEntries]);

  const handleAddEntry = (id: string, title: string) => {
    if (!selectedEntries.some((e) => e.id === id)) {
      setSelectedEntries((prev) => [...prev, { id, title }]);
    }
    setEntrySearch("");
    setShowSearchResults(false);
  };

  const handleRemoveEntry = (id: string) => {
    setSelectedEntries((prev) => prev.filter((e) => e.id !== id));
  };

  const handleGenerate = () => {
    const entryIds = parseEntryIds();
    if (entryIds.length === 0) return;

    const request: DetectionSummaryRequest = {
      entry_ids: entryIds,
      include_existing_intelligence: true,
      rule_formats: ruleFormats.length > 0 ? ruleFormats : undefined,
      focus: focus ? (focus as DetectionSummaryRequest["focus"]) : undefined,
    };

    detectionSummary.mutate(request);
  };

  const handleToggleRuleFormat = (format: string) => {
    setRuleFormats((prev) =>
      prev.includes(format) ? prev.filter((f) => f !== format) : [...prev, format]
    );
  };

  const [savedRuleIndices, setSavedRuleIndices] = useState<Set<number>>(new Set());

  const handleCopyRule = async (content: string, index: number) => {
    await copyToClipboard(content);
    setCopiedRuleIndex(index);
    setTimeout(() => setCopiedRuleIndex(null), 2000);
  };

  const handleSaveRule = async (rule: GeneratedRule, index: number) => {
    try {
      const { default: api } = await import("@/api/client");
      await api.post("/detection-rules", {
        rule_type: rule.rule_type,
        title: rule.title,
        rule_content: rule.content,
        severity: rule.severity || null,
        entry_id: selectedEntries.length === 1 ? selectedEntries[0].id : null,
      });
      setSavedRuleIndices((prev) => new Set(prev).add(index));
    } catch {
      // silently fail for now
    }
  };

  const handleExportRules = () => {
    if (!result || result.generated_rules.length === 0) return;

    const lines: string[] = [];
    for (const rule of result.generated_rules) {
      lines.push(`# ${rule.title}`);
      lines.push(`# Type: ${rule.rule_type}${rule.severity ? ` | Severity: ${rule.severity}` : ""}`);
      lines.push("");
      lines.push(rule.content);
      lines.push("");
      lines.push("---");
      lines.push("");
    }

    downloadTextFile("detection-rules.txt", lines.join("\n"));
  };

  const handleExportSummary = () => {
    if (!result) return;

    const lines: string[] = [];

    lines.push("# Detection Engineering Summary");
    lines.push("");
    lines.push("## Executive Summary");
    lines.push("");
    lines.push(result.executive_summary);
    lines.push("");

    if (result.attack_chain.length > 0) {
      lines.push("## Attack Chain");
      lines.push("");
      for (const step of result.attack_chain) {
        lines.push(`### Step ${step.step}: ${step.phase} - ${step.technique}`);
        lines.push("");
        lines.push(step.description);
        lines.push("");
        lines.push(`**Detection Opportunity:** ${step.detection_opportunity}`);
        lines.push("");
        lines.push(`**Feasibility:** ${step.detection_feasibility}`);
        if (step.log_sources.length > 0) {
          lines.push(`**Log Sources:** ${step.log_sources.join(", ")}`);
        }
        lines.push("");
      }
    }

    if (result.indicators) {
      lines.push("## Indicators");
      lines.push("");
      for (const category of ["network", "host", "behavioral"] as const) {
        const indicators = result.indicators[category];
        if (indicators && indicators.length > 0) {
          lines.push(`### ${category.charAt(0).toUpperCase() + category.slice(1)}`);
          lines.push("");
          for (const ind of indicators) {
            lines.push(`- **${ind.type}**${ind.value ? `: \`${ind.value}\`` : ""}`);
            if (ind.context) lines.push(`  - Context: ${ind.context}`);
            if (ind.detection_note) lines.push(`  - Detection: ${ind.detection_note}`);
          }
          lines.push("");
        }
      }
    }

    if (result.generated_rules.length > 0) {
      lines.push("## Generated Rules");
      lines.push("");
      for (const rule of result.generated_rules) {
        lines.push(`### ${rule.title} (${rule.rule_type})`);
        if (rule.severity) lines.push(`Severity: ${rule.severity}`);
        lines.push("");
        lines.push("```");
        lines.push(rule.content);
        lines.push("```");
        lines.push("");
      }
    }

    if (result.gaps_and_recommendations.length > 0) {
      lines.push("## Gaps & Recommendations");
      lines.push("");
      for (const gap of result.gaps_and_recommendations) {
        lines.push(`- ${gap}`);
      }
      lines.push("");
    }

    downloadTextFile("detection-summary.md", lines.join("\n"), "text/markdown");
  };

  const handleExportNavigator = () => {
    if (!result || result.attack_chain.length === 0) return;
    const techniques = result.attack_chain.map((step) => ({
      techniqueID: step.technique,
      tactic: step.phase.replace(/\s+/g, "-").toLowerCase(),
      color: step.detection_feasibility === "high" ? "#ff6666" : step.detection_feasibility === "medium" ? "#ffcc66" : "#ffff99",
      comment: step.description,
      score: step.detection_feasibility === "high" ? 100 : step.detection_feasibility === "medium" ? 75 : 50,
      enabled: true,
    }));
    const layer = {
      name: "Detection Workbench Analysis",
      versions: { attack: "14", navigator: "4.9.1", layer: "4.5" },
      domain: "enterprise-attack",
      techniques,
      gradient: { colors: ["#ffffff", "#ffcc66", "#ff6666"], minValue: 0, maxValue: 100 },
    };
    downloadTextFile("navigator-layer.json", JSON.stringify(layer, null, 2), "application/json");
  };

  const getIndicatorCount = (tab: IndicatorTab): number => {
    if (!result || !result.indicators) return 0;
    return result.indicators[tab]?.length ?? 0;
  };

  const currentIndicators: DetectionIndicator[] =
    result?.indicators?.[activeIndicatorTab] ?? [];

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h1>Detection Engineering Workbench</h1>
        <p className={styles.headerSubtitle}>
          Analyze entries to generate attack chains, indicators, and detection rules
        </p>
      </div>

      <div className={styles.configSection}>
        <h2>Configuration</h2>

        <div className={styles.field}>
          <label htmlFor="entry-search">Select Entries</label>
          <div className={styles.entrySearchWrapper}>
            <input
              id="entry-search"
              type="text"
              className={styles.input}
              value={entrySearch}
              onChange={(e) => {
                setEntrySearch(e.target.value);
                setShowSearchResults(true);
              }}
              onFocus={() => { if (entrySearch.trim()) setShowSearchResults(true); }}
              placeholder="Search entries by title..."
            />
            {showSearchResults && debouncedSearch && entryResults.length > 0 && (
              <div className={styles.searchDropdown}>
                {entryResults.slice(0, 10).map((entry) => (
                  <div
                    key={entry.id}
                    className={styles.searchDropdownItem}
                    onClick={() => handleAddEntry(entry.id, entry.title ?? entry.id)}
                  >
                    <span className={styles.searchDropdownTitle}>
                      {entry.title ?? entry.id}
                    </span>
                    {entry.published_at && (
                      <span className={styles.searchDropdownDate}>
                        {formatDate(entry.published_at)}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
          {selectedEntries.length > 0 && (
            <div className={styles.selectedEntries}>
              {selectedEntries.map((entry) => (
                <div key={entry.id} className={styles.selectedEntry}>
                  <span className={styles.selectedEntryTitle}>{entry.title}</span>
                  <button
                    className={styles.removeEntryBtn}
                    onClick={() => handleRemoveEntry(entry.id)}
                    title="Remove entry"
                  >
                    &times;
                  </button>
                </div>
              ))}
            </div>
          )}
          <p className={styles.inputHint}>
            Search and select entries to analyze
          </p>
        </div>

        <div className={styles.field}>
          <label>Rule Formats</label>
          <div className={styles.checkboxGroup}>
            {RULE_FORMAT_OPTIONS.map((opt) => (
              <label
                key={opt.value}
                className={`${styles.checkboxLabel} ${ruleFormats.includes(opt.value) ? styles.checkboxLabelChecked : ""}`}
              >
                <input
                  type="checkbox"
                  checked={ruleFormats.includes(opt.value)}
                  onChange={() => handleToggleRuleFormat(opt.value)}
                />
                {opt.label}
              </label>
            ))}
          </div>
        </div>

        <div className={styles.field}>
          <label htmlFor="focus-select">Analysis Focus</label>
          <select
            id="focus-select"
            className={styles.select}
            value={focus}
            onChange={(e) => setFocus(e.target.value)}
          >
            {FOCUS_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>

        <div className={styles.configActions}>
          <button
            className={styles.btn}
            onClick={handleGenerate}
            disabled={parseEntryIds().length === 0 || detectionSummary.isPending}
          >
            {detectionSummary.isPending ? "Analyzing..." : "Generate Analysis"}
          </button>
          {parseEntryIds().length > 0 && (
            <>
              <span className={styles.inputHint}>
                {parseEntryIds().length} {parseEntryIds().length === 1 ? "entry" : "entries"} selected
              </span>
              <button
                className={styles.btnSecondary}
                onClick={() =>
                  openCopilotWith({
                    context: {
                      entry_ids: parseEntryIds(),
                      label: `${parseEntryIds().length} selected articles`,
                    },
                    lockContext: true,
                  })
                }
                title="Discuss these entries with the copilot"
              >
                Ask Copilot
              </button>
            </>
          )}
        </div>
      </div>

      {detectionSummary.isPending && (
        <div className={styles.loadingContainer}>
          <div className={styles.spinner} />
          <span className={styles.loadingText}>
            AI is analyzing entries and generating detection content...
          </span>
        </div>
      )}

      {detectionSummary.isError && (
        <div className={styles.errorBanner}>
          Failed to generate detection summary:{" "}
          {detectionSummary.error instanceof Error
            ? detectionSummary.error.message
            : "Unknown error occurred"}
        </div>
      )}

      {result && !detectionSummary.isPending && (
        <div className={styles.results}>
          <ExecutiveSummarySection summary={result.executive_summary} />

          <AttackChainSection steps={result.attack_chain} />

          <IndicatorsSection
            indicators={result.indicators}
            activeTab={activeIndicatorTab}
            onTabChange={setActiveIndicatorTab}
            currentIndicators={currentIndicators}
            getCount={getIndicatorCount}
          />

          <GeneratedRulesSection
            rules={result.generated_rules}
            copiedIndex={copiedRuleIndex}
            savedIndices={savedRuleIndices}
            onCopy={handleCopyRule}
            onSave={handleSaveRule}
          />

          <RelatedIntelligenceSection intelligence={result.related_intelligence} />

          <GapsSection gaps={result.gaps_and_recommendations} />

          <div className={styles.exportFooter}>
            <button
              className={styles.btn}
              onClick={handleExportRules}
              disabled={result.generated_rules.length === 0}
            >
              Export Rules
            </button>
            <button className={styles.btnSecondary} onClick={handleExportSummary}>
              Export Summary
            </button>
            <button
              className={styles.btnSecondary}
              onClick={handleExportNavigator}
              disabled={result.attack_chain.length === 0}
            >
              Export Navigator
            </button>
          </div>
        </div>
      )}

      {!result && !detectionSummary.isPending && !detectionSummary.isError && (
        <div className={styles.emptyResults}>
          <div className={styles.emptyIcon}>&#x1F6E1;</div>
          <p>
            Search and select entries above, configure rule formats, then click
            "Generate Analysis" to begin.
          </p>
        </div>
      )}
    </div>
  );
}

function ExecutiveSummarySection({ summary }: { summary: string }) {
  return (
    <Panel
      className={styles.sectionPanel}
      padding="lg"
      titleVariant="heading"
      title={
        <>
          <span className={styles.sectionIcon}>&#x1F4CB;</span>
          Executive Summary
        </>
      }
    >
      <p className={styles.summaryText}>{summary}</p>
    </Panel>
  );
}

function AttackChainSection({ steps }: { steps: AttackChainStep[] }) {
  if (steps.length === 0) return null;

  return (
    <Panel
      className={styles.sectionPanel}
      padding="lg"
      titleVariant="heading"
      title={
        <>
          <span className={styles.sectionIcon}>&#x26D3;</span>
          Attack Chain
        </>
      }
    >
      <div className={styles.attackChain}>
        {steps.map((step) => (
          <div key={step.step} className={styles.attackStep}>
            <div className={styles.stepConnector}>{step.step}</div>
            <div className={styles.stepHeader}>
              <span className={styles.stepPhase}>{step.phase}</span>
              <span className={styles.stepTechnique}>{step.technique}</span>
            </div>
            <p className={styles.stepDescription}>{step.description}</p>
            <div className={styles.stepDetection}>
              <span className={styles.stepDetectionLabel}>Detection Opportunity</span>
              {step.detection_opportunity}
            </div>
            <div className={styles.stepMeta}>
              <span
                className={`${styles.feasibilityBadge} ${getFeasibilityClass(step.detection_feasibility)}`}
              >
                {getFeasibilityLabel(step.detection_feasibility)}
              </span>
              {step.log_sources.map((source) => (
                <span key={source} className={styles.logSourceTag}>
                  {source}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function IndicatorsSection({
  indicators,
  activeTab,
  onTabChange,
  currentIndicators,
  getCount,
}: {
  indicators: DetectionSummaryResponse["indicators"];
  activeTab: IndicatorTab;
  onTabChange: (tab: IndicatorTab) => void;
  currentIndicators: DetectionIndicator[];
  getCount: (tab: IndicatorTab) => number;
}) {
  const tabs: { key: IndicatorTab; label: string }[] = [
    { key: "network", label: "Network" },
    { key: "host", label: "Host" },
    { key: "behavioral", label: "Behavioral" },
  ];

  const totalCount =
    (indicators.network?.length ?? 0) +
    (indicators.host?.length ?? 0) +
    (indicators.behavioral?.length ?? 0);

  if (totalCount === 0) return null;

  return (
    <div className={styles.sectionCard}>
      <div className={styles.sectionHeader}>
        <span className={styles.sectionIcon}>&#x1F50D;</span>
        <span className={styles.sectionTitle}>Indicators</span>
      </div>
      <div className={styles.tabNav}>
        {tabs.map((tab) => (
          <button
            key={tab.key}
            className={`${styles.tab} ${activeTab === tab.key ? styles.tabActive : ""}`}
            onClick={() => onTabChange(tab.key)}
          >
            {tab.label}
            <span className={styles.tabCount}>{getCount(tab.key)}</span>
          </button>
        ))}
      </div>
      {currentIndicators.length > 0 ? (
        <div className={styles.indicatorGrid}>
          {currentIndicators.map((indicator, idx) => (
            <IndicatorCard key={idx} indicator={indicator} />
          ))}
        </div>
      ) : (
        <div className={styles.indicatorEmpty}>
          No {activeTab} indicators found in this analysis.
        </div>
      )}
    </div>
  );
}

function IndicatorCard({ indicator }: { indicator: DetectionIndicator }) {
  return (
    <div className={styles.indicatorCard}>
      <div className={styles.indicatorType}>{indicator.type}</div>
      {indicator.value && (
        <div className={styles.indicatorValue}>{indicator.value}</div>
      )}
      {(indicator.context || indicator.description) && (
        <p className={styles.indicatorContext}>
          {indicator.context || indicator.description}
        </p>
      )}
      {indicator.detection_note && (
        <div className={styles.indicatorDetection}>
          {indicator.detection_note}
        </div>
      )}
    </div>
  );
}

function GeneratedRulesSection({
  rules,
  copiedIndex,
  savedIndices,
  onCopy,
  onSave,
}: {
  rules: GeneratedRule[];
  copiedIndex: number | null;
  savedIndices: Set<number>;
  onCopy: (content: string, index: number) => void;
  onSave: (rule: GeneratedRule, index: number) => void;
}) {
  if (rules.length === 0) return null;

  return (
    <Panel
      className={styles.sectionPanel}
      padding="lg"
      titleVariant="heading"
      title={
        <>
          <span className={styles.sectionIcon}>&#x1F4DD;</span>
          Generated Rules ({rules.length})
        </>
      }
    >
      <div className={styles.rulesGrid}>
        {rules.map((rule, idx) => (
          <div key={idx} className={styles.ruleCard}>
            <div className={styles.ruleHeader}>
              <div className={styles.ruleHeaderLeft}>
                <span className={styles.ruleTypeBadge}>{rule.rule_type}</span>
                <span className={styles.ruleTitle}>{rule.title}</span>
                {rule.severity && (
                  <span className={styles.ruleSeverity}>
                    Severity: {rule.severity}
                  </span>
                )}
              </div>
              <div style={{ display: "flex", gap: "0.375rem" }}>
                <button
                  className={
                    savedIndices.has(idx)
                      ? `${styles.saveBtn} ${styles.savedBtn}`
                      : styles.saveBtn
                  }
                  onClick={() => onSave(rule, idx)}
                  disabled={savedIndices.has(idx)}
                >
                  {savedIndices.has(idx) ? "Saved" : "Save"}
                </button>
                <button
                  className={styles.copyBtn}
                  onClick={() => onCopy(rule.content, idx)}
                >
                  {copiedIndex === idx ? "Copied" : "Copy"}
                </button>
              </div>
            </div>
            <div className={styles.ruleContent}>
              <pre>{rule.content}</pre>
            </div>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function RelatedIntelligenceSection({
  intelligence,
}: {
  intelligence: DetectionSummaryResponse["related_intelligence"];
}) {
  const articles = intelligence?.previous_articles ?? [];
  const rules = intelligence?.existing_detection_rules ?? [];
  const cves = intelligence?.related_cves ?? [];

  if (articles.length === 0 && rules.length === 0 && cves.length === 0) return null;

  return (
    <Panel
      className={styles.sectionPanel}
      padding="lg"
      titleVariant="heading"
      title={
        <>
          <span className={styles.sectionIcon}>&#x1F517;</span>
          Related Intelligence
        </>
      }
    >
      {articles.length > 0 && (
        <div style={{ marginBottom: "1rem" }}>
          <div className={styles.relatedSubheading}>Related Articles</div>
          <ul className={styles.relatedList}>
            {articles.map((a, i) => (
              <li key={i} className={styles.relatedListItem}>
                {a.url ? (
                  <a href={a.url} target="_blank" rel="noopener noreferrer">
                    {a.title}
                  </a>
                ) : (
                  a.title
                )}
                {a.published_at && (
                  <span className={styles.relatedDate}>{a.published_at}</span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
      {rules.length > 0 && (
        <div style={{ marginBottom: "1rem" }}>
          <div className={styles.relatedSubheading}>Existing Detection Rules</div>
          <ul className={styles.relatedList}>
            {rules.map((r, i) => (
              <li key={i} className={styles.relatedListItem}>
                <span className={styles.ruleTypeBadge}>{r.rule_type}</span>
                {r.title}
              </li>
            ))}
          </ul>
        </div>
      )}
      {cves.length > 0 && (
        <div>
          <div className={styles.relatedSubheading}>Related CVEs</div>
          <ul className={styles.relatedList}>
            {cves.map((c, i) => (
              <li key={i} className={styles.relatedListItem}>
                <strong>{c.cve_id}</strong>
                {c.description && <span> — {c.description}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
    </Panel>
  );
}

function GapsSection({ gaps }: { gaps: string[] }) {
  if (gaps.length === 0) return null;

  return (
    <Panel
      className={styles.sectionPanel}
      padding="lg"
      titleVariant="heading"
      title={
        <>
          <span className={styles.sectionIcon}>&#x26A0;</span>
          Gaps & Recommendations
        </>
      }
    >
      <ul className={styles.gapsList}>
        {gaps.map((gap, idx) => (
          <li key={idx} className={styles.gapItem}>
            <span className={styles.gapIcon}>&#x26A0;</span>
            <span>{gap}</span>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
