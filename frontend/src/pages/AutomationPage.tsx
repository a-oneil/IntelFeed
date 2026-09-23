import { useState, useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import {
  useAutomationRules,
  useDeleteAutomationRule,
  useToggleAutomationRule,
  useRunAutomationRule,
  useExportAutomationRules,
  useUpdateAutomationRule,
  useCreateAutomationRule,
} from "@/hooks/useAutomation";
import { toast } from "sonner";
import { AutomationRuleEditor } from "@/components/AutomationRuleEditor";
import { FlowBuilder } from "@/components/automation/FlowBuilder";
import {
  TemplateGallery,
  type AutomationTemplate,
} from "@/components/automation/TemplateGallery";
import { ImportExportDialog } from "@/components/automation/ImportExportDialog";
import { formatDate } from "@/utils/formatDate";
import type { AutomationRule } from "@/api/types";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import { useAuthStore } from "@/stores/authStore";
import { useUIStore } from "@/stores/uiStore";
import { Chip, PageHeader, Segmented } from "@/components/primitives";
import styles from "./AutomationPage.module.css";

type EditorMode = "flow" | "form";

export function AutomationPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [filterLabel, setFilterLabel] = useState<string | undefined>(undefined);
  const { data: rulesData, isLoading } = useAutomationRules(filterLabel);
  const toggleRule = useToggleAutomationRule();
  const deleteRule = useDeleteAutomationRule();
  const updateRule = useUpdateAutomationRule();
  const undoableDelete = useUndoableDelete();
  const runRule = useRunAutomationRule();
  const createRule = useCreateAutomationRule();
  const [editingRule, setEditingRule] = useState<AutomationRule | null>(null);
  const [showEditor, setShowEditor] = useState(false);
  const [editorMode, setEditorMode] = useState<EditorMode>("flow");
  const [showGallery, setShowGallery] = useState(false);
  const [showImport, setShowImport] = useState(false);
  const exportRules = useExportAutomationRules();
  const user = useAuthStore((s) => s.user);
  // Run/toggle/edit/delete are owner-or-admin on the backend now.
  const canManage = (rule: AutomationRule) =>
    user?.role === "admin" || rule.created_by === user?.id;
  const automationShowDisabled = useUIStore((s) => s.automationShowDisabled);
  const toggleAutomationShowDisabled = useUIStore(
    (s) => s.toggleAutomationShowDisabled
  );

  // Auto-open editor when navigated with ?create=true
  useEffect(() => {
    if (searchParams.get("create") === "true") {
      setEditingRule(null);
      setShowEditor(true);
      setSearchParams({}, { replace: true });
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Enabled rules first, then alphabetical — disabled ones sink to the bottom
  // (and are hidden entirely unless the toolbar toggle is on).
  const rules = [...(rulesData?.items ?? [])].sort(
    (a, b) =>
      Number(b.is_enabled) - Number(a.is_enabled) ||
      a.name.localeCompare(b.name, undefined, { sensitivity: "base" })
  );
  const disabledCount = rules.filter((r) => !r.is_enabled).length;
  const visibleRules = automationShowDisabled
    ? rules
    : rules.filter((r) => r.is_enabled);

  // Collect all unique labels across rules for the filter bar
  const allLabels = Array.from(
    new Set(rules.flatMap((r) => r.labels ?? []))
  ).sort();

  const handleNewRule = () => {
    setEditingRule(null);
    setShowEditor(true);
  };

  const handleEditRule = (rule: AutomationRule) => {
    setEditingRule(rule);
    setShowEditor(true);
  };

  // Create a draft rule from a template (disabled), then drop straight into the
  // builder so the user can review/tweak and save.
  const handleUseTemplate = async (template: AutomationTemplate) => {
    try {
      const created = await createRule.mutateAsync({
        name: template.name,
        description: template.description,
        trigger_type: template.trigger_type,
        trigger_config: template.trigger_config,
        conditions: template.conditions,
        actions: template.actions as Array<Record<string, unknown>>,
        is_enabled: false,
      });
      setShowGallery(false);
      setEditingRule(created);
      setShowEditor(true);
      toast.success(`Created "${template.name}" — review and enable it`);
    } catch {
      toast.error("Failed to create rule from template");
    }
  };

  const handleCloseEditor = () => {
    setShowEditor(false);
    setEditingRule(null);
  };

  const handleDelete = (ruleId: string) => {
    undoableDelete({
      label: "Automation rule",
      key: `automation-${ruleId}`,
      onDelete: () => deleteRule.mutate(ruleId),
    });
  };

  const handleToggleLabel = (ruleId: string, label: string, currentLabels: string[]) => {
    const hasLabel = currentLabels.includes(label);
    const nextLabels = hasLabel
      ? currentLabels.filter((l) => l !== label)
      : [...currentLabels, label];
    updateRule.mutate({ ruleId, data: { labels: nextLabels } });
  };

  const handleAddLabel = (ruleId: string, currentLabels: string[]) => {
    const label = prompt("Enter label name:");
    if (!label?.trim()) return;
    const normalized = label.trim().toLowerCase();
    if (currentLabels.includes(normalized)) return;
    updateRule.mutate({ ruleId, data: { labels: [...currentLabels, normalized] } });
  };

  const handleExport = (ruleIds?: string[]) => {
    exportRules.mutate(
      { ruleIds },
      {
        onSuccess: (data) => {
          const blob = new Blob([JSON.stringify(data, null, 2)], {
            type: "application/json",
          });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          const date = new Date().toISOString().slice(0, 10);
          a.download = `intelfeed-rules-${date}.json`;
          a.click();
          URL.revokeObjectURL(url);
          toast.success(
            `Exported ${data.rules.length} rule(s)`
          );
        },
        onError: () => {
          toast.error("Export failed");
        },
      }
    );
  };

  const handleRunNow = (ruleId: string, ruleName: string) => {
    runRule.mutate(
      { ruleId },
      {
        onSuccess: (data) => {
          toast.success(`${ruleName}: ${data.message}`);
        },
      }
    );
  };

  if (showGallery) {
    return (
      <TemplateGallery
        onClose={() => setShowGallery(false)}
        onUseTemplate={handleUseTemplate}
      />
    );
  }

  if (showEditor) {
    if (editorMode === "flow") {
      return (
        <FlowBuilder rule={editingRule} onClose={handleCloseEditor} />
      );
    }
    return (
      <AutomationRuleEditor
        rule={editingRule}
        onClose={handleCloseEditor}
      />
    );
  }

  return (
    <div className={styles.container}>
      <PageHeader
        title="Automation"
        count={`${rules.filter((r) => r.is_enabled).length} active / ${rules.length} rules`}
        actions={
          <>
            {disabledCount > 0 && (
              <button
                onClick={toggleAutomationShowDisabled}
                className={`${styles.templateBtn} ${automationShowDisabled ? styles.disabledToggleOn : ""}`}
                title={
                  automationShowDisabled
                    ? "Hide disabled rules"
                    : "Show disabled rules"
                }
              >
                {automationShowDisabled ? "Hide" : "Show"} {disabledCount} disabled
              </button>
            )}
            <button onClick={() => setShowGallery(true)} className={styles.templateBtn}>
              Templates
            </button>
            <button
              onClick={() => handleExport()}
              className={styles.templateBtn}
              disabled={exportRules.isPending || rules.length === 0}
            >
              {exportRules.isPending ? "Exporting..." : "Export"}
            </button>
            <button
              onClick={() => setShowImport(true)}
              className={styles.templateBtn}
            >
              Import
            </button>
            <button onClick={handleNewRule} className={styles.addBtn}>
              + New Rule
            </button>
          </>
        }
        controls={
          <Segmented<"flow" | "form">
            label="Rule editor mode"
            size="sm"
            value={editorMode}
            onChange={setEditorMode}
            options={[
              { value: "flow", label: "Flow", title: "Visual flow builder" },
              { value: "form", label: "Form", title: "Classic form editor" },
            ]}
          />
        }
      />
      {allLabels.length > 0 && (
        <div className={styles.labelBar}>
          <span className={styles.labelBarTitle}>Labels:</span>
          <Chip
            pill
            tone={!filterLabel ? "toned" : "default"}
            tint="var(--accent)"
            aria-pressed={!filterLabel}
            onClick={() => setFilterLabel(undefined)}
          >
            All
          </Chip>
          {allLabels.map((label) => (
            <Chip
              key={label}
              pill
              truncate
              tone={filterLabel === label ? "toned" : "default"}
              tint="var(--accent)"
              aria-pressed={filterLabel === label}
              onClick={() =>
                setFilterLabel(filterLabel === label ? undefined : label)
              }
            >
              {label}
            </Chip>
          ))}
        </div>
      )}

      <div className={styles.content}>
        {/* Rules list */}
        <div className={styles.section}>
          {isLoading && <p className={styles.muted}>Loading...</p>}
          {!isLoading && rules.length === 0 && (
            <p className={styles.muted}>
              No automation rules yet.{" "}
              <button
                onClick={() => setShowGallery(true)}
                className={styles.linkBtn}
              >
                Browse templates
              </button>{" "}
              or create one from scratch.
            </p>
          )}
          {!isLoading && rules.length > 0 && visibleRules.length === 0 && (
            <p className={styles.muted}>
              All {rules.length} rules are disabled.{" "}
              <button
                onClick={toggleAutomationShowDisabled}
                className={styles.linkBtn}
              >
                Show them
              </button>
            </p>
          )}
          <div className={styles.ruleList}>
            {visibleRules.map((rule) => (
              <div
                key={rule.id}
                className={`${styles.ruleCard} ${rule.is_enabled ? "" : styles.ruleCardDisabled}`}
              >
                <div className={styles.ruleHeader}>
                  <span
                    className={`${styles.statusDot} ${rule.is_enabled ? styles.active : styles.inactive}`}
                  />
                  <span
                    className={styles.ruleName}
                    onClick={canManage(rule) ? () => handleEditRule(rule) : undefined}
                  >
                    {rule.name}
                  </span>
                  <Chip>{rule.trigger_type.replace("on_", "")}</Chip>
                  {!canManage(rule) && (
                    <span className={styles.sharedTag} title="Owned by another user">
                      shared
                    </span>
                  )}
                </div>
                {rule.description && (
                  <p className={styles.ruleDesc}>{rule.description}</p>
                )}
                <div className={styles.ruleLabels}>
                  {(rule.labels ?? []).map((label) =>
                    canManage(rule) ? (
                      <Chip
                        key={label}
                        pill
                        truncate
                        tone="toned"
                        tint="var(--accent)"
                        className={styles.ruleLabelChip}
                        onClick={() =>
                          handleToggleLabel(rule.id, label, rule.labels ?? [])
                        }
                        title={`Click to remove "${label}"`}
                      >
                        {label} &times;
                      </Chip>
                    ) : (
                      <Chip
                        key={label}
                        pill
                        truncate
                        tone="toned"
                        tint="var(--accent)"
                        className={styles.ruleLabelChip}
                      >
                        {label}
                      </Chip>
                    )
                  )}
                  {canManage(rule) && (
                    <button
                      className={styles.addLabelBtn}
                      onClick={() =>
                        handleAddLabel(rule.id, rule.labels ?? [])
                      }
                    >
                      + label
                    </button>
                  )}
                </div>
                <div className={styles.ruleMeta}>
                  <span>
                    Last: {formatDate(rule.last_triggered_at, "Never")}
                  </span>
                  <span>{rule.run_count} runs</span>
                  <span>{rule.actions.length} action(s)</span>
                </div>
                <div className={styles.ruleActions}>
                  {canManage(rule) && (
                    <>
                      <button
                        onClick={() => handleRunNow(rule.id, rule.name)}
                        className={`${styles.smallBtn} ${styles.runBtn}`}
                        disabled={runRule.isPending}
                      >
                        {runRule.isPending &&
                        runRule.variables?.ruleId === rule.id
                          ? "Running..."
                          : "Run Now"}
                      </button>
                      <button
                        onClick={() => toggleRule.mutate(rule.id)}
                        className={styles.smallBtn}
                      >
                        {rule.is_enabled ? "Disable" : "Enable"}
                      </button>
                    </>
                  )}
                  <button
                    onClick={() => handleExport([rule.id])}
                    className={styles.smallBtn}
                  >
                    Export
                  </button>
                  {canManage(rule) && (
                    <>
                      <button
                        onClick={() => handleEditRule(rule)}
                        className={styles.smallBtn}
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => handleDelete(rule.id)}
                        className={`${styles.smallBtn} ${styles.dangerBtn}`}
                      >
                        Delete
                      </button>
                    </>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>

      {showImport && (
        <ImportExportDialog onClose={() => setShowImport(false)} />
      )}
    </div>
  );
}
