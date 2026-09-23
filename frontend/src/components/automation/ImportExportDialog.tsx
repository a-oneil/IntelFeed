import { useState, useRef, useCallback } from "react";
import { useImportAutomationRules } from "@/hooks/useAutomation";
import { toast } from "sonner";
import type { RuleExportPayload, RuleImportResponse } from "@/api/types";
import styles from "./ImportExportDialog.module.css";

interface Props {
  onClose: () => void;
}

export function ImportExportDialog({ onClose }: Props) {
  const fileInput = useRef<HTMLInputElement>(null);
  const [payload, setPayload] = useState<RuleExportPayload | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);
  const [enabledOnImport, setEnabledOnImport] = useState(false);
  const [overwriteExisting, setOverwriteExisting] = useState(false);
  const [result, setResult] = useState<RuleImportResponse | null>(null);

  const importMutation = useImportAutomationRules();

  const handleFileSelect = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (!file) return;

      setParseError(null);
      setPayload(null);
      setResult(null);

      const reader = new FileReader();
      reader.onload = () => {
        try {
          const data = JSON.parse(reader.result as string);
          if (!data.intelfeed_rule_export || !Array.isArray(data.rules)) {
            setParseError(
              "Invalid file: missing intelfeed_rule_export header or rules array"
            );
            return;
          }
          if (data.intelfeed_rule_export.version !== 1) {
            setParseError(
              `Unsupported format version: ${data.intelfeed_rule_export.version}`
            );
            return;
          }
          setPayload(data as RuleExportPayload);
        } catch {
          setParseError("Invalid JSON file");
        }
      };
      reader.readAsText(file);
    },
    []
  );

  const handleImport = () => {
    if (!payload) return;
    importMutation.mutate(
      { payload, enabledOnImport, overwriteExisting },
      {
        onSuccess: (data) => {
          setResult(data);
          if (data.imported > 0) {
            toast.success(`Imported ${data.imported} rule(s)`);
          }
        },
        onError: () => {
          toast.error("Import failed");
        },
      }
    );
  };

  return (
    <div className={styles.overlay} onClick={onClose}>
      <div className={styles.dialog} onClick={(e) => e.stopPropagation()}>
        <div className={styles.header}>
          <h3>Import Automation Rules</h3>
          <button className={styles.closeBtn} onClick={onClose}>
            &times;
          </button>
        </div>

        <div className={styles.body}>
          {/* File selection */}
          {!payload && !result && (
            <>
              <div
                className={styles.dropZone}
                onClick={() => fileInput.current?.click()}
              >
                Click to select an IntelFeed rule export (.json)
              </div>
              <input
                ref={fileInput}
                type="file"
                accept=".json"
                onChange={handleFileSelect}
                className={styles.hiddenInput}
              />
            </>
          )}

          {parseError && <p className={styles.error}>{parseError}</p>}

          {/* Preview */}
          {payload && !result && (
            <>
              <div className={styles.rulePreview}>
                {payload.rules.map((rule, i) => (
                  <div key={i} className={styles.rulePreviewItem}>
                    <span className={styles.rulePreviewName}>{rule.name}</span>
                    <span className={styles.rulePreviewMeta}>
                      {rule.trigger_type.replace("on_", "")} &middot;{" "}
                      {rule.actions.length} action(s)
                    </span>
                  </div>
                ))}
              </div>

              <div className={styles.options}>
                <label className={styles.option}>
                  <input
                    type="checkbox"
                    checked={enabledOnImport}
                    onChange={(e) => setEnabledOnImport(e.target.checked)}
                  />
                  Enable imported rules immediately
                </label>
                <label className={styles.option}>
                  <input
                    type="checkbox"
                    checked={overwriteExisting}
                    onChange={(e) => setOverwriteExisting(e.target.checked)}
                  />
                  Overwrite rules with the same name
                </label>
              </div>
            </>
          )}

          {/* Result */}
          {result && (
            <div className={styles.resultSummary}>
              <p>
                <strong>{result.imported}</strong> imported,{" "}
                <strong>{result.skipped}</strong> skipped
              </p>
              {result.errors.length > 0 && (
                <div className={styles.error}>
                  {result.errors.map((e, i) => (
                    <p key={i}>{e}</p>
                  ))}
                </div>
              )}
              {result.warnings.length > 0 && (
                <div className={styles.warning}>
                  {result.warnings.map((w, i) => (
                    <p key={i}>{w}</p>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        <div className={styles.footer}>
          {result ? (
            <button className={styles.cancelBtn} onClick={onClose}>
              Done
            </button>
          ) : (
            <>
              <button className={styles.cancelBtn} onClick={onClose}>
                Cancel
              </button>
              {payload && (
                <button
                  className={styles.importBtn}
                  onClick={handleImport}
                  disabled={importMutation.isPending}
                >
                  {importMutation.isPending
                    ? "Importing..."
                    : `Import ${payload.rules.length} Rule(s)`}
                </button>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
