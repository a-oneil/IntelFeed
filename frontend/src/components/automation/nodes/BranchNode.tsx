import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { Chip } from "@/components/primitives";
import styles from "./NodeStyles.module.css";

const CONDITION_TYPES = [
  { value: "feed_matches", label: "Feed Matches" },
  { value: "content_contains", label: "Content Contains" },
  { value: "severity_above", label: "Severity Above" },
  { value: "author_matches", label: "Author Matches" },
  { value: "tag_matches", label: "Tag Matches" },
  { value: "feed_type_matches", label: "Feed Type" },
  { value: "is_read", label: "Is Read" },
  { value: "is_starred", label: "Is Starred" },
  { value: "is_bookmarked", label: "Is Bookmarked" },
  { value: "has_note", label: "Has Note" },
];

interface BranchNodeData {
  conditionType: string;
  conditionConfig: Record<string, unknown>;
  onUpdate?: (data: Record<string, unknown>) => void;
  onDelete?: () => void;
  [key: string]: unknown;
}

export const BranchNode = memo(function BranchNode({ data }: NodeProps) {
  const d = data as unknown as BranchNodeData;
  const { conditionType, conditionConfig, onUpdate, onDelete } = d;

  return (
    <div className={`${styles.node} ${styles.branchNode}`}>
      <Handle type="target" position={Position.Left} className={styles.handle} />

      <div className={styles.nodeHeader}>
        <Chip size="sm" tone="toned" tint="var(--node-branch)" className={styles.badge}>
          IF/ELSE
        </Chip>
        <span className={styles.nodeTitle}>Branch</span>
        {onDelete && (
          <button className={styles.deleteBtn} onClick={onDelete}>
            &times;
          </button>
        )}
      </div>

      <div className={styles.nodeBody}>
        <div className={styles.fieldGroup}>
          <span className={styles.fieldLabel}>Condition</span>
          <select
            className={styles.select}
            value={conditionType || "content_contains"}
            onChange={(e) =>
              onUpdate?.({ conditionType: e.target.value, conditionConfig: {} })
            }
          >
            {CONDITION_TYPES.map((ct) => (
              <option key={ct.value} value={ct.value}>
                {ct.label}
              </option>
            ))}
          </select>
        </div>

        {/* Condition-specific config */}
        {conditionType === "content_contains" && (
          <div className={styles.fieldGroup}>
            <span className={styles.fieldLabel}>Pattern</span>
            <input
              className={styles.input}
              value={(conditionConfig?.pattern as string) ?? ""}
              onChange={(e) =>
                onUpdate?.({
                  conditionConfig: { ...conditionConfig, pattern: e.target.value },
                })
              }
              placeholder="keyword or regex"
            />
            <label className={styles.checkLabel}>
              <input
                type="checkbox"
                checked={(conditionConfig?.is_regex as boolean) ?? false}
                onChange={(e) =>
                  onUpdate?.({
                    conditionConfig: {
                      ...conditionConfig,
                      is_regex: e.target.checked,
                    },
                  })
                }
              />
              Regex
            </label>
          </div>
        )}

        {conditionType === "severity_above" && (
          <div className={styles.fieldGroup}>
            <span className={styles.fieldLabel}>Min CVSS</span>
            <input
              className={styles.input}
              type="number"
              min={0}
              max={10}
              step={0.1}
              value={(conditionConfig?.min_cvss as number) ?? 7.0}
              onChange={(e) =>
                onUpdate?.({
                  conditionConfig: {
                    ...conditionConfig,
                    min_cvss: parseFloat(e.target.value),
                  },
                })
              }
            />
          </div>
        )}

        {conditionType === "author_matches" && (
          <div className={styles.fieldGroup}>
            <span className={styles.fieldLabel}>Authors (comma-sep)</span>
            <input
              className={styles.input}
              value={(conditionConfig?.authors as string[])?.join(", ") ?? ""}
              onChange={(e) =>
                onUpdate?.({
                  conditionConfig: {
                    ...conditionConfig,
                    authors: e.target.value
                      .split(",")
                      .map((a) => a.trim())
                      .filter(Boolean),
                  },
                })
              }
            />
          </div>
        )}

        {/* Output handle labels */}
        <div className={styles.branchOutputs}>
          <div className={styles.branchOutput}>
            <Chip tone="quiet" fg="var(--success)">
              Yes
            </Chip>
          </div>
          <div className={styles.branchOutput}>
            <Chip tone="quiet" fg="var(--danger)">
              No
            </Chip>
          </div>
        </div>
      </div>

      <Handle
        type="source"
        position={Position.Right}
        id="then"
        className={styles.handle}
        style={{ top: "40%" }}
      />
      <Handle
        type="source"
        position={Position.Right}
        id="else"
        className={styles.handle}
        style={{ top: "70%" }}
      />
    </div>
  );
});
