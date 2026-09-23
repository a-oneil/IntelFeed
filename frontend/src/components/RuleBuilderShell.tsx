import type { RuleValidationError } from "@/api/types";
import CodeMirrorEditor from "@/components/CodeMirrorEditor";
import styles from "./RuleBuilderShell.module.css";

interface RuleBuilderShellProps {
  ruleType: string;
  value: string;
  onChange: (value: string) => void;
  readOnly?: boolean;
  validationErrors?: RuleValidationError[];
}

export default function RuleBuilderShell({
  ruleType,
  value,
  onChange,
  readOnly = false,
  validationErrors = [],
}: RuleBuilderShellProps) {
  return (
    <div className={styles.shell}>
      <div className={styles.editorFill}>
        <CodeMirrorEditor
          value={value}
          onChange={readOnly ? undefined : onChange}
          language={ruleType}
          readOnly={readOnly}
          validationErrors={validationErrors}
          height="100%"
        />
      </div>
    </div>
  );
}
