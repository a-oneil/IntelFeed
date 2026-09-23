import bench from "./bench.module.css";
import styles from "./RuleAIActions.module.css";

const ACTIONS: [label: string, prompt: string][] = [
  ["Reduce noise", "Make this rule less noisy by adding exclusions"],
  ["Evasion check", "What would an adversary do to evade this detection?"],
  ["Explain", "Explain what this rule does in plain English"],
  ["Cover a new observable", "What observable is this rule missing, and how would I add it?"],
];

interface RuleAIActionsProps {
  onAsk: (prompt: string) => void;
  disabled?: boolean;
}

export function RuleAIActions({ onAsk, disabled }: RuleAIActionsProps) {
  return (
    <div className={styles.bar}>
      {ACTIONS.map(([label, prompt]) => (
        <button key={label} type="button" className={bench.btn} onClick={() => onAsk(prompt)} disabled={disabled}>
          {label}
        </button>
      ))}
    </div>
  );
}
