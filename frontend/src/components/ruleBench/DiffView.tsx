import type { DiffLine } from "./lineDiff";
import styles from "./DiffView.module.css";

/** Turn a unified-diff string (what the versions endpoint returns) into lines. */
export function parseUnifiedDiff(diff: string): DiffLine[] {
  return diff.split("\n").map((text) => ({
    op: text.startsWith("+") ? "add" : text.startsWith("-") ? "remove" : "same",
    text,
  }));
}

export function DiffView({ lines }: { lines: DiffLine[] }) {
  return (
    <pre className={styles.diff}>
      {lines.map((line, i) => (
        <div key={i} className={styles[line.op]}>{line.text || " "}</div>
      ))}
    </pre>
  );
}
