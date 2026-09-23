import styles from "./ReliabilityBadge.module.css";

interface Props {
  rating: string | null | undefined;
  size?: "sm" | "md";
}

const RATING_CONFIG: Record<string, { label: string; className: string }> = {
  A: { label: "A — Reliable source", className: "high" },
  B: { label: "B — Usually reliable source", className: "high" },
  C: { label: "C — Fairly reliable source", className: "mid" },
  D: { label: "D — Not usually reliable source", className: "low" },
  E: { label: "E — Unreliable source", className: "low" },
  F: { label: "F — Reliability cannot be judged", className: "unjudged" },
};

/** Admiralty source-reliability rating badge (A–F). Renders nothing when unrated. */
export function ReliabilityBadge({ rating, size = "sm" }: Props) {
  if (!rating) return null;
  const config = RATING_CONFIG[rating];
  if (!config) return null;

  return (
    <span
      className={`${styles.badge} ${styles[config.className]} ${size === "md" ? styles.md : ""}`}
      data-tooltip={config.label}
    >
      {rating}
    </span>
  );
}
