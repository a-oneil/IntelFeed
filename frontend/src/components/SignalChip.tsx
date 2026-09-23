import { Chip } from "./primitives";
import { signalBand } from "@/utils/signalBand";

export interface TopSignal {
  type: string;
  explanation: string;
}

const BAND_TINT = {
  low: "var(--accent)",
  medium: "var(--warning)",
  high: "var(--danger)",
} as const;

/** Priority chip for entries that clear the radar threshold (signal engine). */
export function SignalChip({ score, signals }: { score: number; signals: TopSignal[] }) {
  const band = signalBand(score);
  const tooltip = signals.length
    ? signals.map((s) => s.explanation).join("\n")
    : `Priority score ${score.toFixed(1)}`;
  return (
    <Chip tone="toned" tint={BAND_TINT[band]} pill title={tooltip}>
      ◆ {score.toFixed(1)}
    </Chip>
  );
}
