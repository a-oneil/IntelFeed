import { useNavigate } from "react-router-dom";
import { useCampaignMomentum, type CampaignMomentumRow } from "@/hooks/useWidgetBoardData";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

const CAMPAIGN_COLOR = "#14b8a6";

/** Compare the latest third of the window against the middle third. */
function momentum(row: CampaignMomentumRow): { label: string; hot: boolean } {
  const counts = row.weeks.map((w) => w.count);
  if (counts.length < 3 || counts.every((c) => c === 0)) return { label: "quiet", hot: false };
  const slice = Math.max(1, Math.floor(counts.length / 3));
  const recent = counts.slice(-slice).reduce((a, b) => a + b, 0);
  const prior = counts.slice(-slice * 2, -slice).reduce((a, b) => a + b, 0);
  if (recent === 0) return { label: "quiet", hot: false };
  if (recent > prior * 1.3) return { label: "accelerating", hot: true };
  if (recent * 1.3 < prior) return { label: "cooling", hot: false };
  return { label: "steady", hot: false };
}

function AreaSpark({ counts }: { counts: number[] }) {
  if (counts.length === 0) return null;
  const w = 92;
  const h = 24;
  const max = Math.max(...counts, 1);
  const step = counts.length > 1 ? w / (counts.length - 1) : 0;
  const pts = counts.map((c, i) => `${(i * step).toFixed(1)},${(h - 3 - (h - 6) * (c / max)).toFixed(1)}`);
  return (
    <svg className={styles.miniSpark} width={w} height={h} viewBox={`0 0 ${w} ${h}`} aria-hidden="true">
      <polygon points={`${pts.join(" ")} ${w},${h} 0,${h}`} fill="rgba(20,184,166,0.12)" />
      <polyline
        points={pts.join(" ")}
        fill="none"
        stroke={CAMPAIGN_COLOR}
        strokeWidth="1.5"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}

export default function CampaignMomentumWidget({ config }: Props) {
  const limit = (config.limit as number) || 6;
  const { data, isLoading } = useCampaignMomentum(limit);
  const navigate = useNavigate();

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.items.length === 0) {
    return <div className={styles.noData}>No open campaigns</div>;
  }

  return (
    <div className={styles.list}>
      {data.items.map((row) => {
        const m = momentum(row);
        return (
          <button
            key={row.id}
            className={styles.boardRow}
            onClick={() => navigate(`/workbench/campaign/${row.id}`)}
          >
            <span className={styles.entityDot} style={{ background: "var(--entity-campaign)" }} />
            <span className={styles.boardGrow}>
              <span className={styles.boardPrimary}>{row.name}</span>
              <span className={styles.boardMeta}>
                {row.recent_count > 0 ? `+${row.recent_count} recent` : "no new entries"} ·{" "}
                {row.total_entries} total
              </span>
            </span>
            <AreaSpark counts={row.weeks.map((w) => w.count)} />
            <Chip
              className={styles.boardChip}
              tone={m.hot ? "toned" : "default"}
              tint={m.hot ? "var(--accent)" : undefined}
            >
              {m.label}
            </Chip>
          </button>
        );
      })}
    </div>
  );
}
