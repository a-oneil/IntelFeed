import { useNavigate } from "react-router-dom";
import { useMorningBriefing } from "@/hooks/useWidgetBoardData";
import { EntityLinkedMarkdown } from "@/components/EntityLinkedMarkdown";
import { WidgetChartSkeleton } from "@/components/Skeleton";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

function generatedLabel(iso: string | null): string {
  if (!iso) return "";
  const when = new Date(iso);
  if (Number.isNaN(when.getTime())) return "";
  return when.toLocaleString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

export default function MorningBriefingWidget({ config }: Props) {
  void config;
  const { data, isLoading } = useMorningBriefing();
  const navigate = useNavigate();

  if (isLoading) return <WidgetChartSkeleton />;
  if (!data?.summary) {
    return (
      <div className={styles.noData}>
        No briefing yet — daily summaries generate overnight, or run one from the reader&apos;s day divider
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", minHeight: 0 }}>
      <div className={styles.briefingBody}>
        {/* Entity linking goes through the remark plugin — never post-render DOM
            mutation, which crashes react-markdown's reconciliation. */}
        <EntityLinkedMarkdown text={data.summary} />
      </div>
      <div className={styles.briefingFooter}>
        <span className={styles.boardMeta} style={{ display: "inline" }}>
          {generatedLabel(data.generated_at)}
        </span>
        <span style={{ flex: 1 }} />
        <Chip className={styles.boardChip} onClick={() => navigate("/")}>
          open in reader
        </Chip>
      </div>
    </div>
  );
}
