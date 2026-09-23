import { useNavigate } from "react-router-dom";
import { useUnderReported } from "@/hooks/useWidgetBoardData";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

export default function UnderReportedWidget({ config }: Props) {
  const limit = (config.limit as number) || 10;
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const { data, isLoading } = useUnderReported({ date_from, date_to, limit });
  const navigate = useNavigate();

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.items.length === 0) {
    return <div className={styles.noData}>Nothing under-reported in this window</div>;
  }

  return (
    <div className={styles.list}>
      {data.items.map((item) => (
        <button
          key={item.entry_id}
          className={styles.boardRow}
          onClick={() => navigate(`/?entry=${item.entry_id}`)}
          title={item.explanation}
        >
          <span className={styles.boardGrow}>
            <span className={styles.boardPrimary}>{item.title}</span>
            <span className={styles.boardMeta}>{item.explanation}</span>
          </span>
          {item.feeds_covering !== null && item.feeds_covering !== undefined && (
            <Chip className={styles.boardChip}>
              {item.feeds_covering} {item.feeds_covering === 1 ? "feed" : "feeds"}
            </Chip>
          )}
        </button>
      ))}
    </div>
  );
}
