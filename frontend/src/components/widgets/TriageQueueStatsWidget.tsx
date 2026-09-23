import { useNavigate } from "react-router-dom";
import { useTriageQueueStats } from "@/hooks/useWidgetTriageData";
import { useUIStore } from "@/stores/uiStore";
import { WidgetStatSkeleton } from "@/components/Skeleton";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

type TileKey = "unread" | "starred" | "total";

export default function TriageQueueStatsWidget(_: Props) {
  const navigate = useNavigate();
  const setSelectedFeed = useUIStore((s) => s.setSelectedFeed);
  const setSelectedCategory = useUIStore((s) => s.setSelectedCategory);
  const setVirtualFolder = useUIStore((s) => s.setVirtualFolder);
  const setShowUnreadOnly = useUIStore((s) => s.setShowUnreadOnly);
  const { data, isLoading } = useTriageQueueStats();

  if (isLoading) return <WidgetStatSkeleton />;
  if (!data) return <div className={styles.noData}>No data</div>;

  const tiles: Array<{ key: TileKey; label: string }> = [
    { key: "unread", label: "Unread" },
    { key: "starred", label: "Starred" },
    { key: "total", label: "Total" },
  ];

  const handleClick = (key: TileKey) => {
    setSelectedFeed(null);
    setSelectedCategory(null);
    if (key === "starred") {
      setVirtualFolder("starred");
      setShowUnreadOnly(false);
      navigate("/");
    } else if (key === "unread") {
      setVirtualFolder(null);
      setShowUnreadOnly(true);
      navigate("/");
    } else {
      setVirtualFolder(null);
      setShowUnreadOnly(false);
      navigate("/");
    }
  };

  return (
    <div className={styles.triageGrid}>
      {tiles.map((t) => (
        <div
          key={t.key}
          className={styles.triageTile}
          onClick={() => handleClick(t.key)}
          role="button"
          tabIndex={0}
        >
          <span className={styles.triageValue}>{data[t.key].toLocaleString()}</span>
          <span className={styles.triageLabel}>{t.label}</span>
        </div>
      ))}
    </div>
  );
}
