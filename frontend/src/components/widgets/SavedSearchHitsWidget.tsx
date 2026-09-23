import { useSavedSearchHits } from "@/hooks/useWidgetTriageData";
import { useSavedSearches } from "@/hooks/useSearch";
import { useOpenSavedSearch } from "@/hooks/useOpenSavedSearch";
import { WidgetListSkeleton } from "@/components/Skeleton";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

export default function SavedSearchHitsWidget(_: Props) {
  const openSavedSearch = useOpenSavedSearch();
  const { data, isLoading } = useSavedSearchHits();
  const { data: savedSearches } = useSavedSearches();

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.length === 0) {
    return <div className={styles.noData}>No saved searches yet</div>;
  }

  const handleClick = (id: string) => {
    const full = savedSearches?.find((x) => x.id === id);
    if (full) openSavedSearch(full);
  };

  return (
    <div className={styles.list}>
      {data.map((s) => (
        <div
          key={s.id}
          className={styles.savedSearchRow}
          onClick={() => handleClick(s.id)}
          role="button"
          tabIndex={0}
        >
          <span className={styles.savedSearchName} title={s.query || s.name}>
            {s.name}
          </span>
          <span className={styles.savedSearchCounts}>
            <span className={s.unread > 0 ? styles.savedSearchUnread : undefined}>
              {s.unread.toLocaleString()}
            </span>
            {" / "}
            {s.total.toLocaleString()}
          </span>
        </div>
      ))}
    </div>
  );
}
