import { useTopTags } from "@/hooks/useWidgetTriageData";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";
import { contrastText } from "@/utils/contrast";
import { useOpenSavedSearch } from "@/hooks/useOpenSavedSearch";
import { useIsVisitor } from "@/stores/authStore";

interface Props {
  config: Record<string, unknown>;
}

export default function TopTagsWidget({ config }: Props) {
  const openSavedSearch = useOpenSavedSearch();
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const limit = (config.limit as number) || 15;
  const params = {
    limit,
    ...(date_from ? { date_from } : {}),
    ...(date_to ? { date_to } : {}),
  };
  const { data, isLoading } = useTopTags(params);
  const isVisitor = useIsVisitor();

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.length === 0) return <div className={styles.noData}>No tagged entries</div>;

  const handleTagClick = (tagName: string) => {
    openSavedSearch({
      id: `top-tag-${tagName}`,
      name: `tag:${tagName}`,
      display_name: null,
      query: "",
      filters: { tags: [tagName] },
      unread_count: 0,
      total_count: 0,
      created_at: new Date().toISOString(),
    });
  };

  return (
    <div className={styles.tagPills}>
      {data.map((t) => (
        <Chip
          key={t.id}
          tone="solid"
          pill
          tint={t.color}
          fg={contrastText(t.color)}
          style={
            {
              "--tag-scrim":
                contrastText(t.color) === "#000000"
                  ? "rgba(255, 255, 255, 0.38)"
                  : "rgba(0, 0, 0, 0.25)",
            } as React.CSSProperties
          }
          className={styles.tagPill}
          // Opening a tag is a saved search, which a visitor doesn't have.
          onClick={isVisitor ? undefined : () => handleTagClick(t.name)}
          title={`${t.name}: ${t.entry_count} entries`}
        >
          <span>{t.name}</span>
          <span className={styles.tagPillCount}>{t.entry_count}</span>
        </Chip>
      ))}
    </div>
  );
}
