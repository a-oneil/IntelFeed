import { useNavigate } from "react-router-dom";
import { useActiveCampaigns } from "@/hooks/useWidgetEntityData";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { getTLPColor } from "@/utils/colorSchemes";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

export default function ActiveCampaignsWidget({ config }: Props) {
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const params = date_from
    ? { date_from, ...(date_to ? { date_to } : {}), limit: 10 }
    : { limit: 10 };
  const { data, isLoading } = useActiveCampaigns(params);
  const navigate = useNavigate();

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.length === 0) return <div className={styles.noData}>No active campaigns</div>;

  return (
    <div className={styles.list}>
      {data.map((campaign) => (
        <button
          key={campaign.id}
          className={styles.listItemClickable}
          onClick={() => navigate(`/workbench/campaign/${campaign.id}`)}
        >
          <div className={styles.listItemMain}>
            <span
              aria-label={campaign.tlp_marking}
              title={campaign.tlp_marking}
              style={{
                display: "inline-block",
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: getTLPColor(campaign.tlp_marking, "var(--color-text-muted, #9ca3af)"),
                marginRight: 6,
                flexShrink: 0,
              }}
            />
            <span className={styles.actorName}>{campaign.name}</span>
            <Chip className={styles.tagSmall}>{campaign.status}</Chip>
          </div>
          <div className={styles.listItemMeta}>
            {campaign.entry_count} entr{campaign.entry_count !== 1 ? "ies" : "y"}
          </div>
        </button>
      ))}
    </div>
  );
}
