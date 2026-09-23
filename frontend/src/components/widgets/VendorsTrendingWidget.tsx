import { useNavigate } from "react-router-dom";
import { useTrendingVendors } from "@/hooks/useWidgetEntityData";
import { useIntelStore } from "@/stores/intelStore";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

export default function VendorsTrendingWidget({ config }: Props) {
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const params = date_from
    ? { date_from, ...(date_to ? { date_to } : {}), limit: 10 }
    : { limit: 10 };
  const { data, isLoading } = useTrendingVendors(params);
  const navigate = useNavigate();
  const selectEntity = useIntelStore((s) => s.selectEntity);

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.length === 0) return <div className={styles.noData}>No trending vendors</div>;

  return (
    <div className={styles.list}>
      {data.map((vendor) => (
        <button
          key={vendor.id}
          className={styles.listItemClickable}
          onClick={() => { selectEntity("vendor", vendor.id, vendor.name); navigate("/workbench/explore"); }}
        >
          <div className={styles.listItemMain}>
            <span className={styles.actorName}>{vendor.name}</span>
            {vendor.vendor_type && <Chip truncate className={styles.tagSmall}>{vendor.vendor_type}</Chip>}
          </div>
          <div className={styles.listItemMeta}>
            {vendor.entry_count} entr{vendor.entry_count !== 1 ? "ies" : "y"}
          </div>
        </button>
      ))}
    </div>
  );
}
