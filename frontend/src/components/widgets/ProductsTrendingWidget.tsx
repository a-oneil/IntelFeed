import { useNavigate } from "react-router-dom";
import { useTrendingProducts } from "@/hooks/useWidgetEntityData";
import { useIntelStore } from "@/stores/intelStore";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

export default function ProductsTrendingWidget({ config }: Props) {
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const params = date_from
    ? { date_from, ...(date_to ? { date_to } : {}), limit: 10 }
    : { limit: 10 };
  const { data, isLoading } = useTrendingProducts(params);
  const navigate = useNavigate();
  const selectEntity = useIntelStore((s) => s.selectEntity);

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.length === 0) return <div className={styles.noData}>No trending products</div>;

  return (
    <div className={styles.list}>
      {data.map((product) => (
        <button
          key={product.id}
          className={styles.listItemClickable}
          onClick={() => { selectEntity("product", product.id, product.name); navigate("/workbench/explore"); }}
        >
          <div className={styles.listItemMain}>
            <span className={styles.actorName}>{product.name}</span>
            {product.vendor_name && <Chip truncate className={styles.tagSmall}>{product.vendor_name}</Chip>}
            {product.product_type && <Chip truncate className={styles.tagSmall}>{product.product_type}</Chip>}
          </div>
          <div className={styles.listItemMeta}>
            {product.entry_count} entr{product.entry_count !== 1 ? "ies" : "y"}
          </div>
        </button>
      ))}
    </div>
  );
}
