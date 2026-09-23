import { useNavigate } from "react-router-dom";
import { useTargetedCountries } from "@/hooks/useWidgetEntityData";
import { useIntelStore } from "@/stores/intelStore";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

export default function TargetedCountriesWidget({ config }: Props) {
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const params = date_from
    ? { date_from, ...(date_to ? { date_to } : {}), limit: 10 }
    : { limit: 10 };
  const { data, isLoading } = useTargetedCountries(params);
  const navigate = useNavigate();
  const selectEntity = useIntelStore((s) => s.selectEntity);

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.length === 0) return <div className={styles.noData}>No targeted countries</div>;

  return (
    <div className={styles.list}>
      {data.map((country) => (
        <button
          key={country.id}
          className={styles.listItemClickable}
          onClick={() => { selectEntity("country", country.id, country.name); navigate("/workbench/explore"); }}
        >
          <div className={styles.listItemMain}>
            <span className={styles.actorName}>{country.name}</span>
            {country.iso_code && <Chip truncate className={styles.tagSmall}>{country.iso_code}</Chip>}
            {country.region && <Chip truncate className={styles.tagSmall}>{country.region}</Chip>}
          </div>
          <div className={styles.listItemMeta}>
            {country.entry_count} entr{country.entry_count !== 1 ? "ies" : "y"}
          </div>
        </button>
      ))}
    </div>
  );
}
