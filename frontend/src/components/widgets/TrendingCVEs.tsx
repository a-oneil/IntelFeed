import { useNavigate } from "react-router-dom";
import { useTrendingCVEs } from "@/hooks/useWidgetData";
import { useIntelStore } from "@/stores/intelStore";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";
import { cvssChipColors } from "@/utils/severity";

interface Props {
  config: Record<string, unknown>;
}

export default function TrendingCVEs({ config }: Props) {
  const limit = (config.limit as number) || 10;
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const { data, isLoading } = useTrendingCVEs({ limit, ...(date_from ? { date_from } : {}), ...(date_to ? { date_to } : {}) });
  const navigate = useNavigate();
  const selectEntity = useIntelStore((s) => s.selectEntity);

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.length === 0) return <div className={styles.noData}>No trending CVEs</div>;

  return (
    <div className={styles.list}>
      {data.map((cve) => (
        <button
          key={cve.id}
          className={styles.listItemClickable}
          onClick={() => { selectEntity("cve", cve.id, cve.cve_id); navigate("/workbench/explore"); }}
        >
          <div className={styles.listItemMain}>
            <span className={styles.cveId}>{cve.cve_id}</span>
            {cve.cvss_score !== null && (
              <Chip
                tone="solid"
                {...cvssChipColors(cve.cvss_score)}
                className={styles.countChip}
              >
                {Number(cve.cvss_score).toFixed(1)}
              </Chip>
            )}
          </div>
          <div className={styles.listItemMeta}>
            {cve.mention_count} mention{cve.mention_count !== 1 ? "s" : ""}
          </div>
        </button>
      ))}
    </div>
  );
}
