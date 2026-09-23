import { useNavigate } from "react-router-dom";
import { useNewCVEs } from "@/hooks/useWidgetData";
import { useIntelStore } from "@/stores/intelStore";
import { WidgetListSkeleton } from "@/components/Skeleton";
import { Chip } from "@/components/primitives";
import styles from "./widgets.module.css";
import { cvssChipColors } from "@/utils/severity";

interface Props {
  config: Record<string, unknown>;
}

export default function NewCVEsWidget({ config }: Props) {
  const days = (config.days as number) || 7;
  const { data, isLoading } = useNewCVEs(days);
  const navigate = useNavigate();
  const selectEntity = useIntelStore((s) => s.selectEntity);

  if (isLoading) return <WidgetListSkeleton />;
  if (!data || data.length === 0)
    return <div className={styles.noData}>No new CVEs in the last {days} days</div>;

  return (
    <div className={styles.list}>
      {data.map((cve) => {
        const exploited =
          cve.exploit_availability === "weaponized" ||
          cve.exploit_availability === "active_exploitation";
        return (
          <button
            key={cve.id}
            className={styles.listItemClickable}
            onClick={() => {
              selectEntity("cve", cve.id, cve.cve_id);
              navigate("/workbench/explore");
            }}
          >
            <div className={styles.listItemMain}>
              <span className={styles.cveId}>{cve.cve_id}</span>
              {cve.cvss_score !== null && (
                <Chip
                  tone="solid"
                  {...cvssChipColors(cve.cvss_score)}
                  className={styles.countChip}
                >
                  {cve.cvss_score.toFixed(1)}
                </Chip>
              )}
              {exploited && <Chip className={styles.tagSmall}>exploited</Chip>}
            </div>
            <div className={styles.listItemMeta}>
              {cve.mention_count > 0
                ? `${cve.mention_count} mention${cve.mention_count !== 1 ? "s" : ""}`
                : "No mentions yet"}
            </div>
          </button>
        );
      })}
    </div>
  );
}
