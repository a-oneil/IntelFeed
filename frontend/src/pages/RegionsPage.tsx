import { useRegions } from "@/hooks/useCountryProfile";
import { AsyncStateLoading, AsyncStateError, AsyncStateEmpty } from "@/components/AsyncState";
import { PageHeader } from "@/components/primitives";
import styles from "./RegionsPage.module.css";

export function RegionsPage() {
  const { data: regions, isLoading, isError, refetch } = useRegions();

  if (isLoading) return <AsyncStateLoading label="Loading regions…" />;
  if (isError)
    return (
      <AsyncStateError
        title="Failed to load regions"
        description="The regions endpoint didn't respond. Check that the API is reachable."
        onRetry={() => refetch()}
      />
    );
  if (!regions || regions.length === 0)
    return <AsyncStateEmpty title="No regions found" description="Countries need a region assigned before they show up here." />;

  const maxArticles = Math.max(...regions.map((r) => r.total_articles), 1);

  return (
    <div className={styles.layout}>
      <PageHeader
        title="Regions"
        flush
        count={regions.length}
        subtitle="Geographic threat landscape overview."
      />

      <div className={styles.regionGrid}>
        {regions.map((region) => (
          <div key={region.region} className={styles.regionCard}>
            <div className={styles.regionName}>{region.region}</div>
            <div className={styles.regionStats}>
              <span>
                <span className={styles.statValue}>{region.country_count}</span> countries
              </span>
              <span>
                <span className={styles.statValue}>{region.total_articles.toLocaleString()}</span> articles
              </span>
            </div>
            <div className={styles.activityBar}>
              <div
                className={styles.activityFill}
                style={{ width: `${(region.total_articles / maxArticles) * 100}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
