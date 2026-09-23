import { useNavigate } from "react-router-dom";
import { useBoardOverview } from "@/hooks/useWidgetBoardData";
import { useIntelStore } from "@/stores/intelStore";
import { WidgetChartSkeleton } from "@/components/Skeleton";
import { DeltaText, Sparkline, entityColorVar, entityLabel } from "./boardShared";
import styles from "./widgets.module.css";

interface Props {
  config: Record<string, unknown>;
}

/** Workbench section each entity tile deep-links into. */
const ENTITY_SECTION: Record<string, string> = {
  threat_actor: "threat_actors",
  malware: "malware",
  tool: "tools",
  cve: "cves",
  ttp: "ttps",
  vendor: "vendors",
  product: "products",
  country: "countries",
};

export default function OverviewRowWidget({ config }: Props) {
  const date_from = config.date_from as string | undefined;
  const date_to = config.date_to as string | undefined;
  const { data, isLoading } = useBoardOverview({ date_from, date_to });
  const navigate = useNavigate();
  const setActiveSection = useIntelStore((s) => s.setActiveSection);

  if (isLoading) return <WidgetChartSkeleton />;
  if (!data) return <div className={styles.noData}>No overview data</div>;

  const entrySeries = data.series.entries.map((p) => p.count);
  const detectionSeries = data.series.detections.map((p) => p.count);
  const sortedEntities = [...data.entities].sort((a, b) =>
    entityLabel(a.type).localeCompare(entityLabel(b.type)),
  );

  const tiles = [
    {
      key: "entries",
      label: "New entries",
      value: data.headline.entries.count,
      trend: data.headline.entries.trend,
      suffix: "%",
      series: entrySeries,
      goodWhenDown: false,
      onClick: () => navigate("/"),
    },
    {
      key: "radar",
      label: "Radar hits",
      value: data.headline.radar.count,
      trend: undefined,
      suffix: "",
      series: [],
      goodWhenDown: false,
      onClick: () => navigate("/priority-queue"),
    },
    {
      key: "unread",
      label: "Unread",
      value: data.headline.unread.count,
      trend: undefined,
      suffix: "",
      series: [],
      goodWhenDown: true,
      onClick: () => navigate("/"),
    },
    {
      key: "detections",
      label: "New detections",
      value: data.headline.detections.count,
      trend: data.headline.detections.trend,
      suffix: "%",
      series: detectionSeries,
      goodWhenDown: false,
      onClick: () => navigate("/workbench/explore?section=rules"),
    },
  ];

  return (
    <div>
      <div className={styles.kpiRow}>
        {tiles.map((t) => (
          <div key={t.key} className={styles.kpiTile}>
            <p className={styles.kpiLabel}>{t.label}</p>
            <div className={styles.kpiValue}>{t.value.toLocaleString()}</div>
            <div className={styles.kpiDelta}>
              {t.trend !== undefined ? (
                <DeltaText value={t.trend} suffix={`${t.suffix} vs prior`} goodWhenDown={t.goodWhenDown} />
              ) : (
                <span className={styles.deltaFlat}>current</span>
              )}
            </div>
            {t.series.length > 1 && <Sparkline points={t.series} width={104} height={24} />}
          </div>
        ))}
      </div>

      <div className={styles.entityStrip}>
        {sortedEntities.map((e) => (
          <button
            key={e.type}
            className={styles.entityTile}
            onClick={() => {
              const section = ENTITY_SECTION[e.type];
              if (section) setActiveSection(section as Parameters<typeof setActiveSection>[0]);
              navigate("/workbench/explore");
            }}
            title={`${entityLabel(e.type)} first seen in this window`}
          >
            <span className={styles.entityTileLabel}>
              <span className={styles.entityDot} style={{ background: entityColorVar(e.type) }} />
              {entityLabel(e.type)}
            </span>
            <p className={styles.entityTileValue}>{e.count.toLocaleString()}</p>
            <span className={styles.entityTileDelta}>
              <DeltaText value={e.trend} suffix="% vs prior" />
            </span>
          </button>
        ))}
      </div>
    </div>
  );
}
