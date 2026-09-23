import styles from "./Skeleton.module.css";

const bone = styles.bone;

/** Skeleton for compact/expanded entry list rows */
export function EntryListSkeleton({ count = 8 }: { count?: number }) {
  return (
    <div className={styles.entryList}>
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className={styles.entryRow}>
          <div className={`${bone} ${styles.entryFavicon}`} />
          <div className={styles.entryBody}>
            <div className={`${bone} ${styles.entryTitle}`} style={i % 3 === 1 ? { width: "55%" } : i % 3 === 2 ? { width: "85%" } : undefined} />
            <div className={`${bone} ${styles.entryMeta}`} style={i % 2 === 1 ? { width: "30%" } : undefined} />
          </div>
        </div>
      ))}
    </div>
  );
}

/** Skeleton for magazine/card grid view */
export function MagazineSkeleton({ count = 6 }: { count?: number }) {
  return (
    <div className={styles.magazineGrid}>
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className={styles.magazineCard}>
          <div className={`${bone} ${styles.magazineImage}`} />
          <div className={styles.magazineBody}>
            <div className={`${bone} ${styles.entryMeta}`} style={{ width: "45%" }} />
            <div className={`${bone} ${styles.entryTitle}`} style={i % 2 === 1 ? { width: "60%" } : { width: "90%" }} />
            <div className={`${bone} ${styles.entryMeta}`} style={{ width: "75%" }} />
          </div>
        </div>
      ))}
    </div>
  );
}

/** Skeleton for workbench entity table rows */
export function TableSkeleton({ columns = 4, rows = 8 }: { columns?: number; rows?: number }) {
  const widths = ["35%", "20%", "15%", "12%", "10%", "18%"];
  return (
    <div className={styles.table}>
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className={styles.tableRow}>
          {Array.from({ length: columns }, (_, c) => (
            <div
              key={c}
              className={`${bone} ${styles.tableCell}`}
              style={{ width: widths[c % widths.length], opacity: 0.7 + (c === 0 ? 0.3 : 0) }}
            />
          ))}
        </div>
      ))}
    </div>
  );
}

/** Skeleton for triage priority queue items */
export function TriageSkeleton({ count = 4 }: { count?: number }) {
  return (
    <div className={styles.triageList}>
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className={`${bone} ${styles.triageCard}`} />
      ))}
    </div>
  );
}

/** Skeleton for correlation event groups */
export function CorrelationSkeleton({ count = 3 }: { count?: number }) {
  return (
    <div className={styles.corrList}>
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className={`${bone} ${styles.corrCard}`} />
      ))}
    </div>
  );
}

/** Skeleton for stat-grid widgets (e.g. OverviewWidget) */
export function WidgetStatSkeleton() {
  return (
    <div className={styles.widgetFill}>
      <div className={styles.widgetStatGrid}>
        {Array.from({ length: 6 }, (_, i) => (
          <div key={i} className={`${bone} ${styles.widgetStatCell}`} />
        ))}
      </div>
    </div>
  );
}

/** Skeleton for chart widgets */
export function WidgetChartSkeleton() {
  return (
    <div className={styles.widgetFill}>
      <div className={`${bone} ${styles.widgetChart}`} />
    </div>
  );
}

/** Skeleton for list-style widgets */
export function WidgetListSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className={styles.widgetFill}>
      <div className={styles.widgetListCol}>
        {Array.from({ length: rows }, (_, i) => (
          <div key={i} className={`${bone} ${styles.widgetListRow}`} style={i % 2 === 1 ? { width: "80%" } : undefined} />
        ))}
      </div>
    </div>
  );
}
