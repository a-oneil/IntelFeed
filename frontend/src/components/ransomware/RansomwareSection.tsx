import { useCallback, useState } from "react";

import { PageHeader, RailToggle, Segmented } from "@/components/primitives";
import { ResizeHandle } from "@/components/ResizeHandle";
import { useRailWidth } from "@/hooks/useRailWidth";
import { useRansomwareStats } from "@/hooks/useRansomware";
import { useIntelStore } from "@/stores/intelStore";
import { useUIStore } from "@/stores/uiStore";

import { ALL_TIME_DAYS, DEFAULT_LEAK_FILTERS, type LeakFilters } from "./leakFilters";
import { LeakWatchFeed } from "./LeakWatchFeed";
import { LeakWatchRail } from "./LeakWatchRail";
import { LANDSCAPE_RANGES, RansomwareLandscape } from "./RansomwareLandscape";
import styles from "./RansomwareSection.module.css";

type Tab = "feed" | "landscape";

export function RansomwareSection() {
  const [tab, setTab] = useState<Tab>("feed");
  const selectEntity = useIntelStore((s) => s.selectEntity);
  const pivotToGroup = (groupId: string, groupName?: string) => selectEntity("threat_actor", groupId, groupName);

  // The rail and the feed are two columns of one surface, so the filter set
  // they share is owned here rather than inside either of them.
  const [filters, setFilters] = useState<LeakFilters>(DEFAULT_LEAK_FILTERS);
  const patch = useCallback((p: Partial<LeakFilters>) => setFilters((s) => ({ ...s, ...p })), []);
  // "All" is an unbounded window for the disclosure list, but the stat tiles and
  // facet counts still need a finite one — a year, as before the state lift.
  const { data: stats } = useRansomwareStats(filters.days >= ALL_TIME_DAYS ? 365 : filters.days);

  const railCollapsed = useUIStore((s) => s.ransomwareFacetsCollapsed);
  const setRailCollapsed = useUIStore((s) => s.setRansomwareFacetsCollapsed);
  const railWidth = useRailWidth("ransomware-facets", { default: 248, min: 190, max: 460 });

  // Landscape's window switch lives in the page header alongside the tab
  // switch, so `days` is owned here rather than inside the chart column.
  const [landscapeDays, setLandscapeDays] = useState(90);

  const onFeed = tab === "feed";

  return (
    /* Two-column shell: the facet rail runs the full height of the content area
       and the page header sits to its right, the same seating the search page
       and the rule library use. */
    <div className={styles.shell}>
      {onFeed && (
        <>
          <aside
            className={`${styles.rail} ${railCollapsed ? styles.railCollapsed : ""}`}
            aria-label="Leak watch filters"
            style={railCollapsed ? undefined : railWidth.style}
          >
            <LeakWatchRail filters={filters} onChange={patch} stats={stats} />
          </aside>
          {!railCollapsed && (
            <ResizeHandle
              label="ransomware filters"
              className={styles.railResizer}
              {...railWidth.handleProps}
            />
          )}
          <RailToggle
            side="left"
            collapsed={railCollapsed}
            onToggle={() => setRailCollapsed(!railCollapsed)}
            label="ransomware filters"
            verbs={["Show", "Hide"]}
            className={styles.railToggle}
          />
        </>
      )}

      <div className={styles.shellMain}>
        <PageHeader
          title="Ransomware"
          className={styles.pageHeader}
          actions={
            <Segmented<Tab>
              label="Ransomware views"
              role="tablist"
              value={tab}
              onChange={setTab}
              options={[
                { value: "feed", label: "Leak Watch" },
                { value: "landscape", label: "Landscape" },
              ]}
            />
          }
          /* Each tab's own filter belongs in the header's controls row like
             every other workbench page — both used to sit in an orphan band
             between the title and the content. */
          controls={
            onFeed ? (
              <input
                className={styles.search}
                value={filters.q}
                onChange={(e) => patch({ q: e.target.value })}
                placeholder="Filter victims, groups, domains…"
                aria-label="Search victims"
              />
            ) : (
              <Segmented
                label="Time range"
                size="sm"
                value={String(landscapeDays)}
                onChange={(v) => setLandscapeDays(Number(v))}
                options={LANDSCAPE_RANGES}
              />
            )
          }
        />
        <div className={styles.body}>
          {onFeed ? (
            <LeakWatchFeed filters={filters} onChange={patch} stats={stats} onPivotGroup={pivotToGroup} />
          ) : (
            <RansomwareLandscape days={landscapeDays} onPivotGroup={pivotToGroup} />
          )}
        </div>
      </div>
    </div>
  );
}
