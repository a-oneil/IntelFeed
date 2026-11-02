/**
 * ProfileTabs — config-driven tab bar. The tab list scrolls horizontally for
 * high-tab-count types; the trailing control sits outside the tablist and
 * sticks to the bar's right edge, so on a phone it stays in reach while the
 * tabs scroll under it.
 */
import type { ReactNode } from "react";
import { TAB_HINTS, TAB_LABELS, type TabKey } from "./entityProfileConfig";
import { Hint } from "@/components/primitives";
import styles from "./entityProfile.module.css";

export function ProfileTabs({
  tabs,
  active,
  counts,
  onChange,
  trailing,
}: {
  tabs: TabKey[];
  active: TabKey;
  counts?: Partial<Record<TabKey, number>>;
  onChange: (tab: TabKey) => void;
  /** A control for the active tab, pinned to the bar's right edge (outside the tablist). */
  trailing?: ReactNode;
}) {
  return (
    <div className={styles.tabBar}>
      <div className={styles.tabList} role="tablist">
        {tabs.map((tab) => {
          const count = counts?.[tab];
          const hint = TAB_HINTS[tab];
          return (
            <Hint
              key={tab}
              title={hint?.title ?? TAB_LABELS[tab]}
              body={hint?.body ?? ""}
              aside={hint?.aside}
              disabled={!hint}
            >
              <button
                role="tab"
                aria-selected={active === tab}
                className={`${styles.tab} ${active === tab ? styles.tabActive : ""}`}
                onClick={() => onChange(tab)}
              >
                {TAB_LABELS[tab]}
                {count != null && count > 0 && <span className={styles.tabCount}>{count}</span>}
              </button>
            </Hint>
          );
        })}
      </div>
      {trailing && <div className={styles.tabBarTrailing}>{trailing}</div>}
    </div>
  );
}
