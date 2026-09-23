/** ProfileTabs — config-driven tab bar. Scrolls horizontally for high-tab-count types. */
import { TAB_HINTS, TAB_LABELS, type TabKey } from "./entityProfileConfig";
import { Hint } from "@/components/primitives";
import styles from "./entityProfile.module.css";

export function ProfileTabs({
  tabs,
  active,
  counts,
  onChange,
}: {
  tabs: TabKey[];
  active: TabKey;
  counts?: Partial<Record<TabKey, number>>;
  onChange: (tab: TabKey) => void;
}) {
  return (
    <div className={styles.tabBar} role="tablist">
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
  );
}
