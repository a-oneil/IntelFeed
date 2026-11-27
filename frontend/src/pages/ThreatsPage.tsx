import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";

import ThreatBoard from "@/components/ThreatBoard";
import { PageHeader, Segmented } from "@/components/primitives";
import { useExposureBoard } from "@/hooks/useWatchlist";
import { FollowView } from "./ExposurePage";
import styles from "./ThreatsPage.module.css";

/** The Threats page: threat triage on its own route.

    Tabs: the ranked briefing board filtered by entity type, plus the Vulnerabilities tab, which shows CVEs as rows on the same board (ranked by exploitation, with actions derived from stack posture, using the board's own row states).

    Stack management is in the Manage-stack slide-over, because it is a setting of this view rather than a page of its own; the exposure board is fetched only for that slide-over. */

type Tab = "all" | "actors" | "malware" | "vulns";

const TABS: { value: Tab; label: string }[] = [
  { value: "all", label: "All" },
  { value: "actors", label: "Actors" },
  { value: "malware", label: "Malware" },
  { value: "vulns", label: "Vulnerabilities" },
];

const TAB_FACET: Record<Exclude<Tab, "vulns">, string> = {
  all: "all",
  actors: "threat_actor",
  malware: "malware",
};

function parseTab(raw: string | null): Tab {
  return raw === "actors" || raw === "malware" || raw === "vulns" ? raw : "all";
}

export function ThreatsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const tab = parseTab(searchParams.get("tab"));
  const [manageStack, setManageStack] = useState(false);

  // The exposure board backs the Manage-stack slide-over, which only the Vulnerabilities tab offers, so fetch it only while that tab is open.
  const { data: exposure } = useExposureBoard({ enabled: tab === "vulns" });

  const setTab = useCallback(
    (next: Tab) => {
      setSearchParams(
        (prev) => {
          const p = new URLSearchParams(prev);
          if (next === "all") p.delete("tab");
          else p.set("tab", next);
          return p;
        },
        { replace: true }
      );
    },
    [setSearchParams]
  );

  useEffect(() => {
    if (!manageStack) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setManageStack(false);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [manageStack]);

  return (
    <div className={styles.page}>
      <PageHeader
        title="Threats"
        flush
        actions={
          <div className={styles.headerActions}>
            {tab === "vulns" && (
              <button className={styles.manageBtn} onClick={() => setManageStack(true)}>
                Manage stack <span className="caret-glyph">▸</span>
              </button>
            )}
            <Segmented<Tab>
              label="Threats tabs"
              role="tablist"
              value={tab}
              onChange={setTab}
              options={TABS}
            />
          </div>
        }
        subtitle="Recently reported threats, ranked by coverage and new techniques."
      />

      {tab !== "vulns" ? (
        <ThreatBoard facet={TAB_FACET[tab]} />
      ) : (
        <ThreatBoard facet="vulns" />
      )}

      {manageStack && (
        <>
          <div className={styles.backdrop} onClick={() => setManageStack(false)} />
          <div className={styles.slideOver} role="dialog" aria-label="Manage stack">
            <div className={styles.slideHead}>
              <span>Manage stack</span>
              <button className={styles.closeBtn} onClick={() => setManageStack(false)} aria-label="Close">
                ×
              </button>
            </div>
            <div className={styles.slideBody}>
              {exposure ? <FollowView data={exposure} /> : <div className={styles.state}>Loading…</div>}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

export default ThreatsPage;
