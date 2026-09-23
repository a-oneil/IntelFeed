import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";

import ThreatBoard from "@/components/ThreatBoard";
import { PageHeader, Segmented } from "@/components/primitives";
import { useExposureBoard } from "@/hooks/useWatchlist";
import { FollowView } from "./ExposurePage";
import { VulnTiles, VulnLongTail } from "@/components/VulnLandscape";
import styles from "./ThreatsPage.module.css";

/** The Threats page: triage gets its own address.

    Tabs: the ranked briefing board faceted by entity type, plus the
    Vulnerabilities tab — CVE rows as board citizens (exploitation-ranked
    briefing rows, posture-derived actions, the board's own state machine),
    with Vendor Watch's tiles re-idiomed above and its exhaustive stack table
    as the long tail below. Stack management lives in the Manage-stack
    slide-over — a setting of the view, not a destination. */

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

  // The exposure board backs the Vulnerabilities tab and the slide-over; only
  // fetch it once that tab is in play.
  const { data: exposure, isLoading: exposureLoading } = useExposureBoard({ enabled: tab === "vulns" });

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
        subtitle="Recently reported ranked by attention and new tradecraft."
      />

      {tab !== "vulns" ? (
        <ThreatBoard facet={TAB_FACET[tab]} />
      ) : (
        <div className={styles.vulnsBody}>
          {exposure && <VulnTiles data={exposure} onFollow={() => setManageStack(true)} />}
          <ThreatBoard facet="vulns" />
          {exposureLoading && <div className={styles.state}>Loading your stack…</div>}
          {exposure && <VulnLongTail data={exposure} />}
        </div>
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
