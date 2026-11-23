import { beforeEach, describe, expect, it } from "vitest";

import { resolveOpenSections, type OverviewSectionKey } from "@/components/entityProfile/entityProfileConfig";
import { useUIStore } from "@/stores/uiStore";

const CVE_SECTIONS: OverviewSectionKey[] = ["context", "exploit", "affected", "reading", "activity", "workspace"];
const TTP_SECTIONS: OverviewSectionKey[] = ["context", "catalog", "reading", "activity", "workspace"];

/**
 * The entity profile Overview remembers which section rows are open per
 * entity type, and the Brief / Everything switch sits on top of that: closing
 * a row while everything is open has to land on a real set, in Brief.
 */
describe("uiStore profile Overview sections", () => {
  beforeEach(() => {
    useUIStore.setState({ profileOpenSections: {}, profileOverviewMode: "brief" });
  });

  it("stores the open set per entity type, seeded from what the tab shows", () => {
    const { setProfileSectionOpen } = useUIStore.getState();
    setProfileSectionOpen("cve", "activity", true, ["context"]);
    setProfileSectionOpen("threat_actor", "reading", true, []);

    expect(useUIStore.getState().profileOpenSections).toEqual({
      cve: ["context", "activity"],
      threat_actor: ["reading"],
    });
  });

  it("does not duplicate a key that is already open", () => {
    useUIStore.getState().setProfileSectionOpen("cve", "context", true, ["context"]);
    expect(useUIStore.getState().profileOpenSections.cve).toEqual(["context"]);
  });

  it("closing a row removes it and leaves the rest", () => {
    useUIStore.getState().setProfileSectionOpen("cve", "context", false, ["context", "activity"]);
    expect(useUIStore.getState().profileOpenSections.cve).toEqual(["activity"]);
  });

  it("closing a row while Everything is open drops back to Brief with the other rows kept", () => {
    useUIStore.getState().setProfileOverviewMode("everything");
    expect(useUIStore.getState().profileOverviewMode).toBe("everything");

    // The tab passes the full section list as what is currently open.
    useUIStore.getState().setProfileSectionOpen("ttp", "workspace", false, [...TTP_SECTIONS]);

    expect(useUIStore.getState().profileOverviewMode).toBe("brief");
    expect(useUIStore.getState().profileOpenSections.ttp).toEqual(["context", "catalog", "reading", "activity"]);
  });

  it("a visitor toggling a row does not resurrect the Workspace row their page lacks", () => {
    // An analyst left Workspace open on this browser; a visitor's page has no Workspace row.
    useUIStore.setState({ profileOpenSections: { cve: ["context", "workspace"] } });
    const visitorSections = CVE_SECTIONS.filter((k) => k !== "workspace");

    const shown = resolveOpenSections(useUIStore.getState().profileOpenSections.cve, visitorSections, "brief");
    expect(shown).toEqual(["context"]);

    // The tab passes what it shows, so the toggle writes back only rows the page has.
    useUIStore.getState().setProfileSectionOpen("cve", "reading", true, shown);
    expect(useUIStore.getState().profileOpenSections.cve).toEqual(["context", "reading"]);
  });
});
