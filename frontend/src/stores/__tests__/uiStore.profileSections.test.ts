import { beforeEach, describe, expect, it } from "vitest";

import { resolveOpenSections, type OverviewSectionKey } from "@/components/entityProfile/entityProfileConfig";
import { useUIStore } from "@/stores/uiStore";

const CVE_SECTIONS: OverviewSectionKey[] = ["context", "exploit", "affected", "reading", "activity", "workspace"];
const TTP_SECTIONS: OverviewSectionKey[] = ["context", "catalog", "reading", "activity", "workspace"];

/**
 * The entity profile Overview remembers which section rows are open per
 * entity type, and the Brief / Everything switch sits on top of that: closing
 * a row while everything is open has to land on a real set, in Brief. Each
 * entry also records which rows the type had, so a row added later can open.
 */
describe("uiStore profile Overview sections", () => {
  beforeEach(() => {
    useUIStore.setState({ profileOpenSections: {}, profileOverviewMode: "brief" });
  });

  it("stores the open set per entity type, seeded from what the tab shows, with the rows it saw", () => {
    const { setProfileSectionOpen } = useUIStore.getState();
    setProfileSectionOpen("cve", "activity", true, ["context"], CVE_SECTIONS);
    setProfileSectionOpen("threat_actor", "reading", true, ["victims"], ["context", "victims", "reading"]);

    expect(useUIStore.getState().profileOpenSections).toEqual({
      cve: { open: ["context", "activity"], seen: CVE_SECTIONS },
      threat_actor: { open: ["victims", "reading"], seen: ["context", "victims", "reading"] },
    });
  });

  it("does not duplicate a key that is already open", () => {
    useUIStore.getState().setProfileSectionOpen("cve", "context", true, ["context"], CVE_SECTIONS);
    expect(useUIStore.getState().profileOpenSections.cve).toEqual({ open: ["context"], seen: CVE_SECTIONS });
  });

  it("closing a row removes it and leaves the rest", () => {
    useUIStore.getState().setProfileSectionOpen("cve", "context", false, ["context", "activity"], CVE_SECTIONS);
    expect(useUIStore.getState().profileOpenSections.cve).toEqual({ open: ["activity"], seen: CVE_SECTIONS });
  });

  it("closing a row while Everything is open drops back to Brief with the other rows kept", () => {
    useUIStore.getState().setProfileOverviewMode("everything");
    expect(useUIStore.getState().profileOverviewMode).toBe("everything");

    // The tab passes the full section list as what is currently open.
    useUIStore.getState().setProfileSectionOpen("ttp", "workspace", false, ["catalog", "context", "reading", "activity", "workspace"], TTP_SECTIONS);

    expect(useUIStore.getState().profileOverviewMode).toBe("brief");
    expect(useUIStore.getState().profileOpenSections.ttp).toEqual({
      open: ["catalog", "context", "reading", "activity"],
      seen: TTP_SECTIONS,
    });
  });

  it("a type with no entry stays absent, so the tab falls back to its config defaults", () => {
    useUIStore.getState().setProfileSectionOpen("cve", "activity", true, [], CVE_SECTIONS);
    expect("malware" in useUIStore.getState().profileOpenSections).toBe(false);
  });

  it("a visitor toggling a row does not resurrect the Workspace row their page lacks", () => {
    // An analyst left Workspace open on this browser; a visitor's page has no Workspace row.
    useUIStore.setState({ profileOpenSections: { cve: { open: ["context", "workspace"], seen: CVE_SECTIONS } } });
    const visitorSections = CVE_SECTIONS.filter((k) => k !== "workspace");
    const defaults: OverviewSectionKey[] = ["context"];

    const shown = resolveOpenSections(useUIStore.getState().profileOpenSections.cve, visitorSections, defaults, "brief");
    expect(shown).toEqual(["context"]);

    // The tab passes what it shows, so the toggle writes back only rows the page has.
    useUIStore.getState().setProfileSectionOpen("cve", "reading", true, shown, visitorSections);
    expect(useUIStore.getState().profileOpenSections.cve).toEqual({ open: ["context", "reading"], seen: visitorSections });
    expect(resolveOpenSections(useUIStore.getState().profileOpenSections.cve, visitorSections, defaults, "brief")).toEqual([
      "context",
      "reading",
    ]);
  });
});
