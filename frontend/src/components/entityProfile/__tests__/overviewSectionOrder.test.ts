import { describe, expect, it } from "vitest";
import {
  ENTITY_PROFILE_CONFIG,
  OVERVIEW_SECTION_ORDER,
  orderedOverviewSections,
  resolveOpenSections,
  type OverviewSectionKey,
} from "../entityProfileConfig";

const SECTIONS: OverviewSectionKey[] = ["context", "exploit", "affected", "reading", "activity", "workspace"];

/**
 * Which rows are open comes from the stored choice read against the rows the
 * page has now: every row starts closed, stale ids drop, and nothing the page
 * lacks is ever handed back to be stored.
 */
describe("resolveOpenSections", () => {
  it("opens every row in Everything mode, whatever is stored", () => {
    expect(resolveOpenSections([], SECTIONS, "everything")).toEqual(SECTIONS);
  });

  it("starts with every row closed when nothing is stored", () => {
    expect(resolveOpenSections(undefined, SECTIONS, "brief")).toEqual([]);
  });

  it("shows the stored choice in page order", () => {
    expect(resolveOpenSections(["reading", "exploit"], SECTIONS, "brief")).toEqual(["exploit", "reading"]);
  });

  it("drops an id the page no longer has", () => {
    const visitorPage = SECTIONS.filter((k) => k !== "workspace");
    expect(resolveOpenSections(["context", "renamed_row", "workspace"], visitorPage, "brief")).toEqual(["context"]);
  });
});

/**
 * Every profile stacks its Overview rows in the same order, whatever rows the
 * type has: Context directly under the brief, Stories & reading,
 * Activity and Workspace last. The per-type config only says which rows exist.
 */
describe("Overview section order", () => {
  it("puts Context first and reading, activity, workspace last for every type", () => {
    for (const [type, config] of Object.entries(ENTITY_PROFILE_CONFIG)) {
      const rows = orderedOverviewSections(config.overviewSections);
      // A campaign is an internal object no enrichment source applies to, so
      // it has no Context row; every other type leads with it.
      if (type !== "campaign") expect(rows[0], type).toBe("context");
      expect(rows.slice(-3), type).toEqual(["reading", "activity", "workspace"]);
    }
  });

  it("orders a type's rows by the shared list, not by how the config spells them", () => {
    const shuffled: OverviewSectionKey[] = ["workspace", "reading", "victims", "activity", "context", "infrastructure"];
    expect(orderedOverviewSections(shuffled)).toEqual(["context", "victims", "infrastructure", "reading", "activity", "workspace"]);
  });

  it("the config literals already read in the shared order", () => {
    for (const [type, config] of Object.entries(ENTITY_PROFILE_CONFIG)) {
      expect(config.overviewSections, type).toEqual(orderedOverviewSections(config.overviewSections));
    }
  });

  it("the shared list names every section key once", () => {
    expect(new Set(OVERVIEW_SECTION_ORDER).size).toBe(OVERVIEW_SECTION_ORDER.length);
  });
});
