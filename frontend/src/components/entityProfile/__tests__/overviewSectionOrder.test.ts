import { describe, expect, it } from "vitest";
import {
  ENTITY_PROFILE_CONFIG,
  OVERVIEW_SECTION_ORDER,
  orderedOverviewSections,
  resolveOpenSections,
  type OverviewSectionKey,
} from "../entityProfileConfig";

const SECTIONS: OverviewSectionKey[] = ["context", "exploit", "affected", "reading", "activity", "workspace"];
const DEFAULTS: OverviewSectionKey[] = ["context"];

/**
 * Which rows are open comes from the stored choice read against the rows the
 * page has now: stale ids drop, rows added later open if the config says so,
 * and nothing the page lacks is ever handed back to be stored.
 */
describe("resolveOpenSections", () => {
  it("opens every row in Everything mode, whatever is stored", () => {
    expect(resolveOpenSections({ open: [], seen: SECTIONS }, SECTIONS, DEFAULTS, "everything")).toEqual(SECTIONS);
  });

  it("shows the defaults when nothing is stored, limited to the rows the page has", () => {
    expect(resolveOpenSections(undefined, SECTIONS, ["context", "victims"], "brief")).toEqual(["context"]);
  });

  it("shows the stored choice in page order and keeps a closed default closed", () => {
    expect(resolveOpenSections({ open: ["reading", "exploit"], seen: SECTIONS }, SECTIONS, DEFAULTS, "brief")).toEqual([
      "exploit",
      "reading",
    ]);
  });

  it("drops an id the page no longer has", () => {
    const stored = { open: ["context", "renamed_row", "workspace"], seen: [...SECTIONS, "renamed_row"] };
    const visitorPage = SECTIONS.filter((k) => k !== "workspace");
    expect(resolveOpenSections(stored, visitorPage, DEFAULTS, "brief")).toEqual(["context"]);
  });

  it("opens a default-open row the stored choice never saw", () => {
    const before = SECTIONS.filter((k) => k !== "affected");
    const stored = { open: ["reading"], seen: before };
    expect(resolveOpenSections(stored, SECTIONS, ["context", "affected"], "brief")).toEqual(["affected", "reading"]);
  });

  it("does not open a new row the config leaves closed", () => {
    const stored = { open: ["reading"], seen: SECTIONS.filter((k) => k !== "affected") };
    expect(resolveOpenSections(stored, SECTIONS, DEFAULTS, "brief")).toEqual(["reading"]);
  });

  it("reads a bare stored list as its open rows with every current row seen", () => {
    expect(resolveOpenSections(["reading", "old_row"], SECTIONS, ["context", "affected"], "brief")).toEqual(["reading"]);
  });
});

/**
 * Every profile stacks its Overview rows in the same order, whatever rows the
 * type has: Context directly under the facts strip, Stories & reading,
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
