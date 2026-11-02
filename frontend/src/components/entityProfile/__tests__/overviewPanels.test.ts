import { describe, expect, it } from "vitest";
import {
  ENTITY_PROFILE_CONFIG,
  OVERVIEW_SECTION_PANELS,
  type OverviewPanelKey,
  type OverviewSectionKey,
} from "../entityProfileConfig";

/** Every panel key the type union names, read off the section map. */
const ALL_PANELS = Object.values(OVERVIEW_SECTION_PANELS).flat() as OverviewPanelKey[];

/** The section that hosts a panel; a panel with no host never renders. */
const hostOf = (panel: OverviewPanelKey): OverviewSectionKey | undefined =>
  (Object.keys(OVERVIEW_SECTION_PANELS) as OverviewSectionKey[]).find((s) => OVERVIEW_SECTION_PANELS[s]?.includes(panel));

/**
 * A type lists its signal panels (overviewPanels) and its rows
 * (overviewSections) separately, and OVERVIEW_SECTION_PANELS says which row
 * hosts which panel. The three must agree, or a panel is configured but never
 * drawn, or a row opens onto nothing.
 */
describe("Overview panels against sections", () => {
  it("the section map names each panel once", () => {
    expect(new Set(ALL_PANELS).size).toBe(ALL_PANELS.length);
  });

  it("every panel a type lists is hosted by a row the type has", () => {
    for (const [type, config] of Object.entries(ENTITY_PROFILE_CONFIG)) {
      for (const panel of config.overviewPanels) {
        const host = hostOf(panel);
        expect(host, `${type}: ${panel} has no hosting section`).toBeDefined();
        expect(config.overviewSections, `${type}: ${panel} is hosted by ${host}, which the type lacks`).toContain(host);
      }
    }
  });

  it("every panel-hosting row a type has carries at least one of its panels", () => {
    for (const [type, config] of Object.entries(ENTITY_PROFILE_CONFIG)) {
      for (const section of config.overviewSections) {
        const hosted = OVERVIEW_SECTION_PANELS[section];
        if (!hosted) continue;
        expect(
          hosted.some((p) => config.overviewPanels.includes(p)),
          `${type}: row ${section} hosts only panels the type does not list`,
        ).toBe(true);
      }
    }
  });

  it("a type lists no panel twice", () => {
    for (const [type, config] of Object.entries(ENTITY_PROFILE_CONFIG)) {
      expect(new Set(config.overviewPanels).size, type).toBe(config.overviewPanels.length);
    }
  });
});
