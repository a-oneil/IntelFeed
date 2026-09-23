import { beforeEach, describe, expect, it } from "vitest";
import { useUIStore } from "@/stores/uiStore";
import {
  layoutMapsEqual,
  parseTableLayouts,
  toTableLayoutMap,
  type SharedTableLayout,
} from "../tableLayout";

const layout = (over: Partial<SharedTableLayout> = {}): SharedTableLayout => ({
  columnVisibility: {},
  columnWidths: {},
  columnOrder: [],
  updatedAt: 0,
  ...over,
});

describe("parseTableLayouts", () => {
  it("reads layouts out of the settings blob", () => {
    const parsed = parseTableLayouts({
      table_layouts: {
        entries: {
          columnVisibility: { feed: false },
          columnWidths: { title: 400 },
          columnOrder: ["title", "feed"],
          updatedAt: 1700,
        },
      },
    });
    expect(parsed.entries).toEqual({
      columnVisibility: { feed: false },
      columnWidths: { title: 400 },
      columnOrder: ["title", "feed"],
      updatedAt: 1700,
    });
  });

  it("returns an empty map when the key is missing or the wrong shape", () => {
    expect(parseTableLayouts(undefined)).toEqual({});
    expect(parseTableLayouts({})).toEqual({});
    expect(parseTableLayouts({ table_layouts: "nope" })).toEqual({});
  });

  it("drops junk values rather than handing them to the table", () => {
    const parsed = parseTableLayouts({
      table_layouts: {
        entries: {
          columnVisibility: { feed: "yes", title: true },
          columnWidths: { title: "wide", feed: 120 },
          columnOrder: ["title", 7, null],
          updatedAt: "recently",
        },
        broken: 42,
      },
    });
    expect(parsed.entries).toEqual({
      columnVisibility: { title: true },
      columnWidths: { feed: 120 },
      columnOrder: ["title"],
      updatedAt: 0,
    });
    expect(parsed.broken).toBeUndefined();
  });
});

describe("toTableLayoutMap", () => {
  const storeLayout = (over: Record<string, unknown>) => ({
    columnVisibility: {},
    columnWidths: {},
    columnOrder: [],
    textFilters: {},
    hasFilters: {},
    choiceFilters: {},
    clientSort: null,
    layoutUpdatedAt: 0,
    ...over,
  });

  it("keeps only layout fields — filters and sort stay on the device", () => {
    const map = toTableLayoutMap({
      entries: storeLayout({
        columnVisibility: { feed: false },
        textFilters: { title: "ransomware" },
        clientSort: { key: "title", dir: "asc" },
        layoutUpdatedAt: 900,
      }),
    });
    expect(map.entries).toEqual({
      columnVisibility: { feed: false },
      columnWidths: {},
      columnOrder: [],
      updatedAt: 900,
    });
  });

  it("skips untouched tables but keeps a deliberate reset", () => {
    const map = toTableLayoutMap({
      untouched: storeLayout({ textFilters: { title: "x" } }),
      wasReset: storeLayout({ layoutUpdatedAt: 5000 }),
    });
    expect(Object.keys(map)).toEqual(["wasReset"]);
  });
});

describe("layoutMapsEqual", () => {
  it("ignores key order but catches any layout difference", () => {
    expect(
      layoutMapsEqual(
        { a: layout({ columnOrder: ["x"] }), b: layout() },
        { b: layout(), a: layout({ columnOrder: ["x"] }) },
      ),
    ).toBe(true);
    expect(layoutMapsEqual({ a: layout() }, { a: layout({ updatedAt: 1 }) })).toBe(false);
    expect(layoutMapsEqual({ a: layout() }, { a: layout(), b: layout() })).toBe(false);
    expect(
      layoutMapsEqual({ a: layout({ columnWidths: { t: 100 } }) }, { a: layout({ columnWidths: { t: 200 } }) }),
    ).toBe(false);
  });
});

describe("applyRemoteTableLayouts", () => {
  beforeEach(() => {
    useUIStore.setState({ tables: {} });
  });

  it("adopts the server layout for a table this device never touched", () => {
    useUIStore.getState().applyRemoteTableLayouts({
      entries: layout({ columnVisibility: { feed: false }, updatedAt: 10 }),
    });
    const t = useUIStore.getState().tables.entries;
    expect(t.columnVisibility).toEqual({ feed: false });
    expect(t.layoutUpdatedAt).toBe(10);
  });

  it("keeps a newer local arrangement and leaves local filters intact", () => {
    useUIStore.getState().setTableColumnVisible("entries", "feed", true);
    useUIStore.getState().setTableTextFilter("entries", "title", "apt29");
    const localStamp = useUIStore.getState().tables.entries.layoutUpdatedAt;

    useUIStore.getState().applyRemoteTableLayouts({
      entries: layout({ columnVisibility: { feed: false }, updatedAt: localStamp - 1000 }),
    });

    const t = useUIStore.getState().tables.entries;
    expect(t.columnVisibility).toEqual({ feed: true });
    expect(t.layoutUpdatedAt).toBe(localStamp);
    expect(t.textFilters).toEqual({ title: "apt29" });
  });

  it("takes the server layout when it is the newer edit", () => {
    useUIStore.getState().setTableColumnVisible("entries", "feed", true);
    useUIStore.getState().setTableTextFilter("entries", "title", "apt29");
    const localStamp = useUIStore.getState().tables.entries.layoutUpdatedAt;

    useUIStore.getState().applyRemoteTableLayouts({
      entries: layout({ columnOrder: ["title"], updatedAt: localStamp + 1000 }),
    });

    const t = useUIStore.getState().tables.entries;
    expect(t.columnVisibility).toEqual({});
    expect(t.columnOrder).toEqual(["title"]);
    expect(t.textFilters).toEqual({ title: "apt29" });
  });
});
