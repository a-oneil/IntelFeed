import { beforeEach, describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import { useUIStore } from "@/stores/uiStore";
import { DataTable, type DataTableColumn } from "../DataTable";
import { DEFAULT_TABLE_LAYOUTS } from "../defaultLayouts";

interface Row {
  id: string;
}

const COLUMNS: DataTableColumn<Row>[] = [
  { key: "name", label: "Name", width: 200, hideable: true, render: () => null },
  { key: "aliases", label: "Aliases", width: 150, hideable: true, render: () => null },
  { key: "malware_type", label: "Type", width: 120, hideable: true, render: () => null },
  { key: "first_seen_at", label: "First Seen", width: 120, hideable: true, render: () => null },
  { key: "last_seen_at", label: "Last Seen", width: 120, hideable: true, render: () => null },
  { key: "description", label: "Description", width: 300, hideable: true, defaultHidden: true, render: () => null },
  { key: "actor_count", label: "Actors", width: 80, hideable: true, render: () => null },
  { key: "malpedia_url", label: "Malpedia", width: 100, hideable: true, render: () => null },
  { key: "wikipedia_url", label: "Wikipedia", width: 100, hideable: true, render: () => null },
  { key: "article_count", label: "Articles", width: 80, hideable: true, render: () => null },
  { key: "linked_count", label: "Linked", width: 70, hideable: true, render: () => null },
  { key: "top_link", label: "Top link", width: 200, hideable: true, defaultHidden: true, render: () => null },
];

function renderTable() {
  return render(
    <DataTable<Row>
      tableId="entity:malware"
      columns={COLUMNS}
      rows={[]}
      getRowId={(r) => r.id}
    />
  );
}

/** Header labels, left to right, of the columns actually rendered. */
function headerLabels(container: HTMLElement): string[] {
  const row = container.querySelector('[class*="headerRow"]');
  return Array.from(row?.children ?? [])
    .map((cell) => cell.querySelector("span")?.textContent ?? "")
    .filter(Boolean);
}

function widthOf(container: HTMLElement, index: number): string {
  const row = container.querySelector('[class*="headerRow"]') as HTMLElement;
  return row.style.gridTemplateColumns.split(" ")[index];
}

describe("default table layouts", () => {
  beforeEach(() => {
    useUIStore.setState({ tables: {} });
  });

  it("arranges an untouched table the way the preset says", () => {
    const { container } = renderTable();

    // Preset order, minus the columns it marks hidden.
    expect(headerLabels(container)).toEqual([
      "Name",
      "Aliases",
      "Type",
      "First Seen",
      "Description",
      "Actors",
      "Top link",
      "Articles",
    ]);
  });

  it("reveals a defaultHidden column the preset turns on, and hides one it turns off", () => {
    const { container } = renderTable();
    const labels = headerLabels(container);

    // `description` and `top_link` are defaultHidden in the column defs; the
    // preset shows them. `last_seen_at` ships visible; the preset hides it.
    expect(labels).toContain("Description");
    expect(labels).toContain("Top link");
    expect(labels).not.toContain("Last Seen");
  });

  it("applies preset widths", () => {
    const { container } = renderTable();
    // first_seen_at is 4th in the preset order and widened to 196px.
    expect(widthOf(container, 3)).toBe("196px");
  });

  it("lets a stored preference beat the preset, per column", () => {
    useUIStore.getState().setTableColumnVisible("entity:malware", "last_seen_at", true);
    useUIStore.getState().setTableColumnVisible("entity:malware", "description", false);
    useUIStore.getState().setTableColumnWidth("entity:malware", "first_seen_at", 90);

    const { container } = renderTable();
    const labels = headerLabels(container);

    expect(labels).toContain("Last Seen");
    expect(labels).not.toContain("Description");
    // Untouched preset entries still apply alongside the overrides.
    expect(labels).toContain("Top link");
    // first_seen_at keeps its position but takes the user's 90px over the preset's 196px.
    expect(widthOf(container, 3)).toBe("90px");
  });

  it("lets a stored column order replace the preset order wholesale", () => {
    useUIStore
      .getState()
      .setTableColumnOrder("entity:malware", ["article_count", "name", "aliases"]);

    const { container } = renderTable();
    expect(headerLabels(container).slice(0, 3)).toEqual(["Articles", "Name", "Aliases"]);
  });

  it("keeps every preset key pointed at a real column", () => {
    const preset = DEFAULT_TABLE_LAYOUTS["entity:malware"];
    const keys = new Set(COLUMNS.map((c) => c.key));
    for (const key of preset.order ?? []) expect(keys.has(key)).toBe(true);
    for (const key of Object.keys(preset.visibility ?? {})) expect(keys.has(key)).toBe(true);
    for (const key of Object.keys(preset.widths ?? {})) expect(keys.has(key)).toBe(true);
  });
});
