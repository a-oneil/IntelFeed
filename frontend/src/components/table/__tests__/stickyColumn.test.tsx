import { beforeEach, describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import { useUIStore } from "@/stores/uiStore";
import { DataTable, type DataTableColumn } from "../DataTable";

interface Row {
  id: string;
}

const COLUMNS: DataTableColumn<Row>[] = [
  { key: "name", label: "Name", width: 200, hideable: true, render: () => null },
  { key: "country", label: "Country", width: 120, hideable: true, render: () => null },
  { key: "actions", label: "", width: 40, sticky: "right", render: () => null },
];

function renderTable() {
  return render(
    <DataTable<Row>
      tableId="test:sticky"
      columns={COLUMNS}
      rows={[{ id: "a" }]}
      getRowId={(r) => r.id}
    />
  );
}

/** Column keys, left to right, as the header renders them. */
function headerKeys(container: HTMLElement): string[] {
  const row = container.querySelector('[class*="headerRow"]');
  return Array.from(row?.children ?? []).map((cell) =>
    (cell.querySelector("span")?.textContent ?? "").trim()
  );
}

describe("sticky columns", () => {
  beforeEach(() => {
    useUIStore.setState({ tables: {} });
  });

  it("pins the sticky column's header and filter cells", () => {
    const { container } = renderTable();
    // jsdom gives the virtualizer no height, so only the two chrome rows render.
    for (const rowClass of ["headerRow", "filterRow"]) {
      const cells = Array.from(container.querySelector(`[class*="${rowClass}"]`)!.children);
      expect(cells[cells.length - 1].className).toContain("stickyRight");
      expect(cells[0].className).not.toContain("stickyRight");
    }
  });

  it("keeps a sticky column last even when the stored order puts it first", () => {
    useUIStore.getState().setTableColumnOrder("test:sticky", ["actions", "country", "name"]);

    const { container } = renderTable();
    expect(headerKeys(container)).toEqual(["Country", "Name", ""]);
  });

  it("does not let a sticky column be dragged", () => {
    const { container } = renderTable();
    const cells = Array.from(container.querySelector('[class*="headerRow"]')!.children);
    expect(cells[0].getAttribute("draggable")).toBe("true");
    expect(cells[cells.length - 1].getAttribute("draggable")).toBe("false");
  });
});
