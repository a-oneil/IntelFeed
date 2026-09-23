import { beforeEach, describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useUIStore } from "@/stores/uiStore";
import { DataTable, type DataTableColumn } from "../DataTable";

interface Row {
  id: string;
  name: string;
}

const TABLE_ID = "test:empty";

const COLUMNS: DataTableColumn<Row>[] = [
  {
    key: "name",
    label: "Name",
    width: 200,
    textValue: (r) => r.name,
    render: (r) => r.name,
  },
  {
    key: "search",
    label: "Search",
    width: 160,
    serverText: true,
    render: () => null,
  },
  {
    key: "entries",
    label: "Entries",
    width: 80,
    numValue: () => 0,
    render: () => null,
  },
  {
    key: "status",
    label: "Status",
    width: 120,
    choices: [
      { value: "all", label: "Any" },
      { value: "active", label: "Active" },
    ],
    choiceMatch: (_r, v) => v === "all",
    render: () => null,
  },
];

function renderTable(rows: Row[] = []) {
  return render(
    <DataTable<Row>
      tableId={TABLE_ID}
      columns={COLUMNS}
      rows={rows}
      getRowId={(r) => r.id}
      noun="actor"
      nounPlural="actors"
      emptyMessage="No threat actors yet — extract intelligence from articles."
    />
  );
}

describe("DataTable empty state", () => {
  beforeEach(() => {
    useUIStore.setState({ tables: {} });
  });

  it("shows the host's no-data message when no filter is active", () => {
    renderTable([]);
    expect(
      screen.getByText("No threat actors yet — extract intelligence from articles.")
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Clear filters" })).not.toBeInTheDocument();
  });

  it("renders a custom emptyState node unchanged when no filter is active", () => {
    render(
      <DataTable<Row>
        tableId={TABLE_ID}
        columns={COLUMNS}
        rows={[]}
        getRowId={(r) => r.id}
        emptyState={<span>Bespoke empty</span>}
      />
    );
    expect(screen.getByText("Bespoke empty")).toBeInTheDocument();
  });

  it.each([
    ["a client text filter", () => useUIStore.getState().setTableTextFilter(TABLE_ID, "name", "zzz")],
    [
      "a server text filter",
      () => useUIStore.getState().setTableTextFilter(TABLE_ID, "search", "zzz-merge"),
    ],
    ["a >0 numeric filter", () => useUIStore.getState().setTableHasFilter(TABLE_ID, "entries", true)],
    [
      "a dropdown filter",
      () => useUIStore.getState().setTableChoiceFilter(TABLE_ID, "status", "active"),
    ],
  ])("shows the no-matches branch for %s", (_label, applyFilter) => {
    applyFilter();
    renderTable([]);

    expect(screen.getByText("No actors match these filters")).toBeInTheDocument();
    expect(
      screen.queryByText("No threat actors yet — extract intelligence from articles.")
    ).not.toBeInTheDocument();
  });

  it("names the active filter and announces the empty state", () => {
    useUIStore.getState().setTableTextFilter(TABLE_ID, "name", "zzz-merge");
    const { container } = renderTable([]);

    expect(container.querySelector('[role="status"]')).toBeInTheDocument();
    expect(screen.getByText(/Name: “zzz-merge”/)).toBeInTheDocument();
  });

  it("stays on the no-matches branch when loaded rows exist but none match", () => {
    useUIStore.getState().setTableTextFilter(TABLE_ID, "name", "zzz");
    renderTable([{ id: "a", name: "APT29" }]);
    expect(screen.getByText("No actors match these filters")).toBeInTheDocument();
  });

  it("clears every filter from the empty-state button", async () => {
    const user = userEvent.setup();
    useUIStore.getState().setTableTextFilter(TABLE_ID, "name", "zzz");
    useUIStore.getState().setTableTextFilter(TABLE_ID, "search", "zzz-merge");
    useUIStore.getState().setTableHasFilter(TABLE_ID, "entries", true);
    useUIStore.getState().setTableChoiceFilter(TABLE_ID, "status", "active");

    renderTable([]);

    const buttons = screen.getAllByRole("button", { name: "Clear filters" });
    // The table bar keeps its own control; the empty state adds the second.
    expect(buttons).toHaveLength(2);
    await user.click(buttons[buttons.length - 1]);

    const layout = useUIStore.getState().tables[TABLE_ID];
    expect(layout.textFilters).toEqual({});
    expect(layout.hasFilters).toEqual({});
    expect(layout.choiceFilters).toEqual({});
    expect(
      screen.getByText("No threat actors yet — extract intelligence from articles.")
    ).toBeInTheDocument();
  });

  it("falls back to a generic plural when the host passes no noun", () => {
    useUIStore.getState().setTableTextFilter(TABLE_ID, "name", "zzz");
    render(
      <DataTable<Row> tableId={TABLE_ID} columns={COLUMNS} rows={[]} getRowId={(r) => r.id} />
    );
    expect(screen.getByText("No rows match these filters")).toBeInTheDocument();
  });
});
