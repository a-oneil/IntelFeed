import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { RouteFallback } from "../RouteFallback";

function renderAt(path: string, ui = <RouteFallback />) {
  return render(<MemoryRouter initialEntries={[path]}>{ui}</MemoryRouter>);
}

describe("RouteFallback", () => {
  it("names the pending route", () => {
    renderAt("/workbench/threats");
    expect(screen.getByRole("status")).toHaveTextContent("Loading Threats…");
  });

  it("resolves id-carrying detail routes by prefix", () => {
    renderAt("/workbench/cve/CVE-2024-3400");
    expect(screen.getByRole("status")).toHaveTextContent("Loading CVE Detail…");
  });

  it("falls back to a bare message for routes it can't name", () => {
    renderAt("/some/unmapped/route");
    expect(screen.getByRole("status")).toHaveTextContent("Loading…");
  });

  it("prefers an explicit label over the route", () => {
    renderAt("/workbench/explore", <RouteFallback label="ATT&CK matrix" />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading ATT&CK matrix…");
  });
});
