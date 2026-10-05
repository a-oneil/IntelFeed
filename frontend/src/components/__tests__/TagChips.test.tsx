import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";

import type { EntryTag } from "@/api/types";
import { EntryIntelBadges } from "../EntryIntelBadges";
import { TagChips } from "../TagChips";
import { useUIStore } from "@/stores/uiStore";

const del = vi.fn().mockResolvedValue({});
vi.mock("@/api/client", () => ({ default: { delete: (...args: unknown[]) => del(...args) } }));

function chip(name: string, extra: Partial<EntryTag> = {}): EntryTag {
  return { id: `id-${name}`, name, color: "#DC2626", display_as_chip: true, description: null, ...extra };
}

function renderWithApp(ui: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/"]}>
        <Routes>
          <Route path="/" element={ui} />
          <Route path="/search" element={<div>search page</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("TagChips", () => {
  beforeEach(() => {
    del.mockClear();
    useUIStore.getState().setHeaderSearchQuery("");
  });

  it("renders only tags promoted to chips", () => {
    renderWithApp(<TagChips tags={[chip("customer-a"), { name: "quiet", color: "#000000" }]} entryId="e1" />);
    expect(screen.getByText("customer-a")).toBeInTheDocument();
    expect(screen.queryByText("quiet")).not.toBeInTheDocument();
  });

  it("caps at three and folds the rest into +N", () => {
    const tags = ["a", "b", "c", "d", "e"].map((n) => chip(n));
    renderWithApp(<TagChips tags={tags} entryId="e1" />);
    expect(screen.getByText("c")).toBeInTheDocument();
    expect(screen.queryByText("d")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "+2" }));
    expect(screen.getByText("d")).toBeInTheDocument();
    expect(screen.getByText("e")).toBeInTheDocument();
  });

  it("pivots to search on the tag when clicked", () => {
    renderWithApp(<TagChips tags={[chip("OT relevant")]} entryId="e1" />);
    fireEvent.click(screen.getByText("OT relevant"));
    expect(useUIStore.getState().headerSearchQuery).toBe('tag:"OT relevant"');
    expect(screen.getByText("search page")).toBeInTheDocument();
  });

  it("removes the tag from the entry with the ×", async () => {
    renderWithApp(<TagChips tags={[chip("customer-a")]} entryId="e1" />);
    fireEvent.click(screen.getByRole("button", { name: 'Remove "customer-a" from this entry' }));
    await waitFor(() => expect(del).toHaveBeenCalledWith("/tags/entries/e1/id-customer-a"));
  });

  it("uses the description as tooltip and says who sees the tag", () => {
    renderWithApp(<TagChips tags={[chip("customer-a", { description: "Customer A exposure", personal: true })]} />);
    const title = screen.getByText("customer-a").closest("button")!.getAttribute("title")!;
    expect(title).toMatch(/Customer A exposure/);
    expect(title).toMatch(/Only you see this tag/);
  });

  it("says when a tag is global", () => {
    renderWithApp(<TagChips tags={[chip("team-wide", { is_global: true, personal: false })]} />);
    const title = screen.getByText("team-wide").closest("button")!.getAttribute("title")!;
    expect(title).toMatch(/Everyone sees this tag/);
  });

  it("derives a readable foreground from the tag colour", () => {
    renderWithApp(<TagChips tags={[chip("pale", { color: "#FDE68A" })]} />);
    const button = screen.getByText("pale").closest("button")!;
    expect(button.style.getPropertyValue("--chip-fg")).toBe("#000000");
  });
});

describe("EntryIntelBadges with chips", () => {
  it("renders a row for chips alone, leading with them", () => {
    renderWithApp(<EntryIntelBadges tags={[chip("customer-a")]} starred entryId="e1" />);
    const line = screen.getByText("customer-a").closest("span[class*='intelLine']")!;
    expect(line.firstElementChild?.textContent).toContain("customer-a");
    expect(screen.getByLabelText("Starred")).toBeInTheDocument();
  });

  it("stays empty when the entry has no chips or intel", () => {
    const { container } = renderWithApp(<EntryIntelBadges tags={[{ name: "quiet", color: "#000000" }]} />);
    expect(container.textContent).toBe("");
  });
});
