import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ComponentProps } from "react";

const put = vi.fn();
vi.mock("@/api/client", () => ({
  default: { put: (...args: unknown[]) => put(...args) },
}));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import { InfoGradeChip } from "../InfoGradeChip";

function renderIt(props: Partial<ComponentProps<typeof InfoGradeChip>> = {}) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <InfoGradeChip entryId="e1" reliability="B" rating={2} ratingBy="ai" {...props} />
    </QueryClientProvider>,
  );
}

describe("InfoGradeChip", () => {
  beforeEach(() => put.mockReset().mockResolvedValue({ data: {} }));

  it("shows the feed letter and the article number together", () => {
    renderIt();
    expect(screen.getByRole("button", { name: "Grade B2" })).toHaveTextContent("B2");
  });

  it("explains both halves and says when another outlet confirmed it", async () => {
    renderIt({ rating: 1, aiRating: 3, access: "secondhand", note: "relays a vendor blog" });
    await userEvent.click(screen.getByRole("button", { name: "Grade B1" }));
    expect(screen.getByText("Usually reliable")).toBeInTheDocument();
    expect(screen.getByText("Confirmed")).toBeInTheDocument();
    expect(screen.getByText(/AI rated it 3; another outlet confirmed it/)).toBeInTheDocument();
    expect(screen.getByText("Author relays someone else's report")).toBeInTheDocument();
  });

  it("lets an analyst set a rating and go back to the AI's", async () => {
    const { rerender } = renderIt();
    await userEvent.click(screen.getByRole("button", { name: "Grade B2" }));
    await userEvent.click(screen.getByRole("button", { name: "4" }));
    expect(put).toHaveBeenCalledWith("/entries/e1/info-rating", { rating: 4 });

    rerender(
      <QueryClientProvider client={new QueryClient()}>
        <InfoGradeChip entryId="e1" reliability="B" rating={4} ratingBy="analyst" />
      </QueryClientProvider>,
    );
    await userEvent.click(screen.getByText("Go back to the AI's rating"));
    expect(put).toHaveBeenLastCalledWith("/entries/e1/info-rating", { rating: null });
  });

  it("renders nothing when the feed has no reliability rating", () => {
    renderIt({ reliability: null, rating: 2 });
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("shows a dash for an article that isn't rated yet", () => {
    renderIt({ rating: null, ratingBy: null });
    expect(screen.getByRole("button", { name: "Grade B–" })).toBeInTheDocument();
  });

  it("hides the picker when read-only", async () => {
    renderIt({ readOnly: true });
    await userEvent.click(screen.getByRole("button", { name: "Grade B2" }));
    expect(screen.queryByText("Rate this article")).not.toBeInTheDocument();
  });
});
