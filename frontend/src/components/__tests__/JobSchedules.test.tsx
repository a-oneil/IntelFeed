import { render, screen, fireEvent, within } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";

import type { JobSchedule } from "@/hooks/useJobSchedules";
import JobSchedules from "../JobSchedules";

const job = (name: string, category: string, extra: Partial<JobSchedule> = {}): JobSchedule => ({
  name,
  task: `app.workers.${name}`,
  description: `${name} description`,
  category,
  uses_ai: false,
  enabled: true,
  default_schedule: { type: "crontab", minute: "30", hour: "1" },
  effective_schedule: { type: "crontab", minute: "30", hour: "1" },
  is_customized: false,
  human_schedule: "daily 01:30",
  human_default_schedule: "daily 01:30",
  ...extra,
});

vi.mock("@/hooks/useJobSchedules", () => ({
  useJobSchedules: () => ({
    data: {
      jobs: [
        job("cve-nvd-backfill", "enrichment", { source: "nvd" }),
        job("reindex-search", "maintenance"),
      ],
      categories: { enrichment: "Enrichment", maintenance: "Maintenance" },
      category_order: ["enrichment", "maintenance"],
    },
    isLoading: false,
  }),
  useUpdateJobSchedule: () => ({ mutate: vi.fn(), mutateAsync: vi.fn(), isPending: false }),
  useResetJobSchedule: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useRunJobNow: () => ({ mutateAsync: vi.fn(), isPending: false }),
}));

vi.mock("../SystemSettings", () => ({ default: () => <div data-testid="system-settings" /> }));

describe("JobSchedules", () => {
  it("shows a source's job read-only with a link into Enrichment", () => {
    const onOpen = vi.fn();
    render(<JobSchedules onOpenEnrichment={onOpen} />);

    const enrichRow = screen.getByText("Cve Nvd Backfill").closest("div")!.parentElement!;
    expect(within(enrichRow).queryByRole("checkbox")).not.toBeInTheDocument();
    expect(within(enrichRow).queryByTitle("Run now")).not.toBeInTheDocument();
    expect(within(enrichRow).getByText("daily 01:30")).toBeInTheDocument();
    fireEvent.click(within(enrichRow).getByRole("button", { name: "Open in Enrichment" }));
    expect(onOpen).toHaveBeenCalledWith("nvd");

    // Other jobs keep their controls.
    const otherRow = screen.getByText("Reindex Search").closest("div")!.parentElement!;
    expect(within(otherRow).getByRole("checkbox")).toBeInTheDocument();
    expect(within(otherRow).getByTitle("Run now")).toBeInTheDocument();
  });
});
