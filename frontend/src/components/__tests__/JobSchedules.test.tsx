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
        job("cve-nvd-backfill", "enrichment", {
          source: "nvd",
          source_label: "NVD 2.0",
          runs_30d: 33,
          ok_30d: 3,
          last_status: "error",
          last_error: "TimeLimitExceeded(960)",
        }),
        job("epss-bulk-sync", "enrichment", { source: "epss", runs_30d: 30, ok_30d: 30, last_status: "success" }),
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

    // Every category starts collapsed; open the two this test reads.
    expect(screen.queryByText("Cve Nvd Backfill")).not.toBeInTheDocument();
    fireEvent.click(screen.getByText("Enrichment"));
    fireEvent.click(screen.getByText("Maintenance"));

    const enrichRow = screen.getByText("Cve Nvd Backfill").closest("div")!.parentElement!;
    expect(within(enrichRow).queryByRole("checkbox")).not.toBeInTheDocument();
    expect(within(enrichRow).queryByTitle("Run now")).not.toBeInTheDocument();
    expect(within(enrichRow).getByText("daily 01:30")).toBeInTheDocument();
    fireEvent.click(within(enrichRow).getByRole("button", { name: "Open in Enrichment" }));
    expect(onOpen).toHaveBeenCalledWith("nvd");

    // Owner, 30-day success count and the last error, in red only when it failed.
    expect(within(enrichRow).getByText("source · NVD 2.0")).toBeInTheDocument();
    expect(within(enrichRow).getByText("3/33 ok in 30 days")).toBeInTheDocument();
    expect(within(enrichRow).getByText("Last run: TimeLimitExceeded(960)")).toBeInTheDocument();
    const epssRow = screen.getByText("Epss Bulk Sync").closest("div")!.parentElement!;
    // No label from the server: the source key stands in.
    expect(within(epssRow).getByText("source · epss")).toBeInTheDocument();
    expect(within(epssRow).getByText("30/30 ok in 30 days")).toBeInTheDocument();
    expect(within(epssRow).queryByText(/Last run/)).not.toBeInTheDocument();

    // Other jobs keep their controls.
    const otherRow = screen.getByText("Reindex Search").closest("div")!.parentElement!;
    expect(within(otherRow).getByRole("checkbox")).toBeInTheDocument();
    expect(within(otherRow).getByTitle("Run now")).toBeInTheDocument();
  });
});
