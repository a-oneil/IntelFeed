import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ConfirmCard } from "../ConfirmCard";

const request = {
  action_id: "a1",
  tool_name: "delete_feed",
  proposed: { feed_id: "f1", reason: { why: "stale" } },
  targets: { feed_id: "feed 'Krebs on Security'" },
  preview: "Are you sure you want to delete this feed? · entry count: 412",
  destructive: true,
};

describe("ConfirmCard", () => {
  it("shows the exact call and warns before a destructive one", async () => {
    const onConfirm = vi.fn();
    render(<ConfirmCard request={request} state={{ status: "pending" }} onConfirm={onConfirm} onCancel={vi.fn()} />);

    expect(screen.getByText("Delete Feed")).toBeInTheDocument();
    expect(screen.getByText("feed_id")).toBeInTheDocument();
    expect(screen.getByText("f1")).toBeInTheDocument();
    expect(screen.getByText("feed 'Krebs on Security'")).toBeInTheDocument();
    expect(screen.getByText(/entry count: 412/)).toBeInTheDocument();
    expect(screen.getByText('{"why":"stale"}')).toBeInTheDocument();
    expect(screen.getByText(/deletes data or changes it for everyone/)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Confirm" }));
    expect(onConfirm).toHaveBeenCalledOnce();
  });

  it("shows an ordinary write without a warning", () => {
    render(
      <ConfirmCard
        request={{ action_id: "a2", tool_name: "create_campaign", proposed: { name: "Op Lantern" } }}
        state={{ status: "pending" }}
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />
    );
    expect(screen.getByText("Create Campaign")).toBeInTheDocument();
    expect(screen.getByText("Op Lantern")).toBeInTheDocument();
    expect(screen.queryByText(/deletes data/)).not.toBeInTheDocument();
  });
});
