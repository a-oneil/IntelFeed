import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ConfirmCard } from "../ConfirmCard";

const request = {
  action_id: "a1",
  action_type: "delete_feed",
  tool_name: "delete_feed",
  description: "Delete feed (feed_id=f1)",
  proposed: { feed_id: "f1", reason: { why: "stale" } },
  destructive: true,
};

describe("ConfirmCard", () => {
  it("shows the exact call and warns before a destructive one", async () => {
    const onConfirm = vi.fn();
    render(<ConfirmCard request={request} state={{ status: "pending" }} onConfirm={onConfirm} onCancel={vi.fn()} />);

    expect(screen.getByText("Delete Feed")).toBeInTheDocument();
    expect(screen.getByText("feed_id")).toBeInTheDocument();
    expect(screen.getByText("f1")).toBeInTheDocument();
    expect(screen.getByText('{"why":"stale"}')).toBeInTheDocument();
    expect(screen.getByText(/deletes data or changes it for everyone/)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Confirm" }));
    expect(onConfirm).toHaveBeenCalledOnce();
  });

  it("keeps the description for a legacy proposal and no warning for an ordinary write", () => {
    render(
      <ConfirmCard
        request={{ action_id: "a2", action_type: "create_campaign", description: "Create a campaign", proposed: {} }}
        state={{ status: "pending" }}
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />
    );
    expect(screen.getByText("Create a campaign")).toBeInTheDocument();
    expect(screen.queryByText(/deletes data/)).not.toBeInTheDocument();
  });
});
