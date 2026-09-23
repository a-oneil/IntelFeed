import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";

import { ActivityBadge } from "@/pages/WorkbenchPage";

function daysAgo(days: number): string {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
}

describe("ActivityBadge", () => {
  it("shows Active for actors seen within 90 days", () => {
    render(<ActivityBadge lastSeenAt={daysAgo(10)} />);
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByTitle("Seen in the last 90 days")).toBeInTheDocument();
  });

  it("shows Dormant for actors seen between 90 days and a year ago", () => {
    render(<ActivityBadge lastSeenAt={daysAgo(180)} />);
    expect(screen.getByText("Dormant")).toBeInTheDocument();
  });

  it("shows Historical for actors last seen over a year ago", () => {
    render(<ActivityBadge lastSeenAt={daysAgo(400)} />);
    expect(screen.getByText("Historical")).toBeInTheDocument();
  });

  it("shows Historical when the actor has never been seen", () => {
    render(<ActivityBadge lastSeenAt={null} />);
    expect(screen.getByText("Historical")).toBeInTheDocument();
    expect(screen.getByTitle("Never seen in feed content")).toBeInTheDocument();
  });
});
