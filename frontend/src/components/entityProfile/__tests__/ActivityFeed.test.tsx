import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import type { TimelineEvent } from "@/api/types";
import { ActivityFeed } from "../ActivityFeed";

vi.mock("@/components/UnlinkArticleButton", () => ({
  UnlinkArticleButton: () => null,
}));

const entries = [
  { id: "e1", title: "APT29 campaign report", published_at: "2026-06-01T00:00:00Z" },
];

const articleEvent: TimelineEvent = {
  entry_id: "e1",
  title: "APT29 campaign report",
  date: "2026-06-01T00:00:00Z",
  event_type: "article",
} as TimelineEvent;

const relationshipEvent: TimelineEvent = {
  entry_id: null,
  title: "Linked to Cozy Bear",
  date: "2026-06-02T00:00:00Z",
  event_type: "relationship",
} as TimelineEvent;

function renderFeed(events: TimelineEvent[]) {
  return render(
    <ActivityFeed
      entityType="cve"
      entityId="cve-1"
      entries={entries}
      events={events}
      onOpenArticle={vi.fn()}
    />,
  );
}

describe("ActivityFeed events filter", () => {
  it("hides the Events filter when the entity has no non-article events", () => {
    renderFeed([articleEvent]);
    expect(screen.getByRole("button", { name: /All/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Articles/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Events/ })).not.toBeInTheDocument();
  });

  it("shows the Events filter when non-article events exist", () => {
    renderFeed([articleEvent, relationshipEvent]);
    const eventsBtn = screen.getByRole("button", { name: /Events \(1\)/ });
    fireEvent.click(eventsBtn);
    expect(screen.getByText("Linked to Cozy Bear")).toBeInTheDocument();
    expect(screen.queryByText("APT29 campaign report")).not.toBeInTheDocument();
  });
});
