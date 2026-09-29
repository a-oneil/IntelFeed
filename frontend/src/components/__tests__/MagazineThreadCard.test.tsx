import { render, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { MagazineThreadCard } from "../MagazineThreadCard";
import type { StoryThread } from "@/api/types";

function thread(overrides: Partial<StoryThread> = {}): StoryThread {
  return {
    id: "t1",
    slug: "bluemoon-exploit-kit",
    title: "BlueMoon exploit kit",
    summary: "Nine outlets on the same intrusion set.",
    status: "open",
    entry_count: 23,
    source_count: 11,
    echo_count: 0,
    first_seen: null,
    last_seen: null,
    peak_at: null,
    key_entities: [
      { entity_type: "product", entity_id: "p1", label: "Chrome", count: 7 },
      { entity_type: "actor", entity_id: "a1", label: "APT29", count: 4 },
      { entity_type: "cve", entity_id: "c1", label: "CVE-2026-1111", count: 3 },
      { entity_type: "malware", entity_id: "m1", label: "BlueLoader", count: 2 },
    ],
    unread_count: 6,
    new_since_opened: 6,
    top_score: 7.4,
    top_entry_id: "e1",
    entry_ids: ["e1", "e2"],
    narrated_at: null,
    ...overrides,
  };
}

function renderCard(overrides: Partial<StoryThread> = {}, score = 7.4) {
  const onOpen = vi.fn();
  render(<MagazineThreadCard thread={thread(overrides)} score={score} onOpen={onOpen} />);
  return { onOpen };
}

describe("MagazineThreadCard", () => {
  it("leads with what the story cost to read, not with the article it came from", () => {
    renderCard();

    expect(screen.getByText("BlueMoon exploit kit")).toBeInTheDocument();
    expect(screen.getByText("11 outlets · 23 articles · 6 new")).toBeInTheDocument();
    expect(screen.getByText("◆ 7.4")).toBeInTheDocument();
    expect(screen.getByText("Nine outlets on the same intrusion set.")).toBeInTheDocument();
  });

  it("reads as a story, not an article: the thread glyph and no image", () => {
    const { container } = render(
      <MagazineThreadCard thread={thread()} score={7.4} onOpen={vi.fn()} />,
    );

    expect(screen.getByText("⟲")).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
  });

  it("shows the first three key entities and stops there", () => {
    renderCard();

    expect(screen.getByText("Chrome")).toBeInTheDocument();
    expect(screen.getByText("APT29")).toBeInTheDocument();
    expect(screen.getByText("CVE-2026-1111")).toBeInTheDocument();
    expect(screen.queryByText("BlueLoader")).not.toBeInTheDocument();
  });

  it("bands the score by the same thresholds as every other surface", () => {
    const { container } = render(
      <MagazineThreadCard thread={thread()} score={1.2} onOpen={vi.fn()} />,
    );

    expect(container.querySelector(".score")?.className).toContain("low");
  });

  it("opens the story on click and on the keyboard", () => {
    const { onOpen } = renderCard();

    fireEvent.click(screen.getByRole("button"));
    expect(onOpen).toHaveBeenCalledTimes(1);

    fireEvent.keyDown(screen.getByRole("button"), { key: "Enter" });
    expect(onOpen).toHaveBeenCalledTimes(2);
  });
});
