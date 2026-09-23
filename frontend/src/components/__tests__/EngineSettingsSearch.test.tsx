import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";

import { EngineSettingsSearch } from "../engine/EngineSettingsSearch";
import { searchEngineSettings } from "../engine/engineSettingsIndex";

const SETTINGS = {
  thread_join_similarity: {
    value: 0.8,
    is_secret: false,
    source: "default" as const,
    label: "Thread join similarity",
    description: "Cosine similarity an entry must clear to join an existing story thread",
    group: "threads",
  },
  autolinker_min_name_length: {
    value: 4,
    is_secret: false,
    source: "default" as const,
    label: "Minimum name length",
    description: "Shorter entity names are never matched by the dictionary scan",
    group: "autolink",
  },
  backup_retention_days: {
    value: 7,
    is_secret: false,
    source: "default" as const,
    label: "Backup retention days",
    description: "How long nightly dumps are kept",
    group: "backup",
  },
  content_tone: {
    value: "neutral",
    is_secret: false,
    source: "default" as const,
    label: "Content tone",
    description: "Voice used for generated copy",
    group: "content",
  },
};
const GROUPS = { threads: "Story Threads", autolink: "Autolinking", backup: "Backup", content: "Content Generation" };

vi.mock("@/hooks/useSystemSettings", () => ({
  useSystemSettings: () => ({ data: { settings: SETTINGS, groups: GROUPS } }),
}));

describe("searchEngineSettings", () => {
  it("maps a setting's group onto the console surface that renders it", () => {
    const [hit] = searchEngineSettings("thread join", SETTINGS, GROUPS);
    expect(hit.key).toBe("thread_join_similarity");
    expect(hit.dest).toEqual({ kind: "stage", stage: "score" });
  });

  it("matches on key, description and the hand-written panels", () => {
    expect(searchEngineSettings("autolinker_min", SETTINGS, GROUPS)[0].key).toBe("autolinker_min_name_length");
    expect(searchEngineSettings("dictionary scan", SETTINGS, GROUPS)[0].key).toBe("autolinker_min_name_length");
    expect(searchEngineSettings("denylist", SETTINGS, GROUPS)[0].dest).toEqual({ kind: "stage", stage: "extract" });
  });

  it("drops settings no console surface owns and ranks off-console ones last", () => {
    expect(searchEngineSettings("content tone", SETTINGS, GROUPS)).toHaveLength(0);
    const hits = searchEngineSettings("retention", SETTINGS, GROUPS);
    expect(hits[hits.length - 1].key).toBe("backup_retention_days");
  });

  it("ignores queries shorter than two characters", () => {
    expect(searchEngineSettings("t", SETTINGS, GROUPS)).toHaveLength(0);
  });
});

describe("EngineSettingsSearch", () => {
  const type = (value: string) => {
    const input = screen.getByLabelText("Find an engine setting");
    fireEvent.change(input, { target: { value } });
    return input;
  };

  it("hands the picked setting's destination and key to the host", () => {
    const onPick = vi.fn();
    render(<EngineSettingsSearch onPick={onPick} />);
    type("thread join");
    fireEvent.click(screen.getByText("Thread join similarity"));
    expect(onPick).toHaveBeenCalledWith({ kind: "stage", stage: "score" }, "thread_join_similarity");
  });

  it("labels each result with the surface that owns it", () => {
    render(<EngineSettingsSearch onPick={vi.fn()} />);
    type("minimum name");
    expect(screen.getByText("Autolink stage")).toBeInTheDocument();
  });

  it("picks the active result on Enter and clears the query", () => {
    const onPick = vi.fn();
    render(<EngineSettingsSearch onPick={onPick} />);
    const input = type("thread");
    fireEvent.keyDown(input, { key: "Enter" });
    expect(onPick).toHaveBeenCalledWith({ kind: "stage", stage: "score" }, "thread_join_similarity");
    expect(input).toHaveValue("");
  });

  it("says so when nothing matches", () => {
    render(<EngineSettingsSearch onPick={vi.fn()} />);
    type("zzzz");
    expect(screen.getByText(/No engine setting matches/)).toBeInTheDocument();
  });
});
