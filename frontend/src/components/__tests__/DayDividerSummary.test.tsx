import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";

import { DayDividerSummary } from "../DayDividerSummary";

// --- mocks -------------------------------------------------------------------

const { playSpeech, stopSpeech, stopAudio, stateRef } = vi.hoisted(() => ({
  playSpeech: vi.fn(),
  stopSpeech: vi.fn(),
  stopAudio: vi.fn(),
  stateRef: {
    speechTrack: null as null | { entryId: string },
    mode: "audio" as "audio" | "speech",
    currentTrack: null as null | { kind?: string; entryId: string },
    engine: "browser" as "piper" | "browser",
  },
}));

// usePlayerStore is a selector hook; feed the selector a fake state slice.
vi.mock("@/stores/playerStore", () => ({
  usePlayerStore: (sel: (s: unknown) => unknown) =>
    sel({
      playSpeech,
      stopSpeech,
      stop: stopAudio,
      speechTrack: stateRef.speechTrack,
      mode: stateRef.mode,
      currentTrack: stateRef.currentTrack,
    }),
}));

vi.mock("@/stores/uiStore", () => ({
  useUIStore: (sel: (s: unknown) => unknown) => sel({ readAloudEngine: stateRef.engine }),
}));

const ttsStart = vi.fn().mockResolvedValue(true);
vi.mock("@/hooks/useTts", () => ({
  useTts: () => ({ start: ttsStart, cancel: vi.fn(), isPreparing: false }),
}));

const useDailySummaryMock = vi.fn();
const generateMock = { mutate: vi.fn(), isPending: false, error: null };
vi.mock("@/hooks/useDailySummary", () => ({
  useDailySummary: () => useDailySummaryMock(),
  useGenerateDailySummary: () => generateMock,
}));

// The summary body now hosts a text-selection menu that fetches AI tasks of
// its own. These tests are about the Listen button, so stub it out rather than
// standing up a QueryClientProvider for it.
vi.mock("@/components/SummarySelectionMenu", () => ({
  SummarySelectionMenu: () => null,
}));

vi.mock("@/hooks/useDayEntities", () => ({
  useDayEntities: () => ({ data: undefined }),
}));

const SUMMARY = `## TL;DR
Ransomware hit ACME Corp. CVE-2024-1234 was exploited in the wild.

## Details
- APT29 resumed phishing operations.
- A second notable development landed late in the day.`;

function renderSummary() {
  useDailySummaryMock.mockReturnValue({
    data: { summary: SUMMARY, cached: true, generated_at: null },
    isLoading: false,
  });
  return render(
    <MemoryRouter>
      <DayDividerSummary
        dayKey="2026-07-08"
        dayCount={5}
        filters={{ dedup: true }}
        label="Yesterday"
      />
    </MemoryRouter>,
  );
}

describe("DayDividerSummary — Listen button", () => {
  beforeEach(() => {
    vi.stubGlobal("speechSynthesis", {});
    stateRef.speechTrack = null;
    stateRef.mode = "audio";
    stateRef.currentTrack = null;
    stateRef.engine = "browser";
  });

  afterEach(() => {
    vi.clearAllMocks();
    vi.unstubAllGlobals();
  });

  it("reads the full summary aloud with the browser voice when Listen is clicked", () => {
    renderSummary();
    fireEvent.click(screen.getByRole("button", { name: "Listen" }));

    expect(playSpeech).toHaveBeenCalledTimes(1);
    const arg = playSpeech.mock.calls[0][0];
    expect(arg.entryId).toBe("daily-summary:2026-07-08");
    expect(arg.title).toContain("Yesterday");
    // Extracted from the hidden full-summary render — both sections, not just TL;DR.
    expect(arg.paragraphs.length).toBeGreaterThan(0);
    const joined = arg.paragraphs.join(" ");
    expect(joined).toContain("Ransomware");
    expect(joined).toContain("second notable"); // proves the full body, past the TL;DR, was read
    // cleanForSpeech normalizes CVEs so the synthesizer pronounces them.
    expect(joined).toContain("C V E 2024 1234");
    expect(stopSpeech).not.toHaveBeenCalled();
  });

  it("uses the Piper engine (not the browser voice) when selected", async () => {
    stateRef.engine = "piper";
    renderSummary();
    fireEvent.click(screen.getByRole("button", { name: "Listen" }));

    expect(ttsStart).toHaveBeenCalledTimes(1);
    const arg = ttsStart.mock.calls[0][0];
    expect(arg.source).toBe("summary");
    expect(arg.id).toBe("2026-07-08");
    // Text is resolved server-side; the client passes the filter context.
    expect(arg.filters).toEqual({ dedup: true });
    // Piper succeeded → no browser fallback.
    await Promise.resolve();
    expect(playSpeech).not.toHaveBeenCalled();
  });

  it("stops reading when already speaking this summary", () => {
    stateRef.speechTrack = { entryId: "daily-summary:2026-07-08" };
    renderSummary();

    const btn = screen.getByRole("button", { name: "Stop" });
    fireEvent.click(btn);
    expect(stopSpeech).toHaveBeenCalledTimes(1);
    expect(playSpeech).not.toHaveBeenCalled();
  });

  it("stops the audio player when the summary is playing via Piper", () => {
    stateRef.mode = "audio";
    stateRef.currentTrack = { kind: "tts", entryId: "daily-summary:2026-07-08" };
    renderSummary();

    fireEvent.click(screen.getByRole("button", { name: "Stop" }));
    expect(stopAudio).toHaveBeenCalledTimes(1);
    expect(stopSpeech).not.toHaveBeenCalled();
  });

  it("hides the Listen button only when browser voice is selected and Web Speech is unavailable", () => {
    stateRef.engine = "browser";
    vi.unstubAllGlobals(); // remove speechSynthesis
    renderSummary();
    expect(screen.queryByRole("button", { name: "Listen" })).toBeNull();
  });

  it("still shows Listen with Piper even when Web Speech is unavailable", () => {
    stateRef.engine = "piper";
    vi.unstubAllGlobals();
    renderSummary();
    expect(screen.getByRole("button", { name: "Listen" })).toBeInTheDocument();
  });
});
