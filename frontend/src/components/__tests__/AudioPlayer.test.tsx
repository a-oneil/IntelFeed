import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { usePlayerStore } from "@/stores/playerStore";

// Mock playback hooks
vi.mock("@/hooks/usePlayback", () => ({
  useUpdatePlayback: vi.fn(() => ({ mutate: vi.fn() })),
  useMarkPlaybackComplete: vi.fn(() => ({ mutate: vi.fn() })),
}));

vi.mock("@/stores/uiStore", () => ({
  useUIStore: vi.fn((selector: (s: Record<string, unknown>) => unknown) =>
    selector({
      setSelectedEntry: vi.fn(),
    })
  ),
}));

import { AudioPlayer } from "@/components/AudioPlayer";

function createQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
}

function renderAudioPlayer() {
  const queryClient = createQueryClient();
  return render(
    <QueryClientProvider client={queryClient}>
      <AudioPlayer />
    </QueryClientProvider>
  );
}

describe("AudioPlayer", () => {
  beforeEach(() => {
    // Reset store state
    usePlayerStore.setState({
      mode: "audio",
      currentTrack: null,
      isPlaying: false,
      currentTime: 0,
      duration: 0,
      playbackRate: 1,
      volume: 1,
      queue: [],
      speechTrack: null,
      speechIndex: 0,
      speechTotal: 0,
      speechPaused: false,
    });
  });

  it("renders nothing when no track is playing", () => {
    const { container } = renderAudioPlayer();
    expect(container.innerHTML).toBe("");
  });

  it("renders player when track is set", () => {
    usePlayerStore.setState({
      currentTrack: {
        mediaId: "m1",
        entryId: "e1",
        title: "Test Episode",
        feedTitle: "Test Podcast",
        audioUrl: "https://example.com/ep.mp3",
        thumbnailUrl: null,
        durationSeconds: 3600,
      },
      isPlaying: true,
    });
    renderAudioPlayer();
    expect(screen.getByText("Test Episode")).toBeTruthy();
    expect(screen.getByText("Test Podcast")).toBeTruthy();
  });

  it("shows play button when paused", () => {
    usePlayerStore.setState({
      currentTrack: {
        mediaId: "m1",
        entryId: "e1",
        title: "Episode",
        feedTitle: "Show",
        audioUrl: "https://example.com/ep.mp3",
        thumbnailUrl: null,
        durationSeconds: 1800,
      },
      isPlaying: false,
    });
    renderAudioPlayer();
    // Play button shows triangle
    expect(screen.getByText("\u25B6")).toBeTruthy();
  });

  it("shows pause indicator when playing", () => {
    usePlayerStore.setState({
      currentTrack: {
        mediaId: "m1",
        entryId: "e1",
        title: "Episode",
        feedTitle: "Show",
        audioUrl: "https://example.com/ep.mp3",
        thumbnailUrl: null,
        durationSeconds: 1800,
      },
      isPlaying: true,
    });
    renderAudioPlayer();
    expect(screen.getByText("||")).toBeTruthy();
  });

  it("renders playback rate selector", () => {
    usePlayerStore.setState({
      currentTrack: {
        mediaId: "m1",
        entryId: "e1",
        title: "Episode",
        feedTitle: "Show",
        audioUrl: "https://example.com/ep.mp3",
        thumbnailUrl: null,
        durationSeconds: 1800,
      },
    });
    renderAudioPlayer();
    expect(screen.getByText("1x")).toBeTruthy();
    expect(screen.getByText("1.5x")).toBeTruthy();
    expect(screen.getByText("2x")).toBeTruthy();
  });

  it("shows skip buttons", () => {
    usePlayerStore.setState({
      currentTrack: {
        mediaId: "m1",
        entryId: "e1",
        title: "Episode",
        feedTitle: "Show",
        audioUrl: "https://example.com/ep.mp3",
        thumbnailUrl: null,
        durationSeconds: 1800,
      },
    });
    renderAudioPlayer();
    expect(screen.getByText("-15")).toBeTruthy();
    expect(screen.getByText("+30")).toBeTruthy();
  });

  it("shows queue badge when items in queue", () => {
    usePlayerStore.setState({
      currentTrack: {
        mediaId: "m1",
        entryId: "e1",
        title: "Episode 1",
        feedTitle: "Show",
        audioUrl: "https://example.com/ep1.mp3",
        thumbnailUrl: null,
        durationSeconds: 1800,
      },
      queue: [
        {
          mediaId: "m2",
          entryId: "e2",
          title: "Episode 2",
          feedTitle: "Show",
          audioUrl: "https://example.com/ep2.mp3",
          thumbnailUrl: null,
          durationSeconds: 2400,
        },
      ],
    });
    renderAudioPlayer();
    expect(screen.getByText("1 in queue")).toBeTruthy();
  });
});
