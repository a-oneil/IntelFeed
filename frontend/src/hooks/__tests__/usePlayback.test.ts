import { describe, it, expect } from "vitest";
import { usePlayerStore } from "@/stores/playerStore";

describe("playerStore", () => {
  it("starts with no track", () => {
    const state = usePlayerStore.getState();
    expect(state.currentTrack).toBeNull();
    expect(state.isPlaying).toBe(false);
    expect(state.queue).toEqual([]);
  });

  it("plays a track", () => {
    const track = {
      mediaId: "m1",
      entryId: "e1",
      title: "Test Episode",
      feedTitle: "Test Show",
      audioUrl: "https://example.com/ep.mp3",
      thumbnailUrl: null,
      durationSeconds: 3600,
    };

    usePlayerStore.getState().play(track);

    const state = usePlayerStore.getState();
    expect(state.currentTrack).toEqual(track);
    expect(state.isPlaying).toBe(true);
    expect(state.currentTime).toBe(0);
  });

  it("pauses and resumes", () => {
    usePlayerStore.getState().pause();
    expect(usePlayerStore.getState().isPlaying).toBe(false);

    usePlayerStore.getState().resume();
    expect(usePlayerStore.getState().isPlaying).toBe(true);
  });

  it("stops playback", () => {
    usePlayerStore.getState().stop();
    expect(usePlayerStore.getState().currentTrack).toBeNull();
    expect(usePlayerStore.getState().isPlaying).toBe(false);
  });

  it("manages queue", () => {
    const track1 = {
      mediaId: "m1",
      entryId: "e1",
      title: "Ep 1",
      feedTitle: "Show",
      audioUrl: "url1",
      thumbnailUrl: null,
      durationSeconds: 1800,
    };
    const track2 = {
      mediaId: "m2",
      entryId: "e2",
      title: "Ep 2",
      feedTitle: "Show",
      audioUrl: "url2",
      thumbnailUrl: null,
      durationSeconds: 2400,
    };

    usePlayerStore.getState().addToQueue(track1);
    usePlayerStore.getState().addToQueue(track2);
    expect(usePlayerStore.getState().queue).toHaveLength(2);

    // Adding duplicate should not increase queue
    usePlayerStore.getState().addToQueue(track1);
    expect(usePlayerStore.getState().queue).toHaveLength(2);
  });

  it("removes from queue", () => {
    usePlayerStore.getState().removeFromQueue("m1");
    expect(usePlayerStore.getState().queue).toHaveLength(1);
    expect(usePlayerStore.getState().queue[0].mediaId).toBe("m2");
  });

  it("plays next from queue", () => {
    usePlayerStore.getState().playNext();
    expect(usePlayerStore.getState().currentTrack?.mediaId).toBe("m2");
    expect(usePlayerStore.getState().isPlaying).toBe(true);
    expect(usePlayerStore.getState().queue).toHaveLength(0);
  });

  it("stops when queue is empty and playNext called", () => {
    usePlayerStore.getState().playNext();
    expect(usePlayerStore.getState().currentTrack).toBeNull();
    expect(usePlayerStore.getState().isPlaying).toBe(false);
  });

  it("sets playback rate", () => {
    usePlayerStore.getState().setPlaybackRate(1.5);
    expect(usePlayerStore.getState().playbackRate).toBe(1.5);
  });

  it("sets volume", () => {
    usePlayerStore.getState().setVolume(0.7);
    expect(usePlayerStore.getState().volume).toBe(0.7);
  });

  it("clears queue", () => {
    usePlayerStore.getState().addToQueue({
      mediaId: "m3",
      entryId: "e3",
      title: "Ep 3",
      feedTitle: "Show",
      audioUrl: "url3",
      thumbnailUrl: null,
      durationSeconds: 1200,
    });
    usePlayerStore.getState().clearQueue();
    expect(usePlayerStore.getState().queue).toHaveLength(0);
  });
});
