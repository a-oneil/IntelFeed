import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";

export interface QueueItem {
  mediaId: string;
  entryId: string;
  title: string;
  feedTitle: string;
  audioUrl: string;
  thumbnailUrl: string | null;
  durationSeconds: number | null;
  /** "podcast" = external episode with backend playback tracking; "tts" =
   *  server-generated read-aloud whose mediaId is synthetic (no playback row). */
  kind?: "podcast" | "tts";
}

export interface SpeechTrack {
  entryId: string;
  title: string;
  feedTitle: string;
  paragraphs: string[];
}

export type PlayerMode = "audio" | "speech";

interface PlayerState {
  // Mode
  mode: PlayerMode;
  // Current track (audio mode)
  currentTrack: QueueItem | null;
  isPlaying: boolean;
  currentTime: number;
  duration: number;
  playbackRate: number;
  volume: number;
  // Queue (audio mode)
  queue: QueueItem[];
  // Speech mode
  speechTrack: SpeechTrack | null;
  speechIndex: number;
  speechTotal: number;
  speechPaused: boolean;
  /** Character offset of the word currently being spoken within the paragraph */
  speechWordStart: number;
  /** Character length of the word currently being spoken */
  speechWordLength: number;
  /** Set externally to request a skip; SpeechMode consumes and resets to -1 */
  speechSkipRequest: number;
  // Actions — audio
  play: (track: QueueItem) => void;
  pause: () => void;
  resume: () => void;
  stop: () => void;
  setCurrentTime: (time: number) => void;
  setDuration: (duration: number) => void;
  setPlaybackRate: (rate: number) => void;
  setVolume: (volume: number) => void;
  addToQueue: (track: QueueItem) => void;
  removeFromQueue: (mediaId: string) => void;
  playNext: () => void;
  clearQueue: () => void;
  // Actions — speech
  playSpeech: (track: SpeechTrack) => void;
  setSpeechIndex: (index: number) => void;
  setSpeechTotal: (total: number) => void;
  setSpeechPaused: (paused: boolean) => void;
  setSpeechWord: (start: number, length: number) => void;
  requestSpeechSkip: (index: number) => void;
  stopSpeech: () => void;
}

export const usePlayerStore = create<PlayerState>()(
  persist(
    (set, get) => ({
  mode: "audio" as PlayerMode,
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
  speechWordStart: -1,
  speechWordLength: 0,
  speechSkipRequest: -1,

  play: (track) =>
    set({
      mode: "audio",
      currentTrack: track,
      isPlaying: true,
      currentTime: 0,
      duration: track.durationSeconds || 0,
      // Stop any active speech
      speechTrack: null,
      speechIndex: 0,
      speechTotal: 0,
    }),

  pause: () => set({ isPlaying: false }),
  resume: () => set({ isPlaying: true }),
  stop: () =>
    set({
      currentTrack: null,
      isPlaying: false,
      currentTime: 0,
      duration: 0,
      speechTrack: null,
      speechIndex: 0,
      speechTotal: 0,
    }),

  setCurrentTime: (time) => set({ currentTime: time }),
  setDuration: (duration) => set({ duration }),
  setPlaybackRate: (rate) => set({ playbackRate: rate }),
  setVolume: (volume) => set({ volume }),

  addToQueue: (track) =>
    set((s) => ({
      queue: s.queue.some((q) => q.mediaId === track.mediaId)
        ? s.queue
        : [...s.queue, track],
    })),

  removeFromQueue: (mediaId) =>
    set((s) => ({ queue: s.queue.filter((q) => q.mediaId !== mediaId) })),

  playNext: () => {
    const { queue } = get();
    if (queue.length > 0) {
      const [next, ...rest] = queue;
      set({
        mode: "audio",
        currentTrack: next,
        isPlaying: true,
        currentTime: 0,
        duration: next.durationSeconds || 0,
        queue: rest,
      });
    } else {
      set({ currentTrack: null, isPlaying: false, currentTime: 0, duration: 0 });
    }
  },

  clearQueue: () => set({ queue: [] }),

  // Speech actions
  playSpeech: (track) =>
    set({
      mode: "speech",
      speechTrack: track,
      speechIndex: 0,
      speechTotal: track.paragraphs.length,
      speechPaused: false,
      isPlaying: true,
      // Clear audio track
      currentTrack: null,
      currentTime: 0,
      duration: 0,
    }),

  setSpeechIndex: (index) => set({ speechIndex: index }),
  setSpeechTotal: (total) => set({ speechTotal: total }),
  setSpeechPaused: (paused) => set({ speechPaused: paused }),
  setSpeechWord: (start, length) => set({ speechWordStart: start, speechWordLength: length }),
  requestSpeechSkip: (index) => set({ speechSkipRequest: index }),

  stopSpeech: () =>
    set({
      speechTrack: null,
      speechIndex: 0,
      speechTotal: 0,
      speechPaused: false,
      speechWordStart: -1,
      speechWordLength: 0,
      isPlaying: false,
    }),
    }),
    {
      name: "intelfeed-player",
      storage: createJSONStorage(() => {
        // Fall back to a no-op store when localStorage is missing or broken
        // (jsdom in tests, private mode, sandboxed iframes, etc.).
        if (
          typeof window === "undefined" ||
          !window.localStorage ||
          typeof window.localStorage.setItem !== "function"
        ) {
          const mem = new Map<string, string>();
          return {
            getItem: (k) => mem.get(k) ?? null,
            setItem: (k, v) => {
              mem.set(k, v);
            },
            removeItem: (k) => {
              mem.delete(k);
            },
          } as Storage;
        }
        return window.localStorage;
      }),
      // Only persist user preferences, not the active track/queue.
      partialize: (state) => ({
        playbackRate: state.playbackRate,
        volume: state.volume,
      }),
    },
  ),
);
