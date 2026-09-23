import { useCallback, useEffect, useRef, useState } from "react";
import { Chip } from "@/components/primitives";
import { usePlayerStore } from "@/stores/playerStore";
import { useUIStore } from "@/stores/uiStore";
import { useUpdatePlayback, useMarkPlaybackComplete } from "@/hooks/usePlayback";
import styles from "./AudioPlayer.module.css";

const PLAYBACK_RATES = [0.5, 0.75, 1, 1.25, 1.5, 2];
const SAVE_INTERVAL = 30_000; // Save progress every 30s

const VOICE_STORAGE_KEY = "intelfeed:readAloud:voice";
const SPEECH_PROGRESS_KEY = "intelfeed:readAloud:progress";
const SPEECH_PROGRESS_MAX_ENTRIES = 50;
// Chrome / Edge cut off utterances after ~15 seconds. Pinging pause/resume
// every 10s while speaking keeps the queue alive on long paragraphs.
const KEEP_ALIVE_INTERVAL = 10_000;
// Watchdog: if speechSynthesis hasn't been speaking for this long while we
// still think we're reading, assume it stalled and recover.
const STALL_RECOVERY_MS = 3_000;

/**
 * Detect any mobile device. The pause()/resume() keep-alive trick is a
 * desktop Chromium workaround for the 15s utterance cutoff — on mobile it
 * tends to make things worse: iOS Safari permanently stalls on pause(), and
 * Android Chrome has its own quirks where pause/resume can cause silent
 * dropouts. The stall watchdog handles cutoffs on mobile instead.
 */
function isMobileDevice(): boolean {
  if (typeof navigator === "undefined") return false;
  const ua = navigator.userAgent;
  if (/Mobi|Android|iPad|iPhone|iPod/i.test(ua)) return true;
  // iPadOS reports as Mac — distinguish via touch support.
  return ua.includes("Mac") && typeof document !== "undefined" && "ontouchend" in document;
}

interface SavedSpeechProgress {
  i: number; // paragraph index
  t: number; // last-updated timestamp (ms)
}

function readSpeechProgress(entryId: string): number {
  try {
    const raw = localStorage.getItem(SPEECH_PROGRESS_KEY);
    if (!raw) return 0;
    const data = JSON.parse(raw) as Record<string, SavedSpeechProgress>;
    return data[entryId]?.i ?? 0;
  } catch {
    return 0;
  }
}

function writeSpeechProgress(entryId: string, index: number) {
  try {
    const raw = localStorage.getItem(SPEECH_PROGRESS_KEY);
    const data: Record<string, SavedSpeechProgress> = raw ? JSON.parse(raw) : {};
    data[entryId] = { i: index, t: Date.now() };
    // Keep only the most recent N so localStorage doesn't grow unboundedly.
    const trimmed = Object.entries(data)
      .sort(([, a], [, b]) => b.t - a.t)
      .slice(0, SPEECH_PROGRESS_MAX_ENTRIES);
    localStorage.setItem(SPEECH_PROGRESS_KEY, JSON.stringify(Object.fromEntries(trimmed)));
  } catch {
    // ignore quota or parse errors
  }
}

function clearSpeechProgress(entryId: string) {
  try {
    const raw = localStorage.getItem(SPEECH_PROGRESS_KEY);
    if (!raw) return;
    const data = JSON.parse(raw) as Record<string, SavedSpeechProgress>;
    if (data[entryId]) {
      delete data[entryId];
      localStorage.setItem(SPEECH_PROGRESS_KEY, JSON.stringify(data));
    }
  } catch {
    // ignore
  }
}

function formatTime(seconds: number): string {
  if (!seconds || !isFinite(seconds)) return "0:00";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (h > 0) {
    return `${h}:${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`;
  }
  return `${m}:${s.toString().padStart(2, "0")}`;
}

/** Score a voice for quality — higher is better */
function scoreVoice(v: SpeechSynthesisVoice): number {
  let score = 0;
  const name = v.name.toLowerCase();
  if (!v.localService) score -= 5;
  if (v.lang.startsWith("en")) score += 10;
  if (name.includes("enhanced") || name.includes("premium") || name.includes("natural")) score += 20;
  if (name.includes("google")) score += 5;
  if (name.includes("microsoft") && name.includes("online")) score += 3;
  if (name.includes("samantha")) score += 8;
  if (name.includes("whisper") || name.includes("zarvox") || name.includes("trinoids")) score -= 50;
  return score;
}

function AudioMode() {
  const audioRef = useRef<HTMLAudioElement>(null);
  const saveTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const lastSavedRef = useRef<number>(0);
  const setSelectedEntry = useUIStore((s) => s.setSelectedEntry);

  const {
    currentTrack,
    isPlaying,
    currentTime,
    duration,
    playbackRate,
    volume,
    pause,
    resume,
    setCurrentTime,
    setDuration,
    setPlaybackRate,
    setVolume,
    playNext,
    stop,
    queue,
  } = usePlayerStore();

  const updatePlayback = useUpdatePlayback();
  const markComplete = useMarkPlaybackComplete();

  useEffect(() => {
    const audio = audioRef.current;
    if (!audio || !currentTrack) return;
    audio.src = currentTrack.audioUrl;
    audio.playbackRate = playbackRate;
    audio.volume = volume;
    if (isPlaying) {
      audio.play().catch(() => {});
    }
  }, [currentTrack?.mediaId]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const audio = audioRef.current;
    if (!audio) return;
    if (isPlaying) {
      audio.play().catch(() => {});
    } else {
      audio.pause();
    }
  }, [isPlaying]);

  useEffect(() => {
    const audio = audioRef.current;
    if (audio) audio.playbackRate = playbackRate;
  }, [playbackRate]);

  useEffect(() => {
    const audio = audioRef.current;
    if (audio) audio.volume = volume;
  }, [volume]);

  useEffect(() => {
    // Generated TTS tracks have a synthetic mediaId with no backend playback row.
    if (!currentTrack || !isPlaying || currentTrack.kind === "tts") {
      if (saveTimerRef.current) clearInterval(saveTimerRef.current);
      return;
    }

    saveTimerRef.current = setInterval(() => {
      const audio = audioRef.current;
      if (audio && currentTrack && Math.abs(audio.currentTime - lastSavedRef.current) > 5) {
        lastSavedRef.current = audio.currentTime;
        updatePlayback.mutate({
          mediaId: currentTrack.mediaId,
          position: Math.floor(audio.currentTime),
        });
      }
    }, SAVE_INTERVAL);

    return () => {
      if (saveTimerRef.current) clearInterval(saveTimerRef.current);
    };
  }, [currentTrack?.mediaId, isPlaying]); // eslint-disable-line react-hooks/exhaustive-deps

  const saveAndStop = useCallback(() => {
    if (currentTrack && currentTrack.kind !== "tts" && audioRef.current) {
      updatePlayback.mutate({
        mediaId: currentTrack.mediaId,
        position: Math.floor(audioRef.current.currentTime),
      });
    }
  }, [currentTrack, updatePlayback]);

  const handleTimeUpdate = () => {
    const audio = audioRef.current;
    if (audio) setCurrentTime(audio.currentTime);
  };

  const handleLoadedMetadata = () => {
    const audio = audioRef.current;
    if (audio) setDuration(audio.duration);
  };

  const handleEnded = () => {
    if (currentTrack && currentTrack.kind !== "tts") {
      markComplete.mutate(currentTrack.mediaId);
    }
    playNext();
  };

  const handleSeek = (e: React.ChangeEvent<HTMLInputElement>) => {
    const time = Number(e.target.value);
    const audio = audioRef.current;
    if (audio) {
      audio.currentTime = time;
      setCurrentTime(time);
    }
  };

  const skipForward = () => {
    const audio = audioRef.current;
    if (audio) {
      audio.currentTime = Math.min(audio.currentTime + 30, audio.duration);
      setCurrentTime(audio.currentTime);
    }
  };

  const skipBack = () => {
    const audio = audioRef.current;
    if (audio) {
      audio.currentTime = Math.max(audio.currentTime - 15, 0);
      setCurrentTime(audio.currentTime);
    }
  };

  if (!currentTrack) return null;

  const progress = duration > 0 ? (currentTime / duration) * 100 : 0;

  return (
    <div className={styles.player} role="region" aria-label="Audio player">
      <audio
        ref={audioRef}
        onTimeUpdate={handleTimeUpdate}
        onLoadedMetadata={handleLoadedMetadata}
        onEnded={handleEnded}
      />

      <button
        className={styles.trackInfo}
        onClick={() => setSelectedEntry(currentTrack.entryId)}
        title="Open article"
      >
        {currentTrack.thumbnailUrl && (
          <img
            src={currentTrack.thumbnailUrl}
            alt=""
            className={styles.thumbnail}
          />
        )}
        <div className={styles.trackText}>
          <span className={styles.trackTitle}>{currentTrack.title}</span>
          <span className={styles.trackFeed}>{currentTrack.feedTitle}</span>
        </div>
      </button>

      <div className={styles.controls}>
        <button className={styles.controlBtn} onClick={skipBack} title="Back 15s" aria-label="Skip back 15 seconds">
          -15
        </button>
        <button
          className={`${styles.controlBtn} ${styles.playBtn}`}
          onClick={() => (isPlaying ? pause() : resume())}
          aria-label={isPlaying ? "Pause" : "Play"}
        >
          {isPlaying ? "||" : "\u25B6"}
        </button>
        <button className={styles.controlBtn} onClick={skipForward} title="Forward 30s" aria-label="Skip forward 30 seconds">
          +30
        </button>
      </div>

      <div className={styles.progressSection}>
        <span className={styles.time}>{formatTime(currentTime)}</span>
        <input
          type="range"
          min={0}
          max={duration || 0}
          value={currentTime}
          onChange={handleSeek}
          className={styles.progressBar}
          style={{ "--progress": `${progress}%` } as React.CSSProperties}
          aria-label="Playback progress"
        />
        <span className={styles.time}>{formatTime(duration)}</span>
      </div>

      <div className={styles.extras}>
        <select
          value={playbackRate}
          onChange={(e) => setPlaybackRate(Number(e.target.value))}
          className={styles.rateSelect}
          aria-label="Playback speed"
        >
          {PLAYBACK_RATES.map((r) => (
            <option key={r} value={r}>
              {r}x
            </option>
          ))}
        </select>

        <input
          type="range"
          min={0}
          max={1}
          step={0.05}
          value={volume}
          onChange={(e) => setVolume(Number(e.target.value))}
          className={styles.volumeSlider}
          title={`Volume: ${Math.round(volume * 100)}%`}
          aria-label={`Volume: ${Math.round(volume * 100)}%`}
        />

        {queue.length > 0 && <Chip pill>{queue.length} in queue</Chip>}

        <button
          className={styles.controlBtn}
          onClick={() => {
            saveAndStop();
            stop();
          }}
          title="Close player"
          aria-label="Close player"
        >
          x
        </button>
      </div>
    </div>
  );
}

function SpeechMode() {
  const setSelectedEntry = useUIStore((s) => s.setSelectedEntry);
  const {
    speechTrack,
    speechIndex,
    speechTotal,
    speechPaused,
    playbackRate,
    isPlaying,
    setSpeechIndex,
    setSpeechPaused,
    setSpeechWord,
    speechSkipRequest,
    requestSpeechSkip,
    setPlaybackRate,
    stopSpeech,
  } = usePlayerStore();

  const [voices, setVoices] = useState<SpeechSynthesisVoice[]>([]);
  const [selectedVoiceURI, setSelectedVoiceURI] = useState<string | null>(
    () => localStorage.getItem(VOICE_STORAGE_KEY),
  );
  const selectedVoiceURIRef = useRef(selectedVoiceURI);
  const isReadingRef = useRef(false);
  const currentIndexRef = useRef(0);
  const paragraphsRef = useRef<string[]>([]);
  const playbackRateRef = useRef(playbackRate);
  // Generation token: bumped on every speakParagraph() / cancel so stale
  // onend/onerror callbacks from canceled utterances are ignored. Without this,
  // cancel() can fire onend for the previous utterance after we've already
  // queued the next one, causing the same paragraph to be re-read.
  const generationRef = useRef(0);
  const isSupported = typeof window !== "undefined" && "speechSynthesis" in window;

  // Keep refs in sync
  useEffect(() => { selectedVoiceURIRef.current = selectedVoiceURI; }, [selectedVoiceURI]);
  useEffect(() => { playbackRateRef.current = playbackRate; }, [playbackRate]);

  // Load voices
  useEffect(() => {
    if (!isSupported) return;
    const loadVoices = () => {
      const v = window.speechSynthesis.getVoices();
      if (v.length > 0) setVoices(v);
    };
    loadVoices();
    window.speechSynthesis.addEventListener("voiceschanged", loadVoices);
    return () => window.speechSynthesis.removeEventListener("voiceschanged", loadVoices);
  }, [isSupported]);

  // Clean up on unmount
  useEffect(() => {
    return () => {
      if (isSupported) {
        generationRef.current++;
        window.speechSynthesis.cancel();
      }
    };
  }, [isSupported]);

  /** Read voices fresh from the API to avoid stale closures */
  const getVoice = useCallback((): SpeechSynthesisVoice | null => {
    const available = window.speechSynthesis.getVoices();
    if (available.length === 0) return null;
    const uri = selectedVoiceURIRef.current;
    if (uri) {
      const match = available.find((v) => v.voiceURI === uri);
      if (match) return match;
    }
    const sorted = [...available].sort((a, b) => scoreVoice(b) - scoreVoice(a));
    return sorted[0] || null;
  }, []);

  const speakParagraph = useCallback(
    (index: number) => {
      if (!isSupported) return;
      const paragraphs = paragraphsRef.current;
      if (index < 0 || index >= paragraphs.length) {
        generationRef.current++;
        window.speechSynthesis.cancel();
        isReadingRef.current = false;
        // Reached the end — clear saved progress so the next play starts fresh.
        if (speechTrack) clearSpeechProgress(speechTrack.entryId);
        stopSpeech();
        return;
      }

      // Bump the generation token before cancel() so any onend/onerror that
      // fires for the previous (now-canceled) utterance is ignored.
      const myGen = ++generationRef.current;
      window.speechSynthesis.cancel();

      const text = paragraphs[index];
      if (!text.trim()) {
        currentIndexRef.current = index + 1;
        setSpeechIndex(index + 1);
        speakParagraph(index + 1);
        return;
      }

      const utterance = new SpeechSynthesisUtterance(text);
      const utteranceRate = playbackRateRef.current;
      utterance.rate = utteranceRate;
      utterance.pitch = 1.0;

      const voice = getVoice();
      if (voice) utterance.voice = voice;

      // Word-position table for the timer-based highlight fallback. Mobile
      // browsers (Android Chrome especially) don't fire onboundary events for
      // most voices, so without this the highlight stays frozen on mobile.
      const wordPositions: Array<{ start: number; len: number; t: number }> = [];
      // Approximate speech rate: ~15 chars/sec at rate 1.0 (~150 wpm with avg
      // 6-char words). Scaled by the utterance rate.
      const charsPerSec = 15 * Math.max(0.1, utteranceRate);
      const wordRe = /\S+/g;
      let wm: RegExpExecArray | null;
      while ((wm = wordRe.exec(text)) !== null) {
        wordPositions.push({
          start: wm.index,
          len: wm[0].length,
          t: (wm.index / charsPerSec) * 1000,
        });
      }

      let boundaryFired = false;
      let fallbackInterval: ReturnType<typeof setInterval> | null = null;
      let fallbackStartTimer: ReturnType<typeof setTimeout> | null = null;
      let fallbackStartTime = 0;
      let fallbackPausedAt: number | null = null;
      let fallbackPausedDuration = 0;
      let fallbackWordIdx = -1;

      const stopFallback = () => {
        if (fallbackStartTimer) {
          clearTimeout(fallbackStartTimer);
          fallbackStartTimer = null;
        }
        if (fallbackInterval) {
          clearInterval(fallbackInterval);
          fallbackInterval = null;
        }
      };

      const startFallbackHighlight = () => {
        if (fallbackInterval || boundaryFired) return;
        if (wordPositions.length === 0) return;
        fallbackStartTime = Date.now();
        fallbackInterval = setInterval(() => {
          if (myGen !== generationRef.current || boundaryFired) {
            stopFallback();
            return;
          }
          const synth = window.speechSynthesis;
          if (synth.paused) {
            if (fallbackPausedAt === null) fallbackPausedAt = Date.now();
            return;
          }
          if (fallbackPausedAt !== null) {
            fallbackPausedDuration += Date.now() - fallbackPausedAt;
            fallbackPausedAt = null;
          }
          const elapsed = Date.now() - fallbackStartTime - fallbackPausedDuration;
          // Find the latest word whose start time has been reached.
          let idx = fallbackWordIdx;
          while (idx + 1 < wordPositions.length && wordPositions[idx + 1].t <= elapsed) {
            idx++;
          }
          if (idx !== fallbackWordIdx && idx >= 0) {
            fallbackWordIdx = idx;
            const w = wordPositions[idx];
            setSpeechWord(w.start, w.len);
          }
        }, 100);
      };

      utterance.onstart = () => {
        if (myGen !== generationRef.current) return;
        isReadingRef.current = true;
        setSpeechIndex(index);
        setSpeechWord(-1, 0);
        currentIndexRef.current = index;
        if (speechTrack) writeSpeechProgress(speechTrack.entryId, index);
        // Wait briefly to see if the browser will deliver real onboundary
        // events. If not (mobile), kick in the timer-based estimator.
        fallbackStartTimer = setTimeout(() => {
          fallbackStartTimer = null;
          if (!boundaryFired) startFallbackHighlight();
        }, 350);
      };

      utterance.onboundary = (e) => {
        if (myGen !== generationRef.current) return;
        if (e.name === "word") {
          if (!boundaryFired) {
            boundaryFired = true;
            stopFallback();
          }
          const len = e.charLength ?? text.slice(e.charIndex).match(/^\S+/)?.[0]?.length ?? 0;
          setSpeechWord(e.charIndex, len);
        }
      };

      utterance.onend = () => {
        stopFallback();
        if (myGen !== generationRef.current) return;
        if (!isReadingRef.current) return;
        const nextIdx = index + 1;
        currentIndexRef.current = nextIdx;
        setSpeechIndex(nextIdx);
        speakParagraph(nextIdx);
      };

      utterance.onerror = (e) => {
        stopFallback();
        if (myGen !== generationRef.current) return;
        if (e.error !== "interrupted" && e.error !== "canceled") {
          if (import.meta.env.DEV) console.warn("Speech synthesis error:", e.error);
          if (isReadingRef.current) {
            const nextIdx = index + 1;
            currentIndexRef.current = nextIdx;
            setSpeechIndex(nextIdx);
            speakParagraph(nextIdx);
            return;
          }
        }
      };

      window.speechSynthesis.speak(utterance);
    },
    [isSupported, getVoice, setSpeechIndex, setSpeechWord, stopSpeech, speechTrack],
  );

  // Start speaking when speechTrack changes. Wait for the voices list to be
  // populated before kicking off — otherwise getVoice() returns null and the
  // first paragraph is read with the system default (robot) voice instead of
  // the user's selection.
  useEffect(() => {
    if (!speechTrack || !isSupported) return;
    paragraphsRef.current = speechTrack.paragraphs;
    // Resume from where the user left off last time on this entry. If the
    // saved index is past the end (entry was finished), start from the top.
    const saved = readSpeechProgress(speechTrack.entryId);
    const startIndex = saved > 0 && saved < speechTrack.paragraphs.length ? saved : 0;
    currentIndexRef.current = startIndex;
    if (startIndex !== 0) setSpeechIndex(startIndex);
    isReadingRef.current = true;

    let cancelled = false;
    let startTimer: ReturnType<typeof setTimeout> | null = null;
    let fallbackTimer: ReturnType<typeof setTimeout> | null = null;

    const begin = () => {
      if (cancelled) return;
      window.speechSynthesis.removeEventListener("voiceschanged", onVoicesReady);
      if (fallbackTimer) {
        clearTimeout(fallbackTimer);
        fallbackTimer = null;
      }
      // Small delay so any previous cancel() can settle first.
      startTimer = setTimeout(() => {
        if (!cancelled) speakParagraph(startIndex);
      }, 50);
    };

    const onVoicesReady = () => {
      if (window.speechSynthesis.getVoices().length > 0) begin();
    };

    if (window.speechSynthesis.getVoices().length > 0) {
      begin();
    } else {
      window.speechSynthesis.addEventListener("voiceschanged", onVoicesReady);
      // Some browsers never fire voiceschanged — start anyway after 1s.
      fallbackTimer = setTimeout(begin, 1000);
    }

    return () => {
      cancelled = true;
      window.speechSynthesis.removeEventListener("voiceschanged", onVoicesReady);
      if (startTimer) clearTimeout(startTimer);
      if (fallbackTimer) clearTimeout(fallbackTimer);
    };
  }, [speechTrack]); // eslint-disable-line react-hooks/exhaustive-deps

  // Handle stop from outside (e.g. entry change)
  useEffect(() => {
    if (!speechTrack && isReadingRef.current) {
      generationRef.current++;
      isReadingRef.current = false;
      window.speechSynthesis.cancel();
    }
  }, [speechTrack]);

  const handlePause = () => {
    window.speechSynthesis.pause();
    setSpeechPaused(true);
  };

  const handleResume = () => {
    window.speechSynthesis.resume();
    setSpeechPaused(false);
  };

  const skipTo = (index: number) => {
    generationRef.current++;
    isReadingRef.current = false;
    window.speechSynthesis.cancel();
    currentIndexRef.current = index;
    setSpeechIndex(index);
    setSpeechPaused(false);
    setTimeout(() => {
      isReadingRef.current = true;
      speakParagraph(index);
    }, 50);
  };

  // Handle external skip requests (e.g. clicking a paragraph in the article)
  useEffect(() => {
    if (speechSkipRequest >= 0) {
      skipTo(speechSkipRequest);
      requestSpeechSkip(-1);
    }
  }, [speechSkipRequest]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleNext = () => {
    const nextIdx = Math.min(currentIndexRef.current + 1, paragraphsRef.current.length - 1);
    skipTo(nextIdx);
  };

  const handlePrev = () => {
    const prevIdx = Math.max(currentIndexRef.current - 1, 0);
    skipTo(prevIdx);
  };

  const handleStop = () => {
    generationRef.current++;
    isReadingRef.current = false;
    window.speechSynthesis.cancel();
    paragraphsRef.current = [];
    stopSpeech();
  };

  // Refs for the latest handler closures so the Media Session effect can call
  // them without being re-registered on every render.
  const skipToRef = useRef(skipTo);
  const handleStopRef = useRef(handleStop);
  skipToRef.current = skipTo;
  handleStopRef.current = handleStop;

  // Chrome / Edge cut off speechSynthesis utterances at ~15s. Ping pause()/
  // resume() every 10s while speaking to keep the queue alive on long
  // paragraphs. Skip on mobile — pause/resume is unreliable there (iOS
  // permanently stalls; Android Chrome silently drops speech). On mobile we
  // rely on the stall watchdog below to recover from any cutoffs.
  useEffect(() => {
    if (!isSupported || !speechTrack || !isPlaying || speechPaused) return;
    if (isMobileDevice()) return;
    const interval = setInterval(() => {
      if (window.speechSynthesis.speaking && !window.speechSynthesis.paused) {
        window.speechSynthesis.pause();
        window.speechSynthesis.resume();
      }
    }, KEEP_ALIVE_INTERVAL);
    return () => clearInterval(interval);
  }, [isSupported, speechTrack, isPlaying, speechPaused]);

  // Stall watchdog. Mobile browsers stop speaking without firing onend or
  // onerror in several scenarios (Android Chrome cutoff, app backgrounding,
  // audio focus loss). If speechSynthesis.speaking has been false for several
  // seconds while we're still supposed to be reading, advance to the next
  // paragraph as a recovery.
  useEffect(() => {
    if (!isSupported || !speechTrack || !isPlaying || speechPaused) return;
    let lastSpeakingAt = Date.now();
    let hasEverSpoken = false;
    const watchdog = setInterval(() => {
      const synth = window.speechSynthesis;
      if (synth.speaking) {
        lastSpeakingAt = Date.now();
        hasEverSpoken = true;
        return;
      }
      // Don't recover while user-paused, before we've actually started, or
      // while waiting for the first utterance to begin (voice loading, slow
      // synth startup, etc.).
      if (synth.paused || !isReadingRef.current || !hasEverSpoken) return;
      if (Date.now() - lastSpeakingAt < STALL_RECOVERY_MS) return;

      lastSpeakingAt = Date.now(); // debounce so we don't fire repeatedly
      const next = currentIndexRef.current + 1;
      if (next < paragraphsRef.current.length) {
        if (import.meta.env.DEV) {
          console.warn("[read-aloud] watchdog: speech stalled, advancing");
        }
        skipToRef.current(next);
      } else {
        // At end already — just stop cleanly.
        handleStopRef.current();
      }
    }, 1000);
    return () => clearInterval(watchdog);
  }, [isSupported, speechTrack, isPlaying, speechPaused]);

  // Media Session API — show the player on iOS lock screen / Android
  // notification shade with native play/pause/skip controls.
  // NOTE: skipped on mobile. Speech Synthesis doesn't route through the
  // browser's media pipeline, so Android's audio focus manager tears down
  // the session a few seconds after we declare playbackState = "playing"
  // (no actual audio output backing it), which kills speech mid-paragraph.
  // Re-enable once we play a silent audio loop alongside speech.
  useEffect(() => {
    if (!speechTrack) return;
    if (typeof navigator === "undefined" || !("mediaSession" in navigator)) return;
    if (isMobileDevice()) return;

    const ms = navigator.mediaSession;
    ms.metadata = new MediaMetadata({
      title: speechTrack.title,
      artist: speechTrack.feedTitle || "IntelFeed",
      album: "IntelFeed",
    });
    ms.playbackState = speechPaused ? "paused" : "playing";

    ms.setActionHandler("play", () => {
      window.speechSynthesis.resume();
      setSpeechPaused(false);
    });
    ms.setActionHandler("pause", () => {
      window.speechSynthesis.pause();
      setSpeechPaused(true);
    });
    ms.setActionHandler("nexttrack", () => {
      const next = Math.min(
        currentIndexRef.current + 1,
        paragraphsRef.current.length - 1,
      );
      skipToRef.current(next);
    });
    ms.setActionHandler("previoustrack", () => {
      const prev = Math.max(currentIndexRef.current - 1, 0);
      skipToRef.current(prev);
    });
    ms.setActionHandler("stop", () => handleStopRef.current());

    return () => {
      ms.setActionHandler("play", null);
      ms.setActionHandler("pause", null);
      ms.setActionHandler("nexttrack", null);
      ms.setActionHandler("previoustrack", null);
      ms.setActionHandler("stop", null);
      ms.metadata = null;
      ms.playbackState = "none";
    };
  }, [speechTrack, speechPaused, setSpeechPaused]);

  const handleVoiceChange = (uri: string) => {
    setSelectedVoiceURI(uri);
    localStorage.setItem(VOICE_STORAGE_KEY, uri);
  };

  if (!speechTrack || !isPlaying) return null;

  const progress = speechTotal > 0 ? ((speechIndex + 1) / speechTotal) * 100 : 0;

  return (
    <div className={styles.player} role="region" aria-label="Read aloud player">
      <button
        className={styles.trackInfo}
        onClick={() => setSelectedEntry(speechTrack.entryId)}
        title="Open article"
      >
        <div className={styles.speechIcon} aria-hidden="true">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5" />
            <path d="M15.54 8.46a5 5 0 0 1 0 7.07" />
            <path d="M19.07 4.93a10 10 0 0 1 0 14.14" />
          </svg>
        </div>
        <div className={styles.trackText}>
          <span className={styles.trackTitle}>{speechTrack.title}</span>
          <span className={styles.trackFeed}>{speechTrack.feedTitle}</span>
        </div>
      </button>

      <div className={styles.controls}>
        <button className={styles.controlBtn} onClick={handlePrev} title="Previous paragraph" aria-label="Previous paragraph">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M6 6h2v12H6zm3.5 6l8.5 6V6z"/></svg>
        </button>
        <button
          className={`${styles.controlBtn} ${styles.playBtn}`}
          onClick={() => (speechPaused ? handleResume() : handlePause())}
          aria-label={speechPaused ? "Resume" : "Pause"}
        >
          {speechPaused ? "\u25B6" : "||"}
        </button>
        <button className={styles.controlBtn} onClick={handleNext} title="Next paragraph" aria-label="Next paragraph">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M6 18l8.5-6L6 6v12zM16 6v12h2V6h-2z"/></svg>
        </button>
      </div>

      <div className={styles.progressSection}>
        <span className={styles.time}>{speechIndex + 1} / {speechTotal}</span>
        <input
          type="range"
          min={0}
          max={speechTotal - 1}
          value={speechIndex}
          onChange={(e) => skipTo(Number(e.target.value))}
          className={styles.progressBar}
          style={{ "--progress": `${progress}%` } as React.CSSProperties}
          aria-label="Reading progress"
        />
      </div>

      <div className={styles.extras}>
        <select
          value={playbackRate}
          onChange={(e) => setPlaybackRate(Number(e.target.value))}
          className={styles.rateSelect}
          aria-label="Speech speed"
        >
          {PLAYBACK_RATES.map((r) => (
            <option key={r} value={r}>
              {r}x
            </option>
          ))}
        </select>

        <select
          className={`${styles.rateSelect} ${styles.voiceSelect}`}
          value={selectedVoiceURI || ""}
          onChange={(e) => handleVoiceChange(e.target.value)}
          aria-label="Voice"
          title="Voice"
        >
          <option value="">Auto</option>
          {voices
            .filter((v) => v.lang.startsWith("en"))
            .map((v) => (
              <option key={v.voiceURI} value={v.voiceURI}>
                {v.name.replace(/\s*\(.*?\)\s*/g, "")}
              </option>
            ))}
          {voices.filter((v) => !v.lang.startsWith("en")).length > 0 && (
            <optgroup label="Other languages">
              {voices
                .filter((v) => !v.lang.startsWith("en"))
                .map((v) => (
                  <option key={v.voiceURI} value={v.voiceURI}>
                    {v.name.replace(/\s*\(.*?\)\s*/g, "")} ({v.lang})
                  </option>
                ))}
            </optgroup>
          )}
        </select>

        <button
          className={styles.controlBtn}
          onClick={handleStop}
          title="Close player"
          aria-label="Close player"
        >
          x
        </button>
      </div>
    </div>
  );
}

export function AudioPlayer() {
  const mode = usePlayerStore((s) => s.mode);
  const hasAudio = usePlayerStore((s) => !!s.currentTrack);
  const hasSpeech = usePlayerStore((s) => !!s.speechTrack && s.isPlaying);

  if (mode === "speech" && hasSpeech) return <SpeechMode />;
  if (hasAudio) return <AudioMode />;
  return null;
}
