"""Minimal HTTP wrapper around Piper TTS for IntelFeed.

Runs as an isolated sidecar (like the LibreTranslate service) so the heavy
ONNX/audio deps stay out of the shared backend image. The celery-worker POSTs
article/summary text here and gets back an MP3; nothing else talks to this service.

Synthesis STREAMS piper's audio chunks straight into ffmpeg (writing MP3 to a
temp file) rather than buffering the whole WAV in memory — a ~13-minute daily
summary would otherwise build a ~30MB+ WAV and OOM the 512M container. A lock
serializes synthesis so concurrent requests can't stack peak memory.
"""

import os
import subprocess
import tempfile
import threading

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from piper import PiperVoice
from pydantic import BaseModel

VOICE_DIR = os.environ.get("PIPER_VOICE_DIR", "/voices")
VOICE_NAME = os.environ.get("PIPER_VOICE", "en_US-lessac-medium")
MODEL_PATH = os.path.join(VOICE_DIR, f"{VOICE_NAME}.onnx")
# Low bitrate mono keeps generated files tiny on the disk-constrained host.
MP3_BITRATE = os.environ.get("PIPER_MP3_BITRATE", "48k")

app = FastAPI(title="IntelFeed Piper TTS")
_voice: PiperVoice | None = None
_synth_lock = threading.Lock()  # bound peak memory: one synthesis at a time


def _get_voice() -> PiperVoice:
    """Load the voice model once and cache it for the process lifetime."""
    global _voice
    if _voice is None:
        if not os.path.exists(MODEL_PATH):
            raise HTTPException(status_code=503, detail=f"voice model not ready: {MODEL_PATH}")
        _voice = PiperVoice.load(MODEL_PATH)
    return _voice


class SynthesizeRequest(BaseModel):
    text: str


@app.get("/health")
def health() -> dict:
    return {"status": "ok" if os.path.exists(MODEL_PATH) else "loading", "voice": VOICE_NAME}


def _synthesize_to_mp3(voice: PiperVoice, text: str) -> bytes:
    """Stream piper audio chunks through ffmpeg → MP3 bytes (bounded memory)."""
    chunks = voice.synthesize(text)
    first = next(chunks, None)
    if first is None:
        raise HTTPException(status_code=500, detail="piper produced no audio")
    sample_rate = first.sample_rate

    tmp = tempfile.NamedTemporaryFile(suffix=".mp3", delete=False)
    tmp.close()
    try:
        proc = subprocess.Popen(
            [
                "ffmpeg", "-hide_banner", "-loglevel", "error",
                "-f", "s16le", "-ar", str(sample_rate), "-ac", "1", "-i", "pipe:0",
                "-c:a", "libmp3lame", "-b:a", MP3_BITRATE, "-y", tmp.name,
            ],
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            proc.stdin.write(first.audio_int16_bytes)
            for chunk in chunks:
                proc.stdin.write(chunk.audio_int16_bytes)
            proc.stdin.close()
        except BrokenPipeError:
            pass  # ffmpeg died; return code check below surfaces it
        rc = proc.wait()
        if rc != 0:
            err = proc.stderr.read().decode(errors="replace")[:300]
            raise HTTPException(status_code=500, detail=f"ffmpeg failed: {err}")
        with open(tmp.name, "rb") as fh:
            return fh.read()
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


@app.post("/synthesize")
def synthesize(req: SynthesizeRequest) -> Response:
    """Synthesize text to speech and return it as MP3 bytes."""
    text = (req.text or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="text is required")

    voice = _get_voice()
    with _synth_lock:
        audio = _synthesize_to_mp3(voice, text)
    return Response(content=audio, media_type="audio/mpeg")
