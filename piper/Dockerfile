# Isolated Piper TTS sidecar. Heavy ONNX/audio deps live here, not in the
# shared backend image (which rebuilds on every deploy against a build-cache cap).
FROM python:3.12.16-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        espeak-ng \
        ffmpeg \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
        "piper-tts==1.6.0" \
        "fastapi" \
        "uvicorn[standard]"

WORKDIR /app
COPY server.py entrypoint.sh ./
RUN chmod +x entrypoint.sh

ENV PIPER_VOICE=en_US-lessac-medium \
    PIPER_VOICE_DIR=/voices

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=3 \
    CMD curl -fsS http://localhost:5000/health || exit 1

ENTRYPOINT ["./entrypoint.sh"]
