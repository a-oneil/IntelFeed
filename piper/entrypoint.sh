#!/bin/sh
# Download the configured Piper voice into the mounted volume on first boot,
# then start the HTTP wrapper. Keeping the model in a volume (not the image)
# lets the voice be swapped via PIPER_VOICE without rebuilding.
set -e

VOICE_DIR="${PIPER_VOICE_DIR:-/voices}"
VOICE_NAME="${PIPER_VOICE:-en_US-lessac-medium}"
mkdir -p "$VOICE_DIR"

if [ ! -f "$VOICE_DIR/$VOICE_NAME.onnx" ]; then
  echo "[piper] downloading voice '$VOICE_NAME' into $VOICE_DIR ..."
  python3 -m piper.download_voices --download-dir "$VOICE_DIR" "$VOICE_NAME"
fi

exec uvicorn server:app --host 0.0.0.0 --port 5000
