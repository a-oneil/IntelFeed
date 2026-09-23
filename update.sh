#!/usr/bin/env bash
# Auto-update IntelFeed from main branch.
# Example cron (check every 15 minutes):
#   */2 * * * * /path/to/intelfeed/update.sh
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="docker-compose.prod.yml"
LOG_DIR="$REPO_DIR/logs"
mkdir -p "$LOG_DIR"
[ -w "$LOG_DIR" ] || sudo chown "$(id -u):$(id -g)" "$LOG_DIR"
LOG_FILE="$LOG_DIR/update.log"

log() {
    local level="${2:-info}"
    local ts
    ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    # Escape backslashes and double quotes for valid JSON
    local msg="${1//\\/\\\\}"
    msg="${msg//\"/\\\"}"
    local json="{\"timestamp\":\"$ts\",\"level\":\"$level\",\"event\":\"$msg\",\"logger\":\"update\"}"
    echo "$json" | tee -a "$LOG_FILE"
}

cd "$REPO_DIR"

# Fetch and check for changes
git fetch origin main --quiet

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

# Set between pulling and a clean build+start. Without it a failed build left the
# host on new code with old containers and nothing to retry: the next tick saw
# HEAD == origin/main and skipped, so the stack stayed stale until someone
# noticed. With it, every tick retries until the build succeeds.
PENDING_MARKER="$REPO_DIR/.update-pending"

if [ "$LOCAL" = "$REMOTE" ] && [ ! -f "$PENDING_MARKER" ]; then
    log "No changes, skipping." "debug"
    exit 0
fi

if [ "$LOCAL" != "$REMOTE" ]; then
    log "Changes detected ($LOCAL -> $REMOTE), pulling..."
    git log --oneline "$LOCAL".."$REMOTE" | while IFS= read -r line; do log "$line"; done
    git pull origin main --quiet
else
    log "Retrying a previous update that did not complete."
fi
touch "$PENDING_MARKER"

# Generated read-aloud audio (Piper) is written by the appuser (uid 1000) inside
# the api/worker containers to this bind-mounted dir. A fresh dir is created
# root-owned by Docker, so ensure uid 1000 can write (idempotent; mirrors the
# telegram_media/backups ownership handling).
mkdir -p "$REPO_DIR/tts_media"
if [ "$(stat -c %u "$REPO_DIR/tts_media" 2>/dev/null)" != "1000" ]; then
    sudo chown -R 1000:1000 "$REPO_DIR/tts_media" || log "WARN: could not chown tts_media" "warning"
fi

# Build before touching anything that is running. The db image is built from
# ./db (postgres + pgvector), so a build failure here has to mean "no update
# yet" rather than "no database": `up --build` would have torn the old container
# down first and left the host without one.
log "Building images..."
if ! docker compose -f "$COMPOSE_FILE" build 2>&1 | while IFS= read -r line; do [ -n "$line" ] && log "$line"; done; then
    log "Image build FAILED — running stack left untouched, will retry next tick." "error"
    exit 1
fi

log "Restarting stack..."
docker compose -f "$COMPOSE_FILE" up -d 2>&1 | while IFS= read -r line; do [ -n "$line" ] && log "$line"; done
rm -f "$PENDING_MARKER"

log "Waiting for health checks..."
docker compose -f "$COMPOSE_FILE" ps 2>&1 | while IFS= read -r line; do [ -n "$line" ] && log "$line"; done

log "Update complete."
