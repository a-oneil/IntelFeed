#!/usr/bin/env bash
# Auto-update IntelFeed from main branch.
# Example cron (check every 2 minutes):
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

# The commit the running containers were last deployed from. This, not
# LOCAL..REMOTE, is what the rebuild decision diffs against: a tick that pulls
# but then fails has already moved HEAD, and a tick that correctly skipped the
# build must not let the next tick forget those files ever landed.
DEPLOYED_MARKER="$REPO_DIR/.update-deployed"

was_pending=false
[ -f "$PENDING_MARKER" ] && was_pending=true

if [ "$LOCAL" = "$REMOTE" ] && [ "$was_pending" = false ]; then
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

HEAD_SHA=$(git rev-parse HEAD)

# --- What moved? -------------------------------------------------------------
#
# Most commits on this repo touch docs/, scripts/, the Android client
# or CI — none of which are baked into an image. ./docs, ./scripts and
# ./intelfeed-skill are bind-mounted read-only into the containers, so new
# content there is live the moment the pull lands. Rebuilding and recreating the
# stack for those is pure downtime: a cold `docker compose build` on the prod box
# is minutes of CPU, and `up -d` drops every connection in flight.
#
# So classify instead, and act on the narrowest thing that works:
#
#   rebuild   backend/, frontend/, db/, piper/, compose  -> build + up -d
#   reload    Caddyfile                                  -> reload caddy in place
#   none      everything else                            -> pull only
#
# backend/** and frontend/** are rebuild triggers in full, unlike the `images`
# filter in CI: prod has no source volume mounts, so the api, worker and SPA
# images COPY the code at build time and a Python or TSX edit only reaches the
# running stack through a build.

base=""
if [ -f "$DEPLOYED_MARKER" ]; then
    candidate=$(tr -d '[:space:]' < "$DEPLOYED_MARKER" 2>/dev/null || true)
    if [ -n "$candidate" ] && git cat-file -e "${candidate}^{commit}" 2>/dev/null; then
        base="$candidate"
    fi
fi
if [ -z "$base" ] && [ "$was_pending" = false ]; then
    # First tick after this script grew a marker, or the recorded commit was
    # rewritten away. A clean (non-pending) tick means the containers match the
    # pre-pull HEAD, so that is a sound base.
    base="$LOCAL"
fi

needs_build=false
needs_reload=false

if [ -z "$base" ]; then
    # Mid-retry with no recorded deployment: we cannot know what the running
    # containers contain, so assume the worst and build.
    needs_build=true
    log "No recorded deployment to compare against — rebuilding."
else
    changed=$(git diff --name-only "$base" "$HEAD_SHA")
    match() { printf '%s\n' "$changed" | grep -qE "$1"; }

    if match '^(backend/|frontend/|db/|piper/|docker-compose.*\.yml$)'; then
        needs_build=true
    fi
    if match '^Caddyfile$'; then
        needs_reload=true
    fi

    if [ "$needs_build" = false ] && [ "$needs_reload" = false ]; then
        log "No image, compose or proxy changes since ${base:0:8} — skipping rebuild."
        printf '%s' "$HEAD_SHA" > "$DEPLOYED_MARKER"
        rm -f "$PENDING_MARKER"
        log "Update complete."
        exit 0
    fi
fi

if [ "$needs_build" = true ]; then
    # Generated read-aloud audio (Piper) is written by the appuser (uid 1000)
    # inside the api/worker containers to this bind-mounted dir. A fresh dir is
    # created root-owned by Docker, so ensure uid 1000 can write (idempotent;
    # mirrors the telegram_media/backups ownership handling).
    mkdir -p "$REPO_DIR/tts_media"
    if [ "$(stat -c %u "$REPO_DIR/tts_media" 2>/dev/null)" != "1000" ]; then
        sudo chown -R 1000:1000 "$REPO_DIR/tts_media" || log "WARN: could not chown tts_media" "warning"
    fi
    # Same for the originals behind manual uploads (api writes, celery-worker reads).
    mkdir -p "$REPO_DIR/ingest_files"
    if [ "$(stat -c %u "$REPO_DIR/ingest_files" 2>/dev/null)" != "1000" ]; then
        sudo chown -R 1000:1000 "$REPO_DIR/ingest_files" || log "WARN: could not chown ingest_files" "warning"
    fi

    # Build before touching anything that is running. The db image is built from
    # ./db (postgres + pgvector), so a build failure here has to mean "no update
    # yet" rather than "no database": `up --build` would have torn the old
    # container down first and left the host without one.
    # Stamp the build with the commit it came from. Must run after the pull and
    # before the build: compose reads these from the environment to fill the api
    # and frontend build args, and nothing inside a build context can see .git.
    # shellcheck source=scripts/ops/version.sh
    . "$REPO_DIR/scripts/ops/version.sh"
    log "Building images (version $APP_VERSION, sha $GIT_SHA)..."
    if ! docker compose -f "$COMPOSE_FILE" build 2>&1 | while IFS= read -r line; do [ -n "$line" ] && log "$line"; done; then
        log "Image build FAILED — running stack left untouched, will retry next tick." "error"
        exit 1
    fi

    log "Restarting stack..."
    docker compose -f "$COMPOSE_FILE" up -d 2>&1 | while IFS= read -r line; do [ -n "$line" ] && log "$line"; done
fi

if [ "$needs_reload" = true ]; then
    # The Caddyfile is bind-mounted, so `up -d` sees an unchanged caddy service
    # and leaves it alone — the new config would sit on disk unread. Reload it
    # in place instead, which keeps TLS and in-flight requests up.
    log "Caddyfile changed — reloading caddy..."
    # -T: cron has no TTY, and `exec` allocates one by default.
    if ! docker compose -f "$COMPOSE_FILE" exec -T caddy \
        caddy reload --config /etc/caddy/Caddyfile 2>&1 |
        while IFS= read -r line; do [ -n "$line" ] && log "$line"; done; then
        log "Caddy reload FAILED — the old config is still serving." "error"
    fi
fi

printf '%s' "$HEAD_SHA" > "$DEPLOYED_MARKER"
rm -f "$PENDING_MARKER"

log "Waiting for health checks..."
docker compose -f "$COMPOSE_FILE" ps 2>&1 | while IFS= read -r line; do [ -n "$line" ] && log "$line"; done

log "Update complete."
