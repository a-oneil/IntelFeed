#!/bin/bash
set -e

# Only run migrations from the API container
if [ "${RUN_MIGRATIONS:-false}" = "true" ]; then
    echo "Running database migrations..."
    if ! alembic upgrade head; then
        echo "ERROR: Database migration failed!" >&2
        exit 1
    fi
    echo "Migrations completed successfully."
fi

# Restore Claude CLI config from the most recent backup if the live file is
# missing. ~/.claude/ is a persistent named volume (so backups survive), but
# ~/.claude.json sits one level up outside the mount and gets wiped on every
# image rebuild. Without it, the CLI errors out on first invocation even
# though credentials are intact. No-op on containers without backups.
CLAUDE_CONFIG="${HOME:-/home/appuser}/.claude.json"
CLAUDE_BACKUPS="${HOME:-/home/appuser}/.claude/backups"
if [ ! -f "$CLAUDE_CONFIG" ] && [ -d "$CLAUDE_BACKUPS" ]; then
    latest_backup=$(ls -1t "$CLAUDE_BACKUPS"/.claude.json.backup.* 2>/dev/null | head -n 1)
    if [ -n "$latest_backup" ]; then
        cp "$latest_backup" "$CLAUDE_CONFIG"
        echo "Restored Claude CLI config from $latest_backup"
    fi
fi

echo "Starting application..."
exec "$@"
