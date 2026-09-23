#!/usr/bin/env bash
# IntelFeed Database Backup Script
# Usage: ./scripts/ops/backup.sh [backup_dir]
# Runs pg_dump against the Docker Compose PostgreSQL container.
# Keeps the last 7 daily backups by default.

set -euo pipefail

BACKUP_DIR="${1:-./backups}"
RETENTION_DAYS="${RETENTION_DAYS:-7}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"
BACKUP_ENCRYPT_KEY="${BACKUP_ENCRYPT_KEY:-}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
if [ -n "$BACKUP_ENCRYPT_KEY" ]; then
    BACKUP_FILE="${BACKUP_DIR}/intelfeed_${TIMESTAMP}.sql.gz.gpg"
else
    BACKUP_FILE="${BACKUP_DIR}/intelfeed_${TIMESTAMP}.sql.gz"
fi

mkdir -p "$BACKUP_DIR"

echo "[backup] Starting database backup..."

# Dump database from the running postgres container
if [ -n "$BACKUP_ENCRYPT_KEY" ]; then
    docker compose -f "$COMPOSE_FILE" exec -T db \
        pg_dump -U "${POSTGRES_USER:-intelfeed}" "${POSTGRES_DB:-intelfeed}" \
        --clean --if-exists --no-owner \
        | gzip | gpg --batch --yes --symmetric --cipher-algo AES256 \
            --passphrase "$BACKUP_ENCRYPT_KEY" -o "$BACKUP_FILE"
else
    docker compose -f "$COMPOSE_FILE" exec -T db \
        pg_dump -U "${POSTGRES_USER:-intelfeed}" "${POSTGRES_DB:-intelfeed}" \
        --clean --if-exists --no-owner \
        | gzip > "$BACKUP_FILE"
fi

SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
echo "[backup] Created $BACKUP_FILE ($SIZE)"

# Create Meilisearch snapshot.
# Runs curl *inside* the meilisearch container: in prod the service is
# internal-only (no host port mapping), and the container already ships curl
# (used by its healthcheck) and has MEILI_MASTER_KEY in its environment, so
# this needs no host-side env. Snapshots are written to /meili_data/snapshots
# inside the meilidata volume.
echo "[backup] Creating Meilisearch snapshot..."
MEILI_SNAPSHOT_OK=false
HTTP_CODE=$(docker compose -f "$COMPOSE_FILE" exec -T meilisearch sh -c \
    'curl -s -o /dev/null -w "%{http_code}" -X POST -H "Authorization: Bearer $MEILI_MASTER_KEY" http://localhost:7700/snapshots') \
    || HTTP_CODE="unreachable"
if [ "$HTTP_CODE" = "202" ]; then
    echo "[backup] Meilisearch snapshot requested (written asynchronously to meilidata volume: /meili_data/snapshots)"
    MEILI_SNAPSHOT_OK=true
else
    echo "[backup] ERROR: Meilisearch snapshot request failed (HTTP $HTTP_CODE)" >&2
fi

# Prune old backups
if [ "$RETENTION_DAYS" -gt 0 ]; then
    DELETED=$(find "$BACKUP_DIR" \( -name "intelfeed_*.sql.gz" -o -name "intelfeed_*.sql.gz.gpg" \) -mtime +"$RETENTION_DAYS" -delete -print | wc -l | tr -d ' ')
    if [ "$DELETED" -gt 0 ]; then
        echo "[backup] Pruned $DELETED backup(s) older than $RETENTION_DAYS days"
    fi
fi

if [ "$MEILI_SNAPSHOT_OK" != "true" ]; then
    echo "[backup] Done WITH ERRORS: database backup succeeded, but the Meilisearch snapshot FAILED (see above)." >&2
    exit 1
fi

echo "[backup] Done."
