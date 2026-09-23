#!/usr/bin/env bash
# IntelFeed Database Restore Script
# Usage: ./scripts/ops/restore.sh <backup_file.sql.gz|backup_file.sql.gz.gpg>

set -euo pipefail

BACKUP_FILE="${1:-}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"
BACKUP_ENCRYPT_KEY="${BACKUP_ENCRYPT_KEY:-}"

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file.sql.gz|backup_file.sql.gz.gpg>"
    echo ""
    echo "Available backups:"
    ls -lt backups/intelfeed_*.sql.gz backups/intelfeed_*.sql.gz.gpg 2>/dev/null || echo "  (none found in ./backups/)"
    exit 1
fi

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Error: Backup file not found: $BACKUP_FILE"
    exit 1
fi

echo "[restore] WARNING: This will overwrite the current database."
read -rp "[restore] Continue? (y/N) " confirm
if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    echo "[restore] Aborted."
    exit 0
fi

DB_USER="${POSTGRES_USER:-intelfeed}"
DB_NAME="${POSTGRES_DB:-intelfeed}"

echo "[restore] Stopping API and worker services..."
docker compose -f "$COMPOSE_FILE" stop api celery-worker celery-beat 2>/dev/null || true

echo "[restore] Dropping and recreating database..."
docker compose -f "$COMPOSE_FILE" exec -T db psql -U "$DB_USER" -d postgres \
    -c "DROP DATABASE IF EXISTS $DB_NAME;"
docker compose -f "$COMPOSE_FILE" exec -T db psql -U "$DB_USER" -d postgres \
    -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"

echo "[restore] Restoring from $BACKUP_FILE..."

if [[ "$BACKUP_FILE" == *.gpg ]]; then
    if [ -z "$BACKUP_ENCRYPT_KEY" ]; then
        echo "Error: BACKUP_ENCRYPT_KEY required to decrypt .gpg backup"
        exit 1
    fi
    gpg --batch --yes --decrypt --passphrase "$BACKUP_ENCRYPT_KEY" "$BACKUP_FILE" \
        | gunzip | docker compose -f "$COMPOSE_FILE" exec -T db \
        psql -U "$DB_USER" "$DB_NAME" \
        --quiet --single-transaction
else
    gunzip -c "$BACKUP_FILE" | docker compose -f "$COMPOSE_FILE" exec -T db \
        psql -U "$DB_USER" "$DB_NAME" \
        --quiet --single-transaction
fi

echo "[restore] Database restored successfully."
echo "[restore] Starting services..."
docker compose -f "$COMPOSE_FILE" start api celery-worker celery-beat
