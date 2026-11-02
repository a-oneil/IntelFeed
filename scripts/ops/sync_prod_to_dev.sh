#!/usr/bin/env bash
# Pull a fresh dump of the production database and restore it into the local
# dev stack (docker-compose.dev.yml). The dev database is dropped and
# recreated; migrations re-run automatically when the api container restarts.
#
# Usage: ./scripts/ops/sync_prod_to_dev.sh [--yes] [--skip-reindex] [existing_dump.sql.gz]
#   --yes                 Skip the overwrite confirmation prompt
#   --skip-reindex        Leave Meilisearch alone (search will be broken, see below)
#   existing_dump.sql.gz  Restore this dump instead of pulling a fresh one
#
# Required: INTELFEED_PROD_HOST — SSH target for the prod host, e.g. user@prod.example.com
# Optional: INTELFEED_PROD_DIR  — checkout path on that host (default: intelfeed)

set -euo pipefail

PROD_HOST="${INTELFEED_PROD_HOST:-}"
PROD_DIR="${INTELFEED_PROD_DIR:-intelfeed}"
if [ -z "$PROD_HOST" ]; then
    echo "ERROR: set INTELFEED_PROD_HOST to your production SSH target, e.g." >&2
    echo "  export INTELFEED_PROD_HOST=user@prod.example.com" >&2
    echo "(INTELFEED_PROD_DIR overrides the checkout path on that host; default 'intelfeed'.)" >&2
    exit 1
fi
DEV_COMPOSE="docker-compose.dev.yml"
BACKUP_DIR="./backups"
KEEP_SYNC_DUMPS=3
# Dev services that hold DB connections — stopped during restore
DB_SERVICES=(api celery-worker celery-worker-ai celery-worker-enrichment celery-beat telegram-listener)

ASSUME_YES=false
SKIP_REINDEX=false
DUMP_FILE=""
for arg in "$@"; do
    case "$arg" in
        --yes) ASSUME_YES=true ;;
        --skip-reindex) SKIP_REINDEX=true ;;
        *) DUMP_FILE="$arg" ;;
    esac
done

cd "$(cd "$(dirname "$0")/../.." && pwd)"

if [ "$ASSUME_YES" = "false" ]; then
    echo "[sync] WARNING: this will DROP and overwrite your local dev database."
    read -rp "[sync] Continue? (y/N) " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "[sync] Aborted."
        exit 0
    fi
fi

# --- 1. Get a prod dump -----------------------------------------------------
if [ -n "$DUMP_FILE" ]; then
    if [ ! -f "$DUMP_FILE" ]; then
        echo "[sync] ERROR: dump file not found: $DUMP_FILE" >&2
        exit 1
    fi
    echo "[sync] Using existing dump: $DUMP_FILE"
else
    mkdir -p "$BACKUP_DIR"
    DUMP_FILE="$BACKUP_DIR/prod_sync_$(date +%Y%m%d_%H%M%S).sql.gz"
    echo "[sync] Dumping prod database from $PROD_HOST (streamed, gzipped)..."
    # pg_dump runs inside the prod db container where POSTGRES_USER/DB are set;
    # gzip runs on the prod host so the transfer is compressed.
    ssh "$PROD_HOST" "cd $PROD_DIR && docker compose -f docker-compose.prod.yml exec -T db sh -c 'pg_dump -U \"\$POSTGRES_USER\" \"\$POSTGRES_DB\" --clean --if-exists --no-owner' | gzip" > "$DUMP_FILE"
    echo "[sync] Pulled $(du -h "$DUMP_FILE" | cut -f1) -> $DUMP_FILE"

    # Keep only the most recent sync dumps
    ls -t "$BACKUP_DIR"/prod_sync_*.sql.gz 2>/dev/null | tail -n +"$((KEEP_SYNC_DUMPS + 1))" | while IFS= read -r old; do
        echo "[sync] Pruning old dump: $old"
        rm -f "$old"
    done
fi

# --- 2. Restore into dev ----------------------------------------------------
echo "[sync] Ensuring dev db container is up..."
docker compose -f "$DEV_COMPOSE" up -d db
until docker compose -f "$DEV_COMPOSE" exec -T db sh -c 'pg_isready -U "$POSTGRES_USER"' >/dev/null 2>&1; do
    sleep 1
done

echo "[sync] Stopping dev services that hold DB connections..."
docker compose -f "$DEV_COMPOSE" stop "${DB_SERVICES[@]}" 2>/dev/null || true

echo "[sync] Dropping and recreating dev database..."
docker compose -f "$DEV_COMPOSE" exec -T db sh -c \
    'psql -U "$POSTGRES_USER" -d postgres -c "DROP DATABASE IF EXISTS $POSTGRES_DB WITH (FORCE);" -c "CREATE DATABASE $POSTGRES_DB OWNER $POSTGRES_USER;"'

echo "[sync] Restoring dump (this can take a while)..."
# ON_ERROR_STOP matters: without it psql exits 0 even though --single-transaction
# rolled the whole restore back, so the script would report success over an
# empty database.
gunzip -c "$DUMP_FILE" | docker compose -f "$DEV_COMPOSE" exec -T db sh -c \
    'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" --quiet --single-transaction -v ON_ERROR_STOP=1'

echo "[sync] Restarting dev services (api will re-run migrations on startup)..."
docker compose -f "$DEV_COMPOSE" start "${DB_SERVICES[@]}"

# --- 3. Rebuild the search indexes ------------------------------------------
# Not optional housekeeping: Meilisearch document ids come from whichever
# database wrote them, so after a restore the index points at rows that no
# longer exist and search returns wrong and missing hits. Run inline (not via
# the Celery task) so a failure here fails the sync instead of surfacing later
# as "search is broken".
if [ "$SKIP_REINDEX" = "true" ]; then
    echo "[sync] Skipping reindex (--skip-reindex). Local search will be wrong until you run:"
    echo "[sync]   docker compose -f $DEV_COMPOSE exec api python scripts/maintenance/rebuild_search_indexes.py"
else
    echo "[sync] Waiting for api and meilisearch to come up..."
    for _ in $(seq 1 60); do
        if docker compose -f "$DEV_COMPOSE" exec -T api python -c 'pass' >/dev/null 2>&1; then
            break
        fi
        sleep 2
    done
    docker compose -f "$DEV_COMPOSE" up -d meilisearch
    echo "[sync] Rebuilding Meilisearch indexes from the restored database..."
    docker compose -f "$DEV_COMPOSE" exec -T api python scripts/maintenance/rebuild_search_indexes.py
fi

echo "[sync] Done. Dev database now mirrors prod (as of this dump)."
