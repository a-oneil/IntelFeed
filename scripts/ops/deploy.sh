#!/usr/bin/env bash
# IntelFeed deploy: push main to origin, then run update.sh on the prod host
# and verify it finished with "Update complete." and healthy containers.
#
# Usage: ./scripts/ops/deploy.sh [--skip-push]
#   --skip-push   Deploy whatever is already on origin/main without pushing
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
SKIP_PUSH=false
[ "${1:-}" = "--skip-push" ] && SKIP_PUSH=true

cd "$(cd "$(dirname "$0")/.." && pwd)"

BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$BRANCH" != "main" ]; then
    echo "[deploy] ERROR: on branch '$BRANCH', not main. Deploys ship main only." >&2
    exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
    echo "[deploy] WARNING: working tree has uncommitted changes — they will NOT ship:"
    git status --short
    read -rp "[deploy] Continue and deploy the last commit anyway? (y/N) " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "[deploy] Aborted. Commit your changes first."
        exit 0
    fi
fi

if [ "$SKIP_PUSH" = "false" ]; then
    echo "[deploy] Pushing main to origin..."
    git push origin main
else
    echo "[deploy] Skipping push (deploying current origin/main)."
fi

echo "[deploy] Shipping $(git log --oneline -1) to $PROD_HOST..."
echo "[deploy] Running remote update (Docker rebuild — this takes a few minutes)..."

LOG_FILE=$(mktemp -t intelfeed-deploy)
DEPLOY_OK=true
ssh "$PROD_HOST" "cd $PROD_DIR && ./update.sh" 2>&1 | tee "$LOG_FILE" || DEPLOY_OK=false

if [ "$DEPLOY_OK" = "false" ] || ! grep -q "Update complete." "$LOG_FILE"; then
    echo "" >&2
    echo "[deploy] FAILED: 'Update complete.' never appeared. Full log: $LOG_FILE" >&2
    exit 1
fi

echo "[deploy] Update complete. Checking container health..."
PS_OUTPUT=$(ssh "$PROD_HOST" "cd $PROD_DIR && docker compose -f docker-compose.prod.yml ps")
echo "$PS_OUTPUT"

if echo "$PS_OUTPUT" | grep -qE "unhealthy|Restarting|Exited"; then
    echo "" >&2
    echo "[deploy] WARNING: deploy finished but some containers are not healthy (see above)." >&2
    exit 1
fi

echo "[deploy] Done — $(git log --oneline -1) is live and all containers are healthy."
