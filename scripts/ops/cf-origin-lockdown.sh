#!/usr/bin/env bash
# Restrict inbound 80/443 on the prod host to Cloudflare edge ranges only.
#
# Closes the origin-bypass hole: the site is proxied by Cloudflare, but the
# origin IP accepts 80/443 from anywhere, so anyone who learns it can skip the
# WAF, bot rules, and rate limiting by sending a Host header directly.
#
# Both rule families are narrowed:
#   ufw allow ...        -> INPUT  (host-bound, docker-proxy listener)
#   ufw route allow ...  -> FORWARD (container-bound, docker DNAT path)
# Narrowing only one leaves the other wide open.
#
# Idempotent: re-run any time to refresh the ranges. Port 22 is never touched,
# so this cannot lock you out of SSH.
#
# Usage: sudo ./scripts/ops/cf-origin-lockdown.sh [--dry-run]
set -euo pipefail

TAG="cloudflare-edge"
V4_URL="https://www.cloudflare.com/ips-v4"
V6_URL="https://www.cloudflare.com/ips-v6"
DRY_RUN=false
[ "${1:-}" = "--dry-run" ] && DRY_RUN=true

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run with sudo" >&2; exit 1; }
command -v ufw >/dev/null || { echo "ERROR: ufw not found" >&2; exit 1; }

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

echo "[cf] fetching Cloudflare ranges..."
curl -fsS --max-time 20 "$V4_URL" -o "$tmp/v4"
curl -fsS --max-time 20 "$V6_URL" -o "$tmp/v6"
grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'  "$tmp/v4" > "$tmp/v4.ok" || true
grep -E '^[0-9a-fA-F:]+/[0-9]+$'                    "$tmp/v6" > "$tmp/v6.ok" || true
n4=$(wc -l < "$tmp/v4.ok"); n6=$(wc -l < "$tmp/v6.ok")

# Sanity gate: a captive portal or CF error page must never wipe the allow rules.
if [ "$n4" -lt 10 ] || [ "$n6" -lt 5 ]; then
    echo "ERROR: implausible range counts (v4=$n4 v6=$n6) — refusing to touch ufw" >&2
    exit 1
fi
echo "[cf] got $n4 IPv4 + $n6 IPv6 ranges"

if [ "$DRY_RUN" = true ]; then
    echo "[cf] --dry-run: would delete the Anywhere 80/443 rules, then add:"
    while read -r cidr; do
        echo "  ufw allow       proto tcp from $cidr to any port 80,443 comment '$TAG'"
        echo "  ufw route allow proto tcp from $cidr to any port 80,443 comment '$TAG'"
    done < <(cat "$tmp/v4.ok" "$tmp/v6.ok")
    exit 0
fi

# Purge previously-added rules (highest number first so lower numbers stay valid).
echo "[cf] purging existing '$TAG' rules..."
while :; do
    # pipefail: grep exits 1 when no tagged rules remain, so absorb it here.
    num=$(ufw status numbered | grep "# $TAG" | tail -1 | sed -E 's/^\[[[:space:]]*([0-9]+)\].*/\1/') || true
    [ -n "$num" ] || break
    ufw --force delete "$num" >/dev/null
done

# Drop the Anywhere rules. IPv6 counterparts go with them (IPV6=yes pairs them).
echo "[cf] removing Anywhere 80/443 rules..."
for spec in "allow 80/tcp" "allow 443/tcp"; do
    ufw --force delete $spec        >/dev/null 2>&1 || true
    ufw --force route delete $spec  >/dev/null 2>&1 || true
done

echo "[cf] adding $((n4 + n6)) Cloudflare ranges (x2 for IN + FWD)..."
while read -r cidr; do
    ufw allow       proto tcp from "$cidr" to any port 80,443 comment "$TAG" >/dev/null
    ufw route allow proto tcp from "$cidr" to any port 80,443 comment "$TAG" >/dev/null
done < <(cat "$tmp/v4.ok" "$tmp/v6.ok")

echo "[cf] done. Current rules:"
ufw status verbose
