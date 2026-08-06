#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# stop.sh - remove the lab server container. The docker network is left in
# place (this container stays attached to it).
# ---------------------------------------------------------------------------
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lab.env"

docker rm -f "$CLIENT_CONTAINER" >/dev/null 2>&1 || true
if docker rm -f "$CONTAINER" >/dev/null 2>&1; then
    echo "==> removed container $CONTAINER (network $NETWORK left in place)"
else
    echo "==> container $CONTAINER was not running"
fi
