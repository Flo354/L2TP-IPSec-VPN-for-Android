#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# run.sh - build and (re)start the L2TP/IPsec lab server. Idempotent.
# ---------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lab.env"

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*"; }

# ---------------------------------------------------------------------------
say "Building image $IMAGE"
docker build -q -t "$IMAGE" "$HERE" | sed 's/^/    /'

# ---------------------------------------------------------------------------
say "Ensuring docker network $NETWORK ($SUBNET)"
if docker network inspect "$NETWORK" >/dev/null 2>&1; then
    existing=$(docker network inspect "$NETWORK" -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}')
    if [ "$existing" != "$SUBNET" ]; then
        warn "network $NETWORK exists with subnet $existing (expected $SUBNET) - recreating"
        docker network rm "$NETWORK" >/dev/null
        docker network create --driver bridge --subnet "$SUBNET" --gateway "$GATEWAY" "$NETWORK" >/dev/null
    fi
else
    docker network create --driver bridge --subnet "$SUBNET" --gateway "$GATEWAY" "$NETWORK" >/dev/null
fi

# ---------------------------------------------------------------------------
say "Removing any previous $CONTAINER"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true

say "Starting $CONTAINER at $SERVER_IP"
docker run -d \
    --name "$CONTAINER" \
    --hostname l2tp-server \
    --privileged \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_MODULE \
    --network "$NETWORK" \
    --ip "$SERVER_IP" \
    --restart=no \
    -e PPP_AUTH="${PPP_AUTH:-any}" \
    -v /lib/modules:/lib/modules:ro \
    "$IMAGE" >/dev/null

# ---------------------------------------------------------------------------
# Attach THIS container (the one running the JVM tests) to the lab network so
# it can reach $SERVER_IP directly.
# ---------------------------------------------------------------------------
SELF_ID="$(cat /etc/hostname 2>/dev/null || true)"
if [ -n "$SELF_ID" ] && docker inspect "$SELF_ID" >/dev/null 2>&1; then
    if docker inspect "$SELF_ID" -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' \
        | tr ' ' '\n' | grep -qx "$NETWORK"; then
        say "This container ($SELF_ID) is already on $NETWORK"
    else
        say "Attaching this container ($SELF_ID) to $NETWORK"
        docker network connect "$NETWORK" "$SELF_ID"
    fi
    SELF_IP="$(docker inspect "$SELF_ID" \
        -f "{{(index .NetworkSettings.Networks \"$NETWORK\").IPAddress}}" 2>/dev/null || true)"
else
    warn "Not running inside a docker container (or id not resolvable) - skipping self-attach"
    SELF_IP="(n/a)"
fi

# ---------------------------------------------------------------------------
say "Waiting for the server to become ready"
ready=0
for i in $(seq 1 60); do
    if docker exec "$CONTAINER" sh -c 'ipsec status >/dev/null 2>&1 && ss -lun | grep -q ":1701"'; then
        ready=1; break
    fi
    sleep 1
done
if [ "$ready" != 1 ]; then
    warn "Server did not report ready in 60s - last 60 log lines:"
    docker logs --tail 60 "$CONTAINER" || true
    exit 1
fi

cat <<EOF

  ------------------------------------------------------------------
   L2TP/IPsec lab server is UP
  ------------------------------------------------------------------
   container        : $CONTAINER
   network          : $NETWORK  ($SUBNET)
   SERVER IP        : $SERVER_IP        <- point the client here
   this container   : ${SELF_IP:-unknown}

   PSK              : $PSK
   username         : $VPN_USER
   password         : $VPN_PASS

   IKEv1 phase 1    : AES-256-CBC / HMAC-SHA-256 / PRF-HMAC-SHA-256 / MODP-2048
                      main mode, PSK auth
   IPsec phase 2    : ESP AES-256-CBC / HMAC-SHA-256-128, TRANSPORT mode, no PFS
   NAT traversal    : forced (forceencaps=yes) - ESP always in UDP/4500
   L2TP             : UDP/1701 (RFC 2661), length bit on
   PPP              : local 10.10.10.1, pool 10.10.10.100-10.10.10.199
                      DNS 10.10.10.1 + 8.8.8.8, MTU/MRU 1400
                      PAP + CHAP-MD5 + MS-CHAPv2 (EAP refused)

   logs             : docker logs -f $CONTAINER
   verify           : $HERE/verify.sh
   stop             : $HERE/stop.sh
  ------------------------------------------------------------------

EOF
