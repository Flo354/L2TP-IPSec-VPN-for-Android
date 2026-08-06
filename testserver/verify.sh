#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# verify.sh - prove that the lab server is really live AND that the full
#             IPsec -> L2TP -> PPP data path works.
#
#   1  container is running on the expected IP
#   2  charon is alive and has loaded conn L2TP-PSK with the expected algos
#   3  UDP/500, UDP/4500 and UDP/1701 are bound inside the container
#   4  the server is reachable from THIS container and answers a real
#      RFC 2661 SCCRQ with an SCCRP
#   5  a real strongSwan + xl2tpd + pppd client in a sibling container brings
#      up ppp0 with an address from the pool and pings 10.10.10.1 - once for
#      MS-CHAPv2, once for CHAP-MD5, once for PAP (each run asserts which
#      auth protocol was actually negotiated)
#   6  server-side evidence: IKE_SA + CHILD_SA established, transport mode,
#      ESP-in-UDP, and pppd brought up an interface
#
# Exits non-zero if anything fails.
#
#   VERIFY_QUICK=1  -> step 5 only runs MS-CHAPv2 (faster smoke test)
# ---------------------------------------------------------------------------
# NOTE: 'pipefail' is deliberately NOT set. `printf '%s' "$BIG" | grep -q`
# makes the writer die of SIGPIPE as soon as grep exits on its first match,
# which pipefail would misreport as a failure.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lab.env"
CAPDIR="$HERE/captures"
QUICK="${VERIFY_QUICK:-0}"

RC=0; PASS=0; FAILED=0

ok()   { printf '\033[1;32m  PASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '\033[1;31m  FAIL\033[0m %s\n' "$*"; FAILED=$((FAILED+1)); RC=1; }
info() { printf '       %s\n' "$*"; }
step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
indent() { sed 's/^/       /' <<< "$1"; }
# has <text> <ERE> - true if the text matches
has()  { grep -qE -- "$2" <<< "$1"; }
show() { grep -E -- "$2" <<< "$1" | head -"${3:-3}" | sed 's/^/       /'; }

# ---------------------------------------------------------------------------
step "1. container $CONTAINER is running"
if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" = "true" ]; then
    ok "container up since $(docker inspect -f '{{.State.StartedAt}}' "$CONTAINER")"
else
    bad "container $CONTAINER is not running - run $HERE/run.sh first"
    exit 1
fi

CIP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NETWORK\").IPAddress}}" "$CONTAINER" 2>/dev/null)
if [ "$CIP" = "$SERVER_IP" ]; then ok "server IP is $CIP"
else bad "server IP is '$CIP', expected $SERVER_IP"; fi

# ---------------------------------------------------------------------------
step "2. charon is alive and conn L2TP-PSK is loaded"
STATUS=$(docker exec "$CONTAINER" ipsec statusall 2>&1)

if has "$STATUS" 'Status of IKE charon daemon'; then
    ok "charon answers on the stroke socket"
    show "$STATUS" 'uptime' 1
else
    bad "charon is not answering (ipsec statusall)"; indent "$STATUS"
fi

if has "$STATUS" '^[[:space:]]*L2TP-PSK:'; then
    ok "conn L2TP-PSK is loaded"
    show "$STATUS" '^[[:space:]]*L2TP-PSK' 6
else
    bad "conn L2TP-PSK is NOT loaded"
fi

# 'l2f' is how strongSwan prints UDP port 1701 (/etc/services name)
if has "$STATUS" 'child:.*\[udp/l2f\].*===.*\[udp\].*TRANSPORT'; then
    ok "child SA policy is udp/1701 === udp/any in TRANSPORT mode"
else
    bad "child SA policy is not the expected transport-mode udp/1701 selector"
fi

CFGOK=1
for want in 'ike=aes256-sha256-modp2048!' 'esp=aes256-sha256!' 'type=transport' \
            'forceencaps=yes' 'keyexchange=ikev1' 'authby=secret'; do
    docker exec "$CONTAINER" grep -qF -- "$want" /etc/ipsec.conf || { CFGOK=0; bad "ipsec.conf is missing '$want'"; }
done
[ "$CFGOK" = 1 ] && ok "ipsec.conf: IKEv1/PSK, aes256-sha256-modp2048!, esp aes256-sha256!, transport, forceencaps"

if docker exec "$CONTAINER" grep -qF 'TestPreSharedKey2024!' /etc/ipsec.secrets; then
    ok "PSK matches the value the tests hard-code"
else
    bad "PSK in /etc/ipsec.secrets is not 'TestPreSharedKey2024!'"
fi

# ---------------------------------------------------------------------------
step "3. UDP/500, UDP/4500 and UDP/1701 are bound"
LISTEN=$(docker exec "$CONTAINER" ss -lunp 2>/dev/null)
[ -z "$LISTEN" ] && LISTEN=$(docker exec "$CONTAINER" netstat -lunp 2>/dev/null)
for p in 500 4500 1701; do
    if has "$LISTEN" "[:.]$p[[:space:]]"; then
        who=$(grep -E "[:.]$p[[:space:]]" <<< "$LISTEN" | head -1 | sed 's/.*users:(("\([^"]*\)".*/\1/')
        ok "UDP/$p is bound (${who:-?})"
    else
        bad "UDP/$p is NOT bound"
    fi
done
indent "$LISTEN"

# ---------------------------------------------------------------------------
step "4. reachable from this container, and xl2tpd speaks RFC 2661"
if command -v python3 >/dev/null 2>&1; then
    if PROBE=$(python3 "$HERE/l2tp_probe.py" "$SERVER_IP" 1701 6 2>&1); then
        ok "plaintext SCCRQ -> SCCRP round trip from this container to $SERVER_IP:1701"
        indent "$PROBE"
    else
        bad "no SCCRP from $SERVER_IP:1701 (unreachable, or xl2tpd is dead)"
        indent "$PROBE"
    fi
else
    if docker run --rm --network "$NETWORK" --entrypoint ping "$IMAGE" \
            -c2 -W2 "$SERVER_IP" >/dev/null 2>&1; then
        ok "server answers ICMP on the lab network"
    else
        bad "server does not answer on the lab network"
    fi
fi

# ---------------------------------------------------------------------------
step "4b. the IKEv1 phase-1 proposal is exactly aes256-sha256-modp2048"
if command -v python3 >/dev/null 2>&1; then
    if IKEP=$(python3 "$HERE/ike_probe.py" "$SERVER_IP" 500 2>&1); then
        ok "all 9 main-mode SA probes behaved as expected (4 accepted, 4 rejected, 1 multi-transform)"
        indent "$IKEP"
    else
        bad "ike_probe.py found unexpected proposal-matching behaviour"
        indent "$IKEP"
    fi
    if L2P=$(python3 "$HERE/l2tp_probe.py" "$SERVER_IP" 1701 4 --variants 2>&1); then
        info "xl2tpd SCCRQ AVP requirements:"
        indent "$L2P"
    fi
fi

# ---------------------------------------------------------------------------
step "5. full data path: real strongSwan + xl2tpd + pppd client"
mkdir -p "$CAPDIR"
# The client container is a SIBLING of this one, so the -v source must be a
# path that exists on the docker HOST. The project tree is bind-mounted at
# the same path on the host, so $CAPDIR works verbatim.
# "auth:clientForceencaps" pairs
RUNS=(mschapv2:yes chap:yes pap:yes mschapv2:no)
[ "$QUICK" = "1" ] && RUNS=(mschapv2:yes)

for run in "${RUNS[@]}"; do
    auth="${run%%:*}"; fenc="${run##*:}"
    label="$auth"
    [ "$fenc" = "no" ] && label="$auth (client forceencaps=no -> server must force ESP-in-UDP)"
    printf '\n\033[1;35m   --- client run: %s ---\033[0m\n' "$label"
    docker rm -f "$CLIENT_CONTAINER" >/dev/null 2>&1 || true
    OUT=$(docker run --rm \
            --name "$CLIENT_CONTAINER" \
            --privileged --cap-add=NET_ADMIN \
            --network "$NETWORK" \
            -v /lib/modules:/lib/modules:ro \
            -v "$CAPDIR:/out" \
            -e SERVER="$SERVER_IP" -e AUTH="$auth" -e CAPTURE=1 \
            -e FORCEENCAPS="$fenc" \
            --entrypoint /opt/l2tp-client/run-client.sh \
            "$IMAGE" 2>&1)
    CRC=$?
    # keep the noise down: show the interesting lines, full output on failure
    if [ $CRC -eq 0 ] && has "$OUT" 'RESULT: SUCCESS'; then
        show "$OUT" 'IKE_SA .* established|CHILD_SA .* established|ESP-in-UDP|SERVER.s forceencaps|ppp0 is up|bytes from 10\.10\.10\.1|AUTH CONFIRMED' 40
        PPPIP=$(sed -n 's/.*ppp0 is up with address \([0-9.]*\).*/\1/p' <<< "$OUT" | head -1)
        ok "$label: IKE_SA + CHILD_SA + L2TP + PPP up, ppp0=$PPPIP, ping 10.10.10.1 OK"
        if [ "$fenc" = "no" ] && has "$OUT" "SERVER's forceencaps=yes is doing the work"; then
            ok "server-side forceencaps=yes proven: ESP-in-UDP without the client asking"
        elif [ "$fenc" = "no" ]; then
            bad "client forceencaps=no did NOT result in server-forced ESP-in-UDP"
        fi
    else
        indent "$OUT"
        bad "$label: full data path did NOT come up (exit $CRC)"
    fi
done

# ---------------------------------------------------------------------------
step "6. server-side evidence"
SRVLOG=$(docker logs --tail 20000 "$CONTAINER" 2>&1)

if has "$SRVLOG" 'IKE_SA L2TP-PSK\[[0-9]+\] established'; then
    ok "IKE_SA established (server log)"
    show "$SRVLOG" 'IKE_SA L2TP-PSK\[[0-9]+\] established' 2
else
    bad "no 'IKE_SA ... established' in the server log"
fi

if has "$SRVLOG" 'CHILD_SA L2TP-PSK\{[0-9]+\} established'; then
    ok "CHILD_SA (ESP) established with udp/l2f traffic selectors"
    show "$SRVLOG" 'CHILD_SA L2TP-PSK\{[0-9]+\} established' 2
else
    bad "no 'CHILD_SA ... established' in the server log"
fi

# strongSwan only *logs* "faking NAT situation" when the peer did NOT already
# claim a NAT; when the peer forces encapsulation too, the server simply logs
# "remote host is behind NAT". Either is proof that we ended up on UDP/4500.
if has "$SRVLOG" 'faking NAT situation to enforce UDP encapsulation'; then
    ok "forceencaps active: charon faked the NAT situation to force UDP/4500"
    show "$SRVLOG" 'faking NAT situation' 1
elif has "$SRVLOG" 'remote host is behind NAT'; then
    ok "NAT-T engaged (peer claimed NAT; server switched to UDP/4500)"
    show "$SRVLOG" 'remote host is behind NAT' 1
else
    bad "no NAT-T evidence in the server log"
fi

if has "$SRVLOG" 'local endpoint changed from .*\[500\] to .*\[4500\]'; then
    ok "IKE moved from UDP/500 to UDP/4500 (NAT-T float)"
    show "$SRVLOG" 'endpoint changed from' 2
else
    bad "IKE never floated to UDP/4500"
fi

if has "$SRVLOG" 'selected proposal: ESP:AES_CBC_256/HMAC_SHA2_256_128'; then
    ok "ESP proposal selected: AES_CBC_256/HMAC_SHA2_256_128 (no PFS)"
else
    bad "the expected ESP proposal was never selected"
fi

if has "$SRVLOG" 'Using interface ppp[0-9]'; then
    ok "server pppd brought up a ppp interface"
    show "$SRVLOG" 'Using interface ppp[0-9]|local  IP address|remote IP address' 6
else
    bad "server pppd never reported a ppp interface"
fi

if has "$SRVLOG" 'Connection established to .*LNS session'; then
    ok "xl2tpd established the L2TP tunnel + session"
    show "$SRVLOG" 'Connection established to |Call established with ' 2
else
    bad "xl2tpd never established an L2TP tunnel"
fi

# ---------------------------------------------------------------------------
printf '\n\033[1m======================================================\033[0m\n'
if [ $RC -eq 0 ]; then
    printf '\033[1;32m  VERIFY OK  - %d checks passed\033[0m\n' "$PASS"
    printf '  server : %s\n  psk    : %s\n  user   : %s / %s\n' \
        "$SERVER_IP" "$PSK" "$VPN_USER" "$VPN_PASS"
    [ -d "$CAPDIR" ] && printf '  pcaps  : %s\n' "$CAPDIR"
else
    printf '\033[1;31m  VERIFY FAILED - %d failed, %d passed\033[0m\n' "$FAILED" "$PASS"
fi
printf '\033[1m======================================================\033[0m\n'
exit $RC
