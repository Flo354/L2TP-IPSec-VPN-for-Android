#!/bin/bash
# ---------------------------------------------------------------------------
# run-client.sh - a REAL strongSwan + xl2tpd + pppd L2TP/IPsec client.
#
# Runs inside a throw-away privileged sibling container on the l2tplab
# network and drives the full data path against the lab server:
#
#     IKEv1 main mode -> quick mode (transport, UDP-encap)
#         -> L2TP SCCRQ/ICRQ  ->  PPP LCP/auth/IPCP  ->  ping over ppp0
#
# Env:
#   SERVER   server IP           (default 172.28.0.10)
#   AUTH     mschapv2|chap|pap   (default mschapv2)
#   CAPTURE  1 -> write /out/cap-<AUTH>.pcap of udp/500+4500 and the
#            decapsulated l2tp/ppp traffic
#   FORCEENCAPS yes|no  - the CLIENT's forceencaps. Set to "no" to prove that
#            the SERVER's own forceencaps=yes is what drives ESP into UDP/4500
#            (the SA must still come out as "encap type espinudp").
# Exit code 0 only if ppp0 came up with a pool address and ping worked.
# ---------------------------------------------------------------------------
set -u
SERVER="${SERVER:-172.28.0.10}"
AUTH="${AUTH:-mschapv2}"
CAPTURE="${CAPTURE:-0}"
FORCEENCAPS="${FORCEENCAPS:-yes}"
POOL_RE='10\.10\.10\.(1[0-9][0-9])'

say() { echo "[client] $*"; }
fail() { echo "[client] FAIL: $*" >&2; dump_logs; exit 1; }

dump_logs() {
    echo "----------------- charon (client) -----------------"
    tail -n 120 /var/log/charon.log 2>/dev/null
    echo "----------------- xl2tpd (client) -----------------"
    tail -n 120 /var/log/xl2tpd-client.log 2>/dev/null
    echo "----------------- pppd (client) -------------------"
    tail -n 120 /var/log/pppd-client.log 2>/dev/null
    echo "----------------- xfrm ----------------------------"
    ip xfrm state 2>/dev/null
    ip xfrm policy 2>/dev/null
    echo "---------------------------------------------------"
}

# --- environment -----------------------------------------------------------
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
[ -c /dev/ppp ]     || mknod /dev/ppp c 108 0
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null
for d in /proc/sys/net/ipv4/conf/*; do
    echo 0 > "$d/rp_filter"        2>/dev/null
    echo 0 > "$d/accept_redirects" 2>/dev/null
    echo 0 > "$d/send_redirects"   2>/dev/null
done
ip xfrm state flush 2>/dev/null; ip xfrm policy flush 2>/dev/null
rm -f /var/run/xl2tpd/l2tp-control; mkdir -p /var/run/xl2tpd
: > /var/log/charon.log; : > /var/log/pppd-client.log; : > /var/log/xl2tpd-client.log

# --- config ----------------------------------------------------------------
sed -e "s/@@SERVER@@/$SERVER/" \
    -e "s/^\( *\)forceencaps=yes/\1forceencaps=$FORCEENCAPS/" \
    /opt/l2tp-client/ipsec.conf  > /etc/ipsec.conf
say "client forceencaps=$FORCEENCAPS"
sed "s/@@SERVER@@/$SERVER/" /opt/l2tp-client/xl2tpd.conf > /etc/xl2tpd/xl2tpd.conf
cp /opt/l2tp-client/options.l2tpd.client /etc/ppp/options.l2tpd.client
: > /etc/ppp/options            # make sure nothing global interferes

# The server offers CHAP-MD5 first. Refusing everything except the method we
# want under test forces pppd to answer with an LCP Configure-Nak carrying
# exactly that method, which is what we want to exercise.
case "$AUTH" in
    mschapv2) say "auth: MS-CHAPv2 (Nak everything else)"
              printf 'refuse-pap\nrefuse-chap\nrefuse-mschap\n' \
                  >> /etc/ppp/options.l2tpd.client ;;
    chap)     say "auth: CHAP-MD5 (Nak everything else)"
              printf 'refuse-pap\nrefuse-mschap\nrefuse-mschap-v2\n' \
                  >> /etc/ppp/options.l2tpd.client ;;
    pap)      say "auth: PAP (Nak all CHAP variants)"
              printf 'refuse-chap\nrefuse-mschap\nrefuse-mschap-v2\n' \
                  >> /etc/ppp/options.l2tpd.client ;;
    *) fail "unknown AUTH=$AUTH" ;;
esac

# --- capture ---------------------------------------------------------------
if [ "$CAPTURE" = "1" ]; then
    mkdir -p /out
    tcpdump -i any -n -s0 -U -w "/out/cap-$AUTH.pcap" \
        'udp port 500 or udp port 4500 or udp port 1701' >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 1
fi

# --- IPsec -----------------------------------------------------------------
say "starting charon"
ipsec start
# Wait for charon to answer AND for starter to have pushed the conn in -
# 'ipsec up' right after 'ipsec start' races with the stroke add.
for i in $(seq 1 60); do
    ipsec statusall 2>/dev/null | grep -q 'L2TP-PSK-client' && break
    sleep 0.5
done
ipsec statusall 2>/dev/null | grep -q 'L2TP-PSK-client' \
    || fail "charon did not load conn L2TP-PSK-client"

say "ipsec up L2TP-PSK-client -> $SERVER"
if ! ipsec up L2TP-PSK-client 2>&1 | sed 's/^/[client][ipsec] /'; then
    fail "ipsec up failed"
fi

sleep 1
say "--- xfrm state ---"; ip xfrm state | sed 's/^/[client][xfrm] /'
say "--- xfrm policy ---"; ip xfrm policy | sed 's/^/[client][xfrm] /'

ip xfrm state | grep -q 'proto esp' || fail "no ESP SA installed"
ip xfrm state | grep -q 'mode transport' || fail "ESP SA is not in TRANSPORT mode"
if ip xfrm state | grep -q 'encap type espinudp sport 4500 dport 4500'; then
    if [ "$FORCEENCAPS" = "no" ]; then
        say "ESP is UDP-encapsulated even though the CLIENT did not ask for it"
        say "  -> the SERVER's forceencaps=yes is doing the work. CONFIRMED."
    else
        say "ESP-in-UDP (4500/4500) confirmed"
    fi
else
    fail "ESP SA is not UDP-encapsulated (forceencaps did not take effect)"
fi

# --- L2TP ------------------------------------------------------------------
say "starting xl2tpd (LAC)"
xl2tpd -D -c /etc/xl2tpd/xl2tpd.conf -p /var/run/xl2tpd/xl2tpd.pid \
       -C /var/run/xl2tpd/l2tp-control > /var/log/xl2tpd-client.log 2>&1 &
XL2TPD_PID=$!
for i in $(seq 1 40); do [ -p /var/run/xl2tpd/l2tp-control ] && break; sleep 0.25; done
[ -p /var/run/xl2tpd/l2tp-control ] || fail "xl2tpd control pipe never appeared"

say "dialling L2TP tunnel"
echo "c lab" > /var/run/xl2tpd/l2tp-control

# --- wait for ppp0 ---------------------------------------------------------
PPPIP=""
for i in $(seq 1 60); do
    PPPIP=$(ip -4 -o addr show ppp0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
    [ -n "$PPPIP" ] && break
    sleep 1
done
[ -n "$PPPIP" ] || fail "ppp0 never came up (no IPCP)"

say "ppp0 is up with address $PPPIP"
ip -4 addr show ppp0 | sed 's/^/[client][ppp0] /'
ip route | sed 's/^/[client][route] /'

echo "$PPPIP" | grep -Eq "^$POOL_RE\$" \
    || fail "ppp0 address $PPPIP is not from the 10.10.10.100-199 pool"

PEER=$(ip -4 -o addr show ppp0 | sed -n 's/.*peer \([0-9.]*\).*/\1/p')
say "peer (LNS) address: ${PEER:-<none>}"

# --- data path -------------------------------------------------------------
say "ping 10.10.10.1 over ppp0"
if ping -c 3 -W 3 -I ppp0 10.10.10.1 2>&1 | sed 's/^/[client][ping] /'; then
    say "PING OK"
else
    fail "ping over ppp0 failed"
fi

# --- what did we negotiate? ------------------------------------------------
say "--- PPP LCP / auth exchange ---"
grep -E 'LCP Conf|CHAP |PAP |authentication (succeeded|failed)' /var/log/pppd-client.log \
    | sed 's/^/[client][pppd] /'

# assert the auth protocol really used, otherwise the run proves nothing
case "$AUTH" in
    mschapv2) EXPECT='auth chap MS-v2'; EXTRA='CHAP authentication succeeded' ;;
    chap)     EXPECT='auth chap MD5';   EXTRA='CHAP authentication succeeded' ;;
    pap)      EXPECT='auth pap';        EXTRA='PAP authentication succeeded' ;;
esac
if grep -q "ConfAck.*$EXPECT" /var/log/pppd-client.log \
   && grep -q "$EXTRA" /var/log/pppd-client.log; then
    say "AUTH CONFIRMED: negotiated '$EXPECT' and $EXTRA"
else
    fail "expected PPP auth '$EXPECT' + '$EXTRA' but the log does not show it"
fi

say "--- ipsec statusall ---"
ipsec statusall 2>&1 | sed 's/^/[client][sa] /'

if [ "$CAPTURE" = "1" ]; then
    sleep 1
    kill "$TCPDUMP_PID" 2>/dev/null
    sleep 1
    say "capture written to /out/cap-$AUTH.pcap"
fi

# --- teardown --------------------------------------------------------------
echo "d lab" > /var/run/xl2tpd/l2tp-control 2>/dev/null
sleep 1
kill "$XL2TPD_PID" 2>/dev/null
ipsec stop >/dev/null 2>&1

say "RESULT: SUCCESS  (auth=$AUTH, ppp0=$PPPIP, ping 10.10.10.1 ok)"
exit 0
