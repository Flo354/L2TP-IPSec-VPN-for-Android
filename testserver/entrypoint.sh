#!/bin/bash
# ---------------------------------------------------------------------------
# entrypoint.sh - bring up a real L2TP/IPsec PSK server inside a container.
#
#   1. create /dev/net/tun and /dev/ppp if the runtime did not
#   2. load whatever kernel modules we are allowed to load
#   3. fix the sysctls that silently break L2TP/IPsec in containers
#   4. start charon (strongSwan starter/stroke)
#   5. start xl2tpd in the foreground
#   6. stream charon / xl2tpd / pppd logs to stdout
# ---------------------------------------------------------------------------
set -u

log() { echo "[entrypoint] $*"; }

# ---------------------------------------------------------------------------
# 1. devices
# ---------------------------------------------------------------------------
mkdir -p /dev/net
if [ ! -c /dev/net/tun ]; then
    log "creating /dev/net/tun"
    mknod /dev/net/tun c 10 200 && chmod 600 /dev/net/tun || log "WARN: mknod tun failed"
fi
if [ ! -c /dev/ppp ]; then
    log "creating /dev/ppp"
    mknod /dev/ppp c 108 0 && chmod 600 /dev/ppp || log "WARN: mknod ppp failed"
fi
ls -l /dev/net/tun /dev/ppp 2>&1 | sed 's/^/[entrypoint] /'

# ---------------------------------------------------------------------------
# 2. kernel modules (best effort - usually already loaded on the host)
# ---------------------------------------------------------------------------
for m in af_key xfrm_user xfrm_algo esp4 ah4 ppp_generic ppp_async ppp_deflate \
         pppox pppol2tp l2tp_ppp l2tp_core l2tp_netlink tun; do
    modprobe "$m" 2>/dev/null && log "modprobe $m: ok"
done

# ---------------------------------------------------------------------------
# 3. sysctls  --  THIS is what breaks L2TP/IPsec in containers
# ---------------------------------------------------------------------------
set_sysctl() { [ -w "/proc/sys/$1" ] && echo "$2" > "/proc/sys/$1" 2>/dev/null; }

set_sysctl net/ipv4/ip_forward 1
for d in /proc/sys/net/ipv4/conf/*; do
    iface=$(basename "$d")
    set_sysctl "net/ipv4/conf/$iface/send_redirects"   0
    set_sysctl "net/ipv4/conf/$iface/accept_redirects" 0
    set_sysctl "net/ipv4/conf/$iface/rp_filter"        0
    set_sysctl "net/ipv4/conf/$iface/forwarding"       1
done
# defaults for interfaces that appear later (ppp0 ...)
set_sysctl net/ipv4/conf/default/rp_filter        0
set_sysctl net/ipv4/conf/default/accept_redirects 0
set_sysctl net/ipv4/conf/default/send_redirects   0
log "ip_forward=$(cat /proc/sys/net/ipv4/ip_forward) all.rp_filter=$(cat /proc/sys/net/ipv4/conf/all/rp_filter)"

# ---------------------------------------------------------------------------
# 4. firewall: wide open + NAT for the PPP pool
# ---------------------------------------------------------------------------
if iptables -L -n >/dev/null 2>&1; then
    iptables -P INPUT ACCEPT   2>/dev/null
    iptables -P FORWARD ACCEPT 2>/dev/null
    iptables -P OUTPUT ACCEPT  2>/dev/null
    iptables -t nat -C POSTROUTING -s 10.10.10.0/24 -j MASQUERADE 2>/dev/null \
        || iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -j MASQUERADE 2>/dev/null
    log "iptables configured"
else
    log "WARN: iptables unusable in this container"
fi

# ---------------------------------------------------------------------------
# 4b. optionally pin the PPP auth protocol we offer ($PPP_AUTH)
#     any (default) = offer CHAP-MD5, accept a Nak to MS-CHAPv2 or PAP
# ---------------------------------------------------------------------------
PPP_AUTH="${PPP_AUTH:-any}"
case "$PPP_AUTH" in
    any)      AUTH_LINES=$'require-chap\nrequire-mschap-v2\nrequire-pap' ;;
    chap)     AUTH_LINES='require-chap' ;;
    mschapv2) AUTH_LINES='require-mschap-v2' ;;
    pap)      AUTH_LINES='require-pap' ;;
    *) log "WARN: unknown PPP_AUTH='$PPP_AUTH', falling back to 'any'"
       PPP_AUTH=any
       AUTH_LINES=$'require-chap\nrequire-mschap-v2\nrequire-pap' ;;
esac
awk -v repl="$AUTH_LINES" '
    /^# >>> AUTH-METHODS >>>/ { print; print repl; skip=1; next }
    /^# <<< AUTH-METHODS <<</ { skip=0 }
    !skip { print }
' /etc/ppp/options.xl2tpd > /tmp/options.xl2tpd.new \
    && mv /tmp/options.xl2tpd.new /etc/ppp/options.xl2tpd
log "PPP auth offer: PPP_AUTH=$PPP_AUTH -> $(echo "$AUTH_LINES" | tr '\n' ' ')"

# ---------------------------------------------------------------------------
# 5. runtime dirs / clean state
# ---------------------------------------------------------------------------
mkdir -p /var/run/xl2tpd /var/run/pluto /var/log
rm -f /var/run/xl2tpd/l2tp-control /var/run/xl2tpd/xl2tpd.pid
: > /var/log/charon.log
: > /var/log/xl2tpd.log
: > /var/log/pppd.log

# a fresh container may inherit stale xfrm state from a previous run
ip xfrm state flush  2>/dev/null
ip xfrm policy flush 2>/dev/null

# ---------------------------------------------------------------------------
# 6. charon
# ---------------------------------------------------------------------------
log "starting strongSwan (charon)..."
ipsec start
# wait until charon answers AND starter has pushed conn L2TP-PSK in
for i in $(seq 1 60); do
    ipsec statusall 2>/dev/null | grep -q 'L2TP-PSK' && break
    sleep 0.5
done
if ! ipsec statusall 2>/dev/null | grep -q 'L2TP-PSK'; then
    log "ERROR: charon did not come up / conn L2TP-PSK not loaded"
    sed 's/^/[charon] /' /var/log/charon.log
    exit 1
fi
ipsec status 2>&1 | sed 's/^/[entrypoint] /'

# ---------------------------------------------------------------------------
# 7. log streaming
# ---------------------------------------------------------------------------
tail -n +1 -F /var/log/charon.log 2>/dev/null | sed -u 's/^/[charon]  /' &
TAIL_CHARON=$!
tail -n +1 -F /var/log/pppd.log   2>/dev/null | sed -u 's/^/[pppd]    /' &
TAIL_PPPD=$!

XL2TPD_PID=""
cleanup() {
    log "shutting down"
    kill "$TAIL_CHARON" "$TAIL_PPPD" 2>/dev/null
    kill "$XL2TPD_PID" 2>/dev/null
    ipsec stop 2>/dev/null
    exit 0
}
trap cleanup TERM INT

# ---------------------------------------------------------------------------
# 8. xl2tpd (foreground, -D = no fork, logs to stderr)
# ---------------------------------------------------------------------------
log "starting xl2tpd..."
xl2tpd -D -c /etc/xl2tpd/xl2tpd.conf -p /var/run/xl2tpd/xl2tpd.pid \
       -C /var/run/xl2tpd/l2tp-control 2>&1 \
    | tee -a /var/log/xl2tpd.log \
    | sed -u 's/^/[xl2tpd]  /' &
XL2TPD_PID=$!

sleep 2
log "-------------------------------------------------------------"
log " L2TP/IPsec lab server ready"
log "   PSK        : TestPreSharedKey2024!"
log "   user/pass  : vpnuser / VpnPass123"
log "   IKEv1 P1   : aes256-sha256-modp2048 (main mode)"
log "   IPsec P2   : esp aes256-sha256, transport, no PFS, forceencaps"
log "   PPP pool   : 10.10.10.100-10.10.10.199  (server 10.10.10.1)"
log "-------------------------------------------------------------"
ss -lunp 2>/dev/null | sed 's/^/[entrypoint] /'

wait "$XL2TPD_PID"
log "xl2tpd exited"
cleanup
