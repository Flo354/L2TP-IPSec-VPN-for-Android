#!/usr/bin/env python3
"""
Minimal RFC 2661 L2TP control-channel probe.

Sends a real SCCRQ to <host>:1701 and waits for an SCCRP. Used by verify.sh
to prove, from the container that runs the JVM tests, that:

  * the lab server is IP-reachable on the lab network,
  * xl2tpd is actually bound to UDP/1701 and speaks RFC 2661,
  * which AVPs xl2tpd puts in its SCCRP (printed - useful reference for the
    Kotlin client implementation).

Note: this deliberately talks *plaintext* L2TP (no IPsec). The lab server's
conn uses auto=add, so strongSwan installs no trap policy and plaintext
UDP/1701 is not blocked. Good enough as a liveness probe; the real
IPsec-protected path is exercised by client/run-client.sh.

Usage: l2tp_probe.py [host] [port] [timeout]
"""
import os
import socket
import struct
import sys

MSG_TYPES = {
    1: "SCCRQ", 2: "SCCRP", 3: "SCCCN", 4: "StopCCN", 6: "HELLO",
    7: "OCRQ", 8: "OCRP", 9: "OCCN", 10: "ICRQ", 11: "ICRP", 12: "ICCN",
    14: "CDN", 15: "WEN", 16: "SLI",
}
AVP_NAMES = {
    0: "Message Type", 1: "Result Code", 2: "Protocol Version",
    3: "Framing Capabilities", 4: "Bearer Capabilities", 5: "Tie Breaker",
    6: "Firmware Revision", 7: "Host Name", 8: "Vendor Name",
    9: "Assigned Tunnel ID", 10: "Receive Window Size", 11: "Challenge",
    13: "Challenge Response", 14: "Assigned Session ID", 15: "Call Serial Number",
    18: "Bearer Type", 19: "Framing Type", 24: "Tx Connect Speed",
    27: "Proxy Authen Type",
}


def avp(attr_type, value, mandatory=True, vendor=0):
    length = 6 + len(value)
    flags = (0x8000 if mandatory else 0) | length
    return struct.pack("!HHH", flags, vendor, attr_type) + value


def build_sccrq(tunnel_id=1, hostname=b"l2tp-probe"):
    body = b"".join([
        avp(0, struct.pack("!H", 1)),                  # Message Type = SCCRQ
        avp(2, struct.pack("!BB", 1, 0)),              # Protocol Version 1.0
        avp(3, struct.pack("!I", 0x00000003)),         # Framing: async+sync
        avp(4, struct.pack("!I", 0x00000003)),         # Bearer: digital+analog
        avp(7, hostname),                              # Host Name
        avp(8, b"l2tp-probe", mandatory=False),        # Vendor Name
        avp(9, struct.pack("!H", tunnel_id)),          # Assigned Tunnel ID
        avp(10, struct.pack("!H", 4)),                 # Receive Window Size
    ])
    # T=1 L=1 S=1 Ver=2  -> 0xC802
    hdr = struct.pack("!HHHHHH", 0xC802, 12 + len(body), 0, 0, 0, 0)
    return hdr + body


def parse(pkt):
    if len(pkt) < 12:
        raise ValueError("short packet (%d bytes)" % len(pkt))
    flags = struct.unpack("!H", pkt[0:2])[0]
    is_ctrl = bool(flags & 0x8000)
    has_len = bool(flags & 0x4000)
    has_seq = bool(flags & 0x0800)
    ver = flags & 0x000F
    off = 2
    length = None
    if has_len:
        length = struct.unpack("!H", pkt[off:off + 2])[0]
        off += 2
    tid, sid = struct.unpack("!HH", pkt[off:off + 4]); off += 4
    ns = nr = None
    if has_seq:
        ns, nr = struct.unpack("!HH", pkt[off:off + 4]); off += 4

    avps = []
    body = pkt[off:length] if length else pkt[off:]
    i = 0
    while i + 6 <= len(body):
        f, vendor, atype = struct.unpack("!HHH", body[i:i + 6])
        alen = f & 0x03FF
        if alen < 6 or i + alen > len(body):
            break
        avps.append((bool(f & 0x8000), vendor, atype, body[i + 6:i + alen]))
        i += alen
    return dict(ctrl=is_ctrl, ver=ver, tid=tid, sid=sid, ns=ns, nr=nr, avps=avps)


def describe(avps):
    out = []
    for mand, vendor, atype, val in avps:
        name = AVP_NAMES.get(atype, "type %d" % atype)
        if vendor:
            name = "vendor %d / %s" % (vendor, name)
        if atype == 0 and len(val) == 2:
            mt = struct.unpack("!H", val)[0]
            pretty = "%s (%d)" % (MSG_TYPES.get(mt, "?"), mt)
        elif atype in (7, 8):
            pretty = val.decode("latin1")
        elif len(val) == 2:
            pretty = str(struct.unpack("!H", val)[0])
        elif len(val) == 4:
            pretty = "0x%08x" % struct.unpack("!I", val)[0]
        else:
            pretty = val.hex()
        out.append("      %-24s M=%d  %s" % (name, mand, pretty))
    return "\n".join(out)


def build_sccrq_variant(name, tunnel_id):
    """Different SCCRQ AVP sets, to find out what xl2tpd really insists on."""
    mt = avp(0, struct.pack("!H", 1))
    pv = avp(2, struct.pack("!BB", 1, 0))
    fc = avp(3, struct.pack("!I", 0x00000003))
    bc = avp(4, struct.pack("!I", 0x00000003))
    hn = avp(7, b"l2tp-probe")
    ti = avp(9, struct.pack("!H", tunnel_id))
    rws = avp(10, struct.pack("!H", 4))
    sets = {
        "full (MsgType,ProtoVer,Framing,Bearer,HostName,Vendor,TunnelID,RWS)":
            [mt, pv, fc, bc, hn, avp(8, b"probe", mandatory=False), ti, rws],
        "RFC 2661 mandatory only (MsgType,ProtoVer,HostName,Framing,TunnelID)":
            [mt, pv, hn, fc, ti],
        "no Host Name AVP":                       [mt, pv, fc, ti],
        "no Framing Capabilities AVP":            [mt, pv, hn, ti],
        "no Assigned Tunnel ID AVP":              [mt, pv, hn, fc],
        "no Protocol Version AVP":                [mt, hn, fc, ti],
        "Message Type AVP last instead of first": [pv, hn, fc, ti, mt],
    }
    body = b"".join(sets[name])
    hdr = struct.pack("!HHHHHH", 0xC802, 12 + len(body), 0, 0, 0, 0)
    return hdr + body, list(sets)


def run_variants(host, port, timeout):
    _, names = build_sccrq_variant(
        "no Host Name AVP", 1)  # just to get the name list
    print("SCCRQ AVP-set probe against %s:%d\n" % (host, port))
    for i, name in enumerate(names, 1):
        tid = struct.unpack("!H", os.urandom(2))[0] | 0x8000
        pkt, _ = build_sccrq_variant(name, tid)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        got = "no reply"
        try:
            sock.sendto(pkt, (host, port))
            data, _peer = sock.recvfrom(4096)
            msg = parse(data)
            mt = None
            for _m, _v, atype, val in msg["avps"]:
                if atype == 0 and len(val) == 2:
                    mt = struct.unpack("!H", val)[0]
            if mt is None and not msg["avps"]:
                got = "ZLB ACK only (no Message Type AVP) - request ignored"
            else:
                got = MSG_TYPES.get(mt, "msg %s" % mt)
            if mt == 4:  # StopCCN - look for the result/error text
                for _m, _v, atype, val in msg["avps"]:
                    if atype == 1:
                        got += " result=%d error=%d %r" % (
                            struct.unpack("!H", val[0:2])[0],
                            struct.unpack("!H", val[2:4])[0] if len(val) >= 4 else -1,
                            val[4:].decode("latin1"))
            if mt == 2:
                stop = b"".join([avp(0, struct.pack("!H", 4)),
                                 avp(9, struct.pack("!H", tid)),
                                 avp(1, struct.pack("!HH", 1, 0))])
                sock.sendto(struct.pack("!HHHHHH", 0xC802, 12 + len(stop),
                                        msg["tid"], 0, 1,
                                        (msg["ns"] or 0) + 1) + stop,
                            (host, port))
        except socket.timeout:
            pass
        finally:
            sock.close()
        print("  %-72s -> %s" % (name, got))
    return 0


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    host = args[0] if len(args) > 0 else "172.28.0.10"
    port = int(args[1]) if len(args) > 1 else 1701
    timeout = float(args[2]) if len(args) > 2 else 5.0
    if "--variants" in sys.argv:
        return run_variants(host, port, timeout)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.bind(("0.0.0.0", 0))
    # Random tunnel ID: xl2tpd remembers the ones it has seen and answers a
    # repeated "Assigned Tunnel ID" with a bare ZLB
    # ("Peer requested tunnel N twice, ignoring second one"), which would make
    # a second run of verify.sh fail for no good reason.
    my_tid = struct.unpack("!H", os.urandom(2))[0] | 0x8000
    sccrq = build_sccrq(tunnel_id=my_tid)
    print("    -> SCCRQ (%d bytes) to %s:%d" % (len(sccrq), host, port))
    for _ in range(3):
        sock.sendto(sccrq, (host, port))
        try:
            data, peer = sock.recvfrom(4096)
        except socket.timeout:
            continue
        msg = parse(data)
        mt = None
        for _m, _v, atype, val in msg["avps"]:
            if atype == 0 and len(val) == 2:
                mt = struct.unpack("!H", val)[0]
        print("    <- %s from %s:%d  tunnel=%d Ns=%s Nr=%s" %
              (MSG_TYPES.get(mt, "msg %s" % mt), peer[0], peer[1],
               msg["tid"], msg["ns"], msg["nr"]))
        print(describe(msg["avps"]))
        if mt == 2:
            # be polite: tear the half-open tunnel down again
            stop = b"".join([
                avp(0, struct.pack("!H", 4)),                        # StopCCN
                avp(9, struct.pack("!H", my_tid)),                   # Assigned Tunnel ID
                avp(1, struct.pack("!HH", 1, 0)),                    # Result Code = 1
            ])
            hdr = struct.pack("!HHHHHH", 0xC802, 12 + len(stop),
                              msg["tid"], 0, 1, (msg["ns"] or 0) + 1)
            sock.sendto(hdr + stop, (host, port))
            return 0
        return 2
    print("    !! no SCCRP received within %.1fs" % timeout)
    return 1


if __name__ == "__main__":
    sys.exit(main())
