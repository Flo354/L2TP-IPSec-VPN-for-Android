#!/usr/bin/env python3
"""
IKEv1 main-mode phase-1 probe: find out exactly which SA payloads the lab
server (strongSwan 5.9.8, ike=aes256-sha256-modp2048!) accepts.

It sends only main-mode message 1 (HDR + SA + VIDs) and reports whether the
responder came back with an SA payload (proposal accepted) or with an
informational NOTIFY (usually NO_PROPOSAL_CHOSEN = 14).

Nothing is completed, so every accepted probe leaves a half-open IKE SA behind.
The lab server raises charon's DoS limits and sets half_open_timeout = 10s, and
each probe uses a fresh random initiator cookie, so repeated runs stay clean.

Usage:  ike_probe.py [host] [port]
"""
import os
import socket
import struct
import sys

# ---------------------------------------------------------------- constants
# IKEv1 phase-1 (ISAKMP DOI) transform attribute types - RFC 2409 Appendix A
ATTR_ENCRYPTION_ALGORITHM = 1
ATTR_HASH_ALGORITHM       = 2
ATTR_AUTHENTICATION_METHOD= 3
ATTR_GROUP_DESCRIPTION    = 4
ATTR_LIFE_TYPE            = 11
ATTR_LIFE_DURATION        = 12
ATTR_KEY_LENGTH           = 14

ENC_AES_CBC   = 7
ENC_3DES      = 5
HASH_SHA1     = 2
HASH_SHA2_256 = 4
AUTH_PSK      = 1
GROUP_MODP1024 = 2
GROUP_MODP2048 = 14

PAYLOAD_NONE, PAYLOAD_SA, PAYLOAD_PROPOSAL, PAYLOAD_TRANSFORM = 0, 1, 2, 3
PAYLOAD_NOTIFY, PAYLOAD_VID = 11, 13

NOTIFY_NAMES = {
    1: "INVALID_PAYLOAD_TYPE", 7: "INVALID_FLAGS", 8: "INVALID_MESSAGE_ID",
    9: "INVALID_PROTOCOL_ID", 11: "INVALID_SPI",
    14: "NO_PROPOSAL_CHOSEN", 17: "PAYLOAD_MALFORMED",
    20: "INVALID_KEY_INFORMATION", 24: "AUTHENTICATION_FAILED",
    29: "ATTRIBUTES_NOT_SUPPORTED", 30: "NO_SA_ESTABLISHED",
}

VID_NATT_RFC3947 = bytes.fromhex("4a131c81070358455c5728f20e95452f")


# ------------------------------------------------------------------ builders
def tv(attr_type, value):
    """Basic (Type/Value) attribute - 4 bytes, AF bit set."""
    return struct.pack("!HH", 0x8000 | attr_type, value)


def tlv(attr_type, value_bytes):
    """Variable (Type/Length/Value) attribute - AF bit clear."""
    return struct.pack("!HH", attr_type, len(value_bytes)) + value_bytes


def transform(num, attrs, transform_id=1, last=True):
    body = b"".join(attrs)
    return struct.pack("!BBHBBH", 0 if last else 3, 0, 8 + len(body),
                       num, transform_id, 0) + body


def proposal(transforms, protocol_id=1, spi=b"", last=True):
    body = b"".join(transforms)
    return struct.pack("!BBHBBBB", 0 if last else 2, 0,
                       8 + len(spi) + len(body), 1, protocol_id,
                       len(spi), len(transforms)) + spi + body


def sa_payload(props, next_payload):
    body = struct.pack("!II", 1, 1) + b"".join(props)   # DOI=IPSEC, SIT=IDENTITY
    return struct.pack("!BBH", next_payload, 0, 4 + len(body)) + body


def vid_payload(data, next_payload):
    return struct.pack("!BBH", next_payload, 0, 4 + len(data)) + data


def isakmp(icookie, payloads, first_payload, exch=2, flags=0, msgid=0):
    body = b"".join(payloads)
    return (icookie + b"\0" * 8 +
            struct.pack("!BBBBII", first_payload, 0x10, exch, flags,
                        msgid, 28 + len(body)) + body)


# ------------------------------------------------------------------- parsing
def parse_response(data):
    if len(data) < 28:
        return "SHORT(%d bytes)" % len(data)
    nxt = data[16]
    total = struct.unpack("!I", data[24:28])[0]
    off = 28
    seen = []
    result = None
    while off + 4 <= min(len(data), total) and nxt != PAYLOAD_NONE:
        n2, _res, plen = struct.unpack("!BBH", data[off:off + 4])
        if plen < 4:
            break
        seen.append(nxt)
        if nxt == PAYLOAD_NOTIFY:
            doi, proto, spisz, ntype = struct.unpack("!IBBH", data[off + 4:off + 12])
            result = "NOTIFY %s (%d)" % (NOTIFY_NAMES.get(ntype, "?"), ntype)
        off += plen
        nxt = n2
    if result is None and PAYLOAD_SA in seen:
        result = "ACCEPTED (SA payload returned)"
    elif result is None:
        result = "payloads=%s" % seen
    return result


# --------------------------------------------------------------------- main
STD_ATTRS = [
    tv(ATTR_ENCRYPTION_ALGORITHM, ENC_AES_CBC),
    tv(ATTR_KEY_LENGTH, 256),
    tv(ATTR_HASH_ALGORITHM, HASH_SHA2_256),
    tv(ATTR_GROUP_DESCRIPTION, GROUP_MODP2048),
    tv(ATTR_AUTHENTICATION_METHOD, AUTH_PSK),
]


def variants():
    """(name, expectation, sa-payload-builder) - built lazily so each run gets
    a fresh cookie."""
    yield ("strongSwan's own attribute set (enc,keylen,hash,group,auth,"
           "lifetype=sec,lifeduration=0)", "accept",
           [proposal([transform(1, STD_ATTRS + [tv(ATTR_LIFE_TYPE, 1),
                                               tv(ATTR_LIFE_DURATION, 0)])])])

    yield ("minimal: enc,keylen,hash,group,auth - NO lifetime attributes",
           "accept", [proposal([transform(1, STD_ATTRS)])])

    yield ("lifetime as 4-byte TLV (28800s) instead of TV", "accept",
           [proposal([transform(1, STD_ATTRS + [
               tv(ATTR_LIFE_TYPE, 1),
               tlv(ATTR_LIFE_DURATION, struct.pack("!I", 28800))])])])

    yield ("attributes in a different order (auth,group,hash,keylen,enc)",
           "accept",
           [proposal([transform(1, [
               tv(ATTR_AUTHENTICATION_METHOD, AUTH_PSK),
               tv(ATTR_GROUP_DESCRIPTION, GROUP_MODP2048),
               tv(ATTR_HASH_ALGORITHM, HASH_SHA2_256),
               tv(ATTR_KEY_LENGTH, 256),
               tv(ATTR_ENCRYPTION_ALGORITHM, ENC_AES_CBC)])])])

    yield ("3 transforms, only #3 matches (3DES/SHA1, AES128, AES256/SHA256)",
           "accept",
           [proposal([
               transform(1, [tv(ATTR_ENCRYPTION_ALGORITHM, ENC_3DES),
                             tv(ATTR_HASH_ALGORITHM, HASH_SHA1),
                             tv(ATTR_GROUP_DESCRIPTION, GROUP_MODP1024),
                             tv(ATTR_AUTHENTICATION_METHOD, AUTH_PSK)],
                         last=False),
               transform(2, [tv(ATTR_ENCRYPTION_ALGORITHM, ENC_AES_CBC),
                             tv(ATTR_KEY_LENGTH, 128),
                             tv(ATTR_HASH_ALGORITHM, HASH_SHA2_256),
                             tv(ATTR_GROUP_DESCRIPTION, GROUP_MODP2048),
                             tv(ATTR_AUTHENTICATION_METHOD, AUTH_PSK)],
                         last=False),
               transform(3, STD_ATTRS)])])

    yield ("NO key-length attribute (AES with implicit key size)", "REJECT",
           [proposal([transform(1, [
               tv(ATTR_ENCRYPTION_ALGORITHM, ENC_AES_CBC),
               tv(ATTR_HASH_ALGORITHM, HASH_SHA2_256),
               tv(ATTR_GROUP_DESCRIPTION, GROUP_MODP2048),
               tv(ATTR_AUTHENTICATION_METHOD, AUTH_PSK)])])])

    yield ("AES-128 instead of AES-256", "REJECT",
           [proposal([transform(1, [
               tv(ATTR_ENCRYPTION_ALGORITHM, ENC_AES_CBC),
               tv(ATTR_KEY_LENGTH, 128),
               tv(ATTR_HASH_ALGORITHM, HASH_SHA2_256),
               tv(ATTR_GROUP_DESCRIPTION, GROUP_MODP2048),
               tv(ATTR_AUTHENTICATION_METHOD, AUTH_PSK)])])])

    yield ("SHA-1 instead of SHA-256", "REJECT",
           [proposal([transform(1, [
               tv(ATTR_ENCRYPTION_ALGORITHM, ENC_AES_CBC),
               tv(ATTR_KEY_LENGTH, 256),
               tv(ATTR_HASH_ALGORITHM, HASH_SHA1),
               tv(ATTR_GROUP_DESCRIPTION, GROUP_MODP2048),
               tv(ATTR_AUTHENTICATION_METHOD, AUTH_PSK)])])])

    yield ("MODP-1024 (group 2) instead of MODP-2048 (group 14)", "REJECT",
           [proposal([transform(1, [
               tv(ATTR_ENCRYPTION_ALGORITHM, ENC_AES_CBC),
               tv(ATTR_KEY_LENGTH, 256),
               tv(ATTR_HASH_ALGORITHM, HASH_SHA2_256),
               tv(ATTR_GROUP_DESCRIPTION, GROUP_MODP1024),
               tv(ATTR_AUTHENTICATION_METHOD, AUTH_PSK)])])])


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "172.28.0.10"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 500

    print("IKEv1 main-mode phase-1 probe against %s:%d\n" % (host, port))
    print("%-4s %-8s %-34s %s" % ("#", "expect", "result", "variant"))
    print("-" * 100)
    failures = 0
    for i, (name, expect, props) in enumerate(variants(), 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(4.0)
        # A *random* initiator cookie per probe is essential: charon keeps
        # half-open IKE_SAs around for half_open_timeout seconds and treats a
        # repeated cookie as a retransmission, so a fixed cookie makes repeat
        # runs of this script silently time out.
        icookie = os.urandom(8)
        sa = sa_payload(props, PAYLOAD_VID)
        vid = vid_payload(VID_NATT_RFC3947, PAYLOAD_NONE)
        pkt = isakmp(icookie, [sa, vid], PAYLOAD_SA)
        got = "NO RESPONSE"
        try:
            sock.sendto(pkt, (host, port))
            data, _ = sock.recvfrom(4096)
            got = parse_response(data)
        except socket.timeout:
            pass
        finally:
            sock.close()
        accepted = got.startswith("ACCEPTED")
        good = accepted if expect == "accept" else not accepted
        if not good:
            failures += 1
        print("%-4d %-8s %-34s %s   %s" %
              (i, expect, got, name, "" if good else "  <-- UNEXPECTED"))
    print("-" * 100)
    print("%d unexpected result(s)" % failures)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
