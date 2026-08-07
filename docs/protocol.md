# Protocol notes

What is implemented at each layer, which RFC says so, and — the part worth reading — the decisions
that would look arbitrary without an explanation.

See also: [architecture.md](architecture.md) for who runs this code,
[rekeying.md](rekeying.md) for SA replacement, [interoperability.md](interoperability.md) for what
real peers actually do.

## Contents

* [The five non-obvious decisions](#the-five-non-obvious-decisions)
* [One socket, three kinds of traffic](#one-socket-three-kinds-of-traffic)
* [IKEv1 — phase 1](#ikev1--phase-1)
* [NAT traversal](#nat-traversal)
* [IKEv1 — phase 2 (Quick Mode)](#ikev1--phase-2-quick-mode)
* [ESP](#esp)
* [The inner UDP datagram](#the-inner-udp-datagram)
* [L2TPv2](#l2tpv2)
* [PPP](#ppp)
* [MTU: the header budget and the MRU clamp](#mtu-the-header-budget-and-the-mru-clamp)
* [RFC index](#rfc-index)

## The five non-obvious decisions

Each is expanded below; this is the summary you want when reviewing a change.

| Decision | Why it is not optional |
| --- | --- |
| ESP is always UDP-encapsulated, forced by a bogus source NAT-D hash | An unprivileged Android app cannot open a raw IP socket, so it can never send or receive IP-protocol-50 ESP. Without forcing, a peer that sees no NAT would happily negotiate plain ESP and the tunnel would be silently unusable. |
| ESP runs in transport mode, not tunnel mode | The protected data is the UDP/1701 datagram itself. Tunnel mode would put a second IP header inside the ciphertext and set `nextHeader = 4`, which is not what an L2TP/IPsec peer expects. |
| The inner UDP checksum is zero | IPv4 permits it, and it side-steps the RFC 3948 §3.1.2 checksum fix-up entirely. Linux's own L2TP does the same. |
| The NAT-T dialect is chosen from the peer's vendor IDs | The payload numbers and the encapsulation-mode values are different between RFC 3947 and the pre-RFC drafts. Guessing wrong produces `NO_PROPOSAL_CHOSEN` or payloads the peer ignores. |
| The TUN MTU is `min(header budget, peer MRU)` | The header budget alone is not enough: a peer that advertises a smaller MRU will drop full-size frames only, which is the "ping works but TLS hangs" failure. |

## One socket, three kinds of traffic

There is exactly one socket, bound to an ephemeral local port and protected from the VPN it is
building. Once NAT traversal is active, port 4500 carries three different things, told apart by
their first bytes (RFC 3948 §2.2 and §4):

| First bytes | Kind | Handling |
| --- | --- | --- |
| `00 00 00 00` followed by more data | ISAKMP behind the **non-ESP marker** | strip four bytes, push to the IKE queue |
| anything else, ≥ minimum ESP size | ESP | demultiplex on the SPI, decrypt, push the inner L2TP packet to the L2TP queue |
| a single `FF` byte | NAT keepalive | drop |

An ESP packet can never be mistaken for an IKE message because SPI 0 is reserved and never
negotiated — the marker is exactly "an SPI field of zero". Before the float to 4500, everything
arriving is a bare ISAKMP message on port 500 and no classification is done.

The client sends its own keepalive — a single `FF` byte — every `natKeepaliveIntervalMs`
(default 20 s, matching charon's own default), from the maintenance thread.

## IKEv1 — phase 1

RFC 2408 (ISAKMP), RFC 2409 (IKEv1), RFC 2407 (the IPsec DOI). Pre-shared key only; certificates and
XAUTH are not implemented.

**Main mode** (the default, RFC 2409 §5.4):

```
HDR, SA                  -->        <-- HDR, SA
HDR, KE, Ni [, NAT-D×2]  -->        <-- HDR, KE, Nr [, NAT-D×2]
HDR*, IDii, HASH_I       -->        <-- HDR*, IDir, HASH_R
```

**Aggressive mode** is implemented too, and moves the NAT-D payloads into the last two messages
(RFC 3947 §4), so the port float happens before message 3 rather than before message 5:

```
HDR, SA, KE, Ni, IDii    -->        <-- HDR, SA, KE, Nr, IDir, HASH_R
HDR*, HASH_I [, NAT-D×2] -->
```

Aggressive mode exists for peers that require it; it leaks the initiator's identity in the clear and
is weaker against offline PSK cracking, so main mode is the default and should stay that way unless
a peer refuses it.

### The proposal

One transform is offered, built from `Phase1Proposal`:

| Attribute | Value from |
| --- | --- |
| Encryption Algorithm (1) | `phase1.encryption.transformId` |
| Key Length (14) | `phase1.encryption.keyBits`, **only when the cipher needs it** |
| Hash Algorithm (2) | `phase1.hash.transformId` |
| Authentication Method (3) | 1 = pre-shared key |
| Group Description (4) | `phase1.dhGroup.groupId` |
| Life Type (11) / Life Duration (12) | seconds / `phase1.lifetimeSeconds` |

The Key Length rule is not cosmetic: **AES must carry a Key Length attribute and 3DES must not.**
3DES has exactly one legal key size, so an explicit length is a protocol error; AES without one is
read by charon as "AES-CBC of unspecified size" and rejected. A missing Key Length on an AES
proposal is the single most common cause of an unexplained `NO_PROPOSAL_CHOSEN`.

The responder's answer must echo the transform we offered — encryption, hash, group, auth method and
key length must all match — or the negotiation is aborted with `IKE_PROPOSAL_REJECTED`. This client
offers exactly one transform, so there is nothing to select between.

### Lifetime

The **responder's** lifetime is what the rekey schedule follows, not ours. If the peer answers with
a shorter Life Duration than we proposed, the shorter number wins. Proposing three hours and being
granted ten minutes would otherwise leave the client renegotiating long after the SA had been torn
down. See [rekeying.md](rekeying.md#why-the-responders-lifetime-and-not-ours).

### The key schedule

RFC 2409 §5, pre-shared key variant, implemented as pure functions in `IkeKeyDerivation` so unit
tests can pin every derived value. A silent change here produces a tunnel that negotiates happily
and then drops every packet, which is close to undebuggable from the client side.

```
SKEYID   = prf(psk,     Ni_b | Nr_b)
SKEYID_d = prf(SKEYID,  g^xy | CKY-I | CKY-R | 0)
SKEYID_a = prf(SKEYID,  SKEYID_d | g^xy | CKY-I | CKY-R | 1)
SKEYID_e = prf(SKEYID,  SKEYID_a | g^xy | CKY-I | CKY-R | 2)
HASH_I   = prf(SKEYID,  g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b)
HASH_R   = prf(SKEYID,  g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b)
```

Two details that are easy to get wrong:

* **The cipher key expansion is not the generic PRF+.** RFC 2409 appendix B stretches a too-short
  `SKEYID_e` with `K1 = prf(SKEYID_e, 0x00)`, `Kn = prf(SKEYID_e, K(n-1))` — the *seed is not
  repeated* in later blocks, unlike the `prf+` used for KEYMAT. A `SKEYID_e` that is already long
  enough is simply truncated. With SHA-256 and AES-256 this path is not taken; with MD5 and 3DES it
  is, which is why a test covers it.
* **The phase-1 IV starts as `hash(g^xi | g^xr)`** truncated to the cipher block size, and then
  chains: each encrypted message's last ciphertext block is the next message's IV. Quick Mode and
  informational exchanges do *not* continue that chain — they each derive their own IV from
  `hash(last phase-1 IV | message id)`.

`HASH_R` is verified in constant time. A mismatch is reported as `IKE_AUTH_FAILED` with "the
pre-shared key is wrong", because that is what it means in practice.

### Identity

The default identity type is `AUTO_IPV4`: an `ID_IPV4_ADDR` payload carrying the socket's real local
address, with protocol and port zeroed. That is what road-warrior L2TP clients send. `FQDN`,
`USER_FQDN`, `KEY_ID` and an explicit `IPV4_ADDR` are also supported for peers that key their PSK on
an identity rather than on `%any`.

The identity is one of the inputs to `HASH_I`, which is why the local address has to be the real one
and not `0.0.0.0` — see [architecture.md](architecture.md#platform-seams).

## NAT traversal

### Why encapsulation is forced

An Android application without root cannot open a raw IP socket. It therefore cannot send an
IP-protocol-50 ESP packet, cannot receive one, and cannot ask the kernel to install an SA that would
do it. **UDP/4500 encapsulation is the only shape this client can speak at all.**

RFC 3947 makes encapsulation conditional on NAT detection: each side hashes
`CKY-I | CKY-R | address | port` for itself and for the peer, sends both, and concludes "there is a
NAT" when a received hash does not match what it computed. So the client makes itself
undetectable-as-itself on purpose:

```
NAT-D[0] = hash(CKY-I | CKY-R | peer address | peer port)     ← honest
NAT-D[1] = hash(CKY-I | CKY-R | our address  | 0)             ← port 0 instead of our real port
```

No responder can reproduce the second hash, so it concludes we are behind a NAT and encapsulates
unconditionally. This is precisely what strongSwan's `forceencaps=yes` does, and strongSwan even
logs it as `faking NAT situation to enforce UDP encapsulation`.

Symmetrically, when we have forced encapsulation we must also *conclude* that we are natted, even
though our own hash obviously matches: otherwise we would keep talking on port 500 after the peer
floated to 4500. That is why the local-NAT verdict is `localMismatch || forceUdpEncapsulation`.

Two guards make the failure mode explicit rather than silent:

* If the peer advertises no NAT-T vendor ID at all, phase 1 fails immediately with a message saying
  an unrooted Android client cannot carry ESP any other way.
* If the responder selects a non-UDP encapsulation mode in Quick Mode, phase 2 fails with
  `IPSEC_SA_FAILED` rather than installing an SA whose packets could never leave the device.

### Evaluating the peer's NAT-D payloads

RFC 3947 §3.2: the **first** NAT-D payload the peer sends hashes the destination — us, as the peer
sees us — and the rest hash the peer itself. So `received[0]` is compared against our own hash and
the remainder against the peer's. A peer that sends none at all is logged and treated as
"remote not natted".

The peer's port used in these hashes is 500 for the initial exchange and 4500 once we have floated.
That matters when phase 1 is renegotiated over an already-established NAT-T session: hashing the
wrong port would make both ends read the NAT state backwards.

### Dialects

RFC 3947 and the pre-RFC drafts allocated different numbers for the same payloads. Which one is in
use is decided from the vendor IDs the peer sent — and the vendor IDs are MD5 hashes of literal
marker strings, computed at runtime from those strings rather than pasted as hex so the mapping stays
auditable.

| Dialect | Vendor ID marker | NAT-D | NAT-OA | UDP-transport mode | UDP-tunnel mode |
| --- | --- | --- | --- | --- | --- |
| RFC 3947 | `"RFC 3947"` | 20 | 21 | 4 | 3 |
| draft-03 | `"draft-ietf-ipsec-nat-t-ike-03"` | 130 | 131 | 61444 | 61443 |
| draft-02 | `"draft-ietf-ipsec-nat-t-ike-02"` and the same string **with a trailing newline** | 130 | 131 | 61444 | 61443 |

The draft-02 newline variant exists because the draft text accidentally included the newline and
several widely deployed stacks hash it that way. Both are offered and both are accepted.

Selection prefers RFC 3947, then draft-03, then draft-02 — a peer offering several always prefers
the newest. The client offers all four NAT-T markers plus the RFC 3706 DPD vendor ID, and ignores
vendor IDs it does not recognise.

One further difference: **the drafts never specified a responder NAT-OA**, so only the initiator's
NAT-OA is sent in the draft dialects, while RFC 3947 sends both.

### NAT-OA

RFC 3947 §5.2 requires the original-address payloads for UDP-encapsulated *transport* mode: the
receiver needs the pre-NAT addresses to fix up TCP/UDP checksums. They are sent in Quick Mode when
either side is behind a NAT, with the same body layout as an ID payload — ID type, protocol, port,
address — and protocol and port set to zero.

Behind a real NAT the address to put here is your **pre-NAT (internal) address**, which is what the
socket reports, so this falls out correctly.

## IKEv1 — phase 2 (Quick Mode)

RFC 2409 §5.5:

```
HDR*, HASH(1), SA, Ni [, KE], IDci, IDcr [, NAT-OA×1..2]  -->
                    <-- HDR*, HASH(2), SA, Nr [, KE], IDci, IDcr [, NAT-OA]
HDR*, HASH(3)                                             -->
```

* `HASH(1) = prf(SKEYID_a, M-ID | everything after the HASH payload)`
* `HASH(2) = prf(SKEYID_a, M-ID | Ni_b | everything after the HASH payload)`
* `HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)`

`HASH(2)` is verified in constant time; a mismatch means the two sides disagree about the ISAKMP SA
keys and is reported as `IKE_AUTH_FAILED`.

Message ids are random and non-zero — id 0 is reserved for phase 1.

### The ESP proposal

| Attribute | Value |
| --- | --- |
| Transform ID | `phase2.encryption.transformId` (12 for AES) |
| Key Length (6) | `phase2.encryption.keyBits`, only when the cipher needs it |
| Authentication Algorithm (5) | `phase2.integrity.attributeValue` |
| Encapsulation Mode (4) | the dialect's UDP-transport value (4, or 61444 for the drafts) |
| SA Life Type (1) / Duration (2) | seconds / `phase2.lifetimeSeconds` |
| Group Description (3) | **only when PFS is configured**; its absence is what "no PFS" means |

Sending a Group Description requests PFS. Most consumer routers are not configured for it, so the
default is `null` — which is exactly what strongSwan's `esp=aes256-sha256!` (no `-modpNNNN` suffix)
means.

SPIs are four bytes, randomly chosen above 255 because RFC 4303 §2.1 reserves 0–255. **We choose our
inbound SPI; the peer's reply carries its own inbound SPI, which is our outbound one.** Getting that
backwards produces an SA that encrypts with the wrong key and drops every packet.

### Traffic selectors

L2TP runs over UDP/1701 in transport mode, so the selectors are single host/port pairs rather than
subnets:

```
IDci = ID_IPV4_ADDR, protocol 17 (UDP), port 1701, our address
IDcr = ID_IPV4_ADDR, protocol 17 (UDP), port 1701, the peer's address
```

The resulting kernel policy on a strongSwan peer only passes UDP to and from port 1701, so anything
else sent inside the SA is dropped. A peer's port of 0 ("any") also matches; 1701 is the safe choice.

### KEYMAT

```
KEYMAT = prf+(SKEYID_d, [g(qm)^xy |] protocol | SPI | Ni_b | Nr_b)
```

Run once per direction: **our own SPI yields the keys the peer encrypts with** (our inbound keys),
**the peer's SPI yields ours** (outbound). The quick-mode secret is empty when PFS is off. The
required length is the cipher key length plus the integrity key length, split in that order.

Unlike the phase-1 cipher-key expansion, this is the generic `prf+` — the seed *is* repeated in each
block.

### Answering a Quick Mode the peer started

Fully implemented; see [rekeying.md](rekeying.md#answering-a-peer-initiated-quick-mode). Two details
belong here:

* The peer's traffic selectors are **echoed verbatim**. Narrowing them is what makes a peer reject
  the answer, and we accept whatever it proposed for the L2TP flow anyway.
* Whatever PFS group the peer asked for is honoured, not only the configured one — a router with PFS
  enabled would otherwise get an answer it has to reject.

## ESP

RFC 4303, **transport mode**, CBC cipher plus HMAC, carried inside UDP/4500 (RFC 3948).

```
SPI (4) | Seq (4) | IV (blockBytes) | ciphertext | ICV (icvBytes)
ciphertext = E(key, IV, payload | padding | padLength(1) | nextHeader(1))
```

The protected `payload` is a complete **transport-layer datagram** — the inner UDP/1701 datagram —
and `nextHeader` is therefore 17. There is no inner IP header at all; the only IP header on the wire
is the outer one of the UDP/4500 datagram (RFC 3948 §2.1).

This is the single most misunderstood point of the design. Tunnel mode would put a second IP header
inside the ciphertext and set `nextHeader = 4`, which is not what an L2TP/IPsec peer expects, and
would also need an inner source address the client does not have until PPP has finished.

### Outbound

* Sequence numbers start at 1 and are atomic, so a number is never reused even under concurrent
  sends.
* The IV is fresh per packet from a CSPRNG, as RFC 4303 §3.3.2.1 requires it to be unpredictable.
* Padding follows the RFC 4303 §2.4 default pattern `1, 2, 3, …` and is the minimum needed to make
  `payload | pad | padLength | nextHeader` a whole number of cipher blocks.
* **The ICV covers `SPI | Seq | IV | ciphertext` and nothing else** — never the outer IP or UDP
  headers. That is exactly why a NAT on the path may rewrite the outer addresses and ports without
  breaking the integrity check, and why the client can force encapsulation without breaking anything.

### Inbound

Order of operations, per RFC 4303 §3.4.4, and it matters:

1. **Length and SPI** — the demultiplexing fields, which carry no secret.
2. **ICV, in constant time.** A forged packet therefore reaches neither the replay window nor the
   cipher.
3. **Replay window**, updated only now that the packet is known to be authentic.
4. **Decrypt**, then strip `padding | padLength | nextHeader`. The pad *bytes* are not checked,
   because RFC 4303 §2.4 lets the sender choose them.

Every failure raises an exception the tunnel logs at debug level and drops the packet. A single bad
datagram on a UDP-encapsulated SA is normal on a lossy link and must never tear down the session.

The anti-replay window is the bitmap variant of RFC 4303 appendix A1: bit *i* records
`highest - i`, so advancing is a left shift. Only 32-bit sequence numbers are used — IKEv1 never
negotiates extended sequence numbers. Sequence 0 is never valid.

### Inbound demultiplexing during a rekey

Two inbound SAs are alive during the overlap window, so **the SPI in the ESP header — not "whichever
one is current" — decides which keys to use.** Getting this wrong loses every packet the peer had
already put on the wire under the old SA. See [rekeying.md](rekeying.md#make-before-break).

## The inner UDP datagram

ESP transport mode protects a transport-layer datagram, so the client has to build one. The outer
UDP/4500 header is produced by the kernel through an ordinary `DatagramSocket`; the inner UDP/1701
header is written by hand.

**Its checksum is zero.** RFC 768 makes the IPv4 UDP checksum optional, signalled by a zero field.
Setting it would mean computing a pseudo-header over the source address — but behind a NAT the
source address is rewritten *after* the checksum would have been computed, so RFC 3948 §3.1.2
requires a receiver-side fix-up using the NAT-OA payloads. A zero checksum side-steps the whole
problem. Linux's own L2TP implementation does the same thing, and every peer we have tested accepts
it.

The codec can compute a real checksum when given both addresses, which the tests use; the send path
never does.

## L2TPv2

RFC 2661. The client is the **LAC**: it dials out, so the call is nonetheless an *incoming* call from
the LNS's point of view, which is why establishment uses ICRQ and not OCRQ.

```
control header:  |T=1 L=1 S=1 ... Ver=2| Length | Tunnel ID | Session ID | Ns | Nr | AVPs...
data header:     |T=0 L=1 S=0 ... Ver=2| Length | Tunnel ID | Session ID | PPP frame...
```

The first two bytes are `C8 02` for a control message and `40 02` for a data message with the length
bit set.

**Addressing rule:** every packet you send carries the ids *the peer assigned* — the Assigned Tunnel
ID from its SCCRP and the Assigned Session ID from its ICRP. Packets from the peer carry the ids you
assigned. Getting this backwards makes the peer silently drop everything.

### Establishment

```
-> SCCRQ   Message Type, Protocol Version, Host Name, Framing Caps,
           Bearer Caps, Firmware Revision, Assigned Tunnel ID, Receive Window Size
<- SCCRP   Assigned Tunnel ID, Host Name, [Challenge]
-> SCCCN   [Challenge Response]
-> ICRQ    Assigned Session ID, Call Serial Number
<- ICRP    Assigned Session ID
-> ICCN    Tx Connect Speed, Framing Type
```

The Message Type AVP **must be the first AVP** of every message (RFC 2661 §4.1) — xl2tpd refuses the
message outright otherwise, answering with a bare ZLB. Framing Capabilities and Assigned Tunnel ID
are likewise hard requirements in the SCCRQ. Both framing bits (async and sync) are claimed so no LNS
rejects the client on framing grounds.

### The control channel

* **Ns/Nr sequencing** with a 16-bit wrapping space. An out-of-order or duplicate message is
  re-acknowledged and dropped.
* **ZLB acks**: a control message with no AVPs whose only job is to carry Nr. It consumes no sequence
  number and is never retransmitted. A pending acknowledgement is flushed whenever nothing upstream
  is going to carry it.
* **Retransmission** with exponential back-off, capped so retries stay useful. Exceeding the retry
  budget fails the tunnel.
* **HELLO** every `l2tpHelloIntervalMs`, which doubles as the liveness probe for the whole stack —
  the HELLO has to survive ESP, so an unanswered one means the tunnel is gone, whatever the reason.
  Only one HELLO is kept in flight at a time.
* **Receive Window Size 8** is advertised. Peers commonly advertise 4, meaning no more than four
  unacknowledged control messages may be in flight towards them.
* **Tunnel authentication** (RFC 2661 §5.1.1) is implemented: if the SCCRP carries a Challenge, the
  SCCCN answers with `MD5(message type | secret | challenge)`. It needs a configured tunnel secret,
  and there is currently no way to set one from the app, so a peer that requires it fails with a
  clear message.
* **AVP hiding** (RFC 2661 §4.3) is implemented on the receive side. The client never hides what it
  sends.

### Teardown

`CDN` for the session, then `StopCCN` for the control connection, each attempted independently so a
failed CDN does not cost the StopCCN, and neither is retransmitted. Getting these out is what stops
the router keeping a stale session; see
[android.md](android.md#the-teardown-ordering-trap).

## PPP

The RFC 1661 §4 automaton reduced to what a client needs: per control protocol, track whether our
Configure-Request has been acknowledged and whether we have acknowledged the peer's, and consider the
protocol open when both are true.

**There is no HDLC framing.** L2TP already delimits the frame, so there are no `7E` flags, no byte
stuffing and no FCS (RFC 2661 §4.3). A frame is `FF 03` plus the two-byte protocol field plus the
payload. Address/control is emitted because that is what pppd sends on an L2TP session, and is
tolerated in either form on receive. The protocol field is always emitted uncompressed; a received
compressed field (odd low byte, RFC 1661 §6.5) is parsed.

### LCP

Requested: MRU (the computed tunnel MTU) and a Magic Number.

Accepted from the peer: MRU, Magic Number, and an Authentication-Protocol option naming something in
`allowedPppAuth`. **Everything else is Configure-Rejected**, including PFC and ACFC — rejecting those
two also keeps the frames the client parses and emits in their canonical form, which is worth more
than the two bytes they would save.

The RFC 1661 §5.1 precedence is followed exactly: an unrecognised option produces a Configure-Reject,
an unacceptable value a Configure-Nak, otherwise the request is acknowledged verbatim.

**Steering the authentication protocol.** The peer offers one; if it is not in our allowed list we
answer with a Configure-Nak naming our preferred one. When the peer proposed a CHAP flavour we
counter with a CHAP flavour if we have one, so a server that only speaks CHAP is not pushed to PAP.
That single Nak is how the client selects MS-CHAPv2 out of a pppd that offers CHAP-MD5 first.

**Loopback detection** (RFC 1661 §6.4): a peer that echoes our magic number, in a Configure-Request
or in an Echo-Request, fails the session immediately.

**Echoes:** an LCP Echo-Request every 20 s; five unanswered ones fail the session. Echo-Requests from
the peer are answered with the request's data and our own magic number. A peer that Code-Rejects
Echo-Request disables keepalives rather than failing.

### Authentication

| Protocol | RFC | Notes |
| --- | --- | --- |
| PAP | RFC 1334 | **Client-initiated**: the Authenticate-Request goes out as soon as LCP opens, without waiting. Its own identifier space. Retransmitted up to a small budget. |
| CHAP-MD5 | RFC 1994 | Response is `MD5(id \| password \| challenge)`. The challenge length is *not* fixed — real servers use anything from 16 to 24 bytes. |
| MS-CHAPv2 | RFC 2759 | Needs MD4, which the JDK does not provide, so it is implemented here. |

MS-CHAPv2 response layout (RFC 2759 §4), 49 bytes:

```
PeerChallenge (16) | Reserved (8, zero) | NT-Response (24) | Flags (1)
```

**The server's authenticator response is verified.** The Success message carries
`S=<40 uppercase hex>`; the client recomputes it and compares in constant time. This is the half of
MS-CHAPv2 that authenticates the *server* to us — accepting a Success without checking it would let
anything on the path claim the tunnel is authenticated. A mismatch fails with `PPP_AUTH_FAILED`.

MS-CHAPv2 Failure messages carry `E=<code>`, which is decoded into a readable reason.

MPPE is never negotiated (CCP is rejected), so the MS-CHAPv2 master keys are not needed.

### IPCP

RFC 1332 plus the RFC 1877 DNS options.

```
-> IPCP ConfReq <addr 0.0.0.0> <ms-dns1 0.0.0.0> <ms-dns2 0.0.0.0>
<- IPCP ConfNak <addr 10.x.x.x> <ms-dns1 ...> <ms-dns2 ...>
-> IPCP ConfReq <addr 10.x.x.x> <ms-dns1 ...> <ms-dns2 ...>
<- IPCP ConfAck
```

Asking for `0.0.0.0` is the idiom that makes the peer fill the values in with a Configure-Nak. The
DNS options are types 129 and 131 (Microsoft's Primary-DNS and Secondary-DNS); a Configure-Reject for
them costs only the DNS servers and the session continues. A Configure-Reject for the IP-Address
option, on the other hand, fails the session — there is no connectivity without an address.

Van Jacobson header compression is not implemented and is rejected; IPCP is perfectly happy without
it.

If IPCP completes without the peer having assigned an address, the session fails rather than bringing
up a TUN with `0.0.0.0`.

Anything else the peer sends — IPV6CP, for instance, which a real Livebox does send — gets an LCP
Protocol-Reject (RFC 1661 §5.7), which is exactly what pppd does.

### Result

What the tunnel takes from PPP: the assigned local address, the peer address, the DNS servers, the
authentication protocol actually used, and **the MRU**, computed as `min(our MRU, the peer's MRU)` —
what we may transmit is bounded by the peer's MRU, what we may receive by ours.

## MTU: the header budget and the MRU clamp

Getting this wrong is *the* classic L2TP/IPsec failure mode: the tunnel comes up, ping works, and
then TLS handshakes hang forever because full-size segments are silently dropped somewhere with the
DF bit set. Small packets always get through; only the big ones die, so everything looks fine until
something tries to move real data.

### The header budget

```
IP(20) UDP(8) | ESP: SPI(4) Seq(4) IV(bs) [ UDP(8) L2TP(8) PPP(4) <IP packet> pad padLen(1) nh(1) ] ICV
```

The outer IP and UDP headers are added by the OS, so they only reduce the budget handed to the
socket; everything inside is the client's to account for.

```
espBudget      = pathMtu - 20 - 8
maxEspPayload  = floor((espBudget - 4 - 4 - blockBytes - icvBytes) / blockBytes) * blockBytes - 2
tunnelMtu      = min(maxEspPayload - 8 - 8 - 4, configuredCeiling)
```

The floor division is exact rather than conservative: the ciphertext is a whole number of cipher
blocks, so rounding the budget down to a block boundary and subtracting the two trailer bytes gives
the true maximum. With AES-256-CBC (16-byte blocks and IV) and HMAC-SHA-256-128 (16-byte ICV) on a
1500-byte path, the budget lands comfortably above the default 1400 ceiling, so the configured
ceiling normally wins.

**The path MTU is not measured.** `Mtu.DEFAULT_PATH_MTU` is a fixed 1500. On a path with a smaller
MTU — a PPPoE uplink, a tunnel of your own — the budget is optimistic and the configured ceiling is
the only protection. This is a real limitation, not an oversight to ignore.

### The MRU clamp

The header budget is only half the story. The peer also tells us, in LCP, the largest frame it is
willing to receive. Handing the TUN anything above that means our full-size packets are dropped at
the far end while everything small gets through — the "ping works but TLS hangs" failure exactly.

So the MTU actually given to the TUN is:

```
effectiveMtu = min(headerBudgetMtu, peerMru)
```

and the client logs the clamp when it happens. The lab deliberately advertises an MRU *below* the
client's own header budget precisely so that a regression here is caught by the live test rather than
by a user.

## RFC index

| RFC | What it gives us |
| --- | --- |
| 768 | UDP, and the optional IPv4 checksum |
| 1071 | The internet checksum algorithm |
| 1320 | MD4, needed by MS-CHAPv2 |
| 1332 | IPCP |
| 1334 | PAP |
| 1661 | PPP: the automaton, LCP, Configure-Reject/Nak precedence, echoes, Protocol-Reject |
| 1877 | The IPCP DNS options (129 / 131) |
| 1994 | CHAP |
| 2407 | The IPsec DOI: identification types, attribute numbers, protocol ids |
| 2408 | ISAKMP: header, payload chaining, Delete semantics |
| 2409 | IKEv1: main and aggressive mode, quick mode, the key schedule, appendix B |
| 2661 | L2TPv2: headers, AVPs, the control channel, AVP hiding, tunnel authentication |
| 2759 | MS-CHAPv2, including the authenticator response |
| 3526 | The MODP-2048 prime |
| 3706 | Dead peer detection |
| 3947 | NAT traversal for IKEv1: NAT-D, NAT-OA, the port float |
| 3948 | UDP encapsulation of ESP: the non-ESP marker, the keepalive, transport-mode rules |
| 4303 | ESP: packet format, sequence numbers, anti-replay, processing order |
| 4868 | The SHA-2 HMAC attribute values and ICV truncation lengths |
