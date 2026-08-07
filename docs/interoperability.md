# Interoperability

What real peers actually do. The Orange Livebox Pro is the router this client was written for; the
Docker lab in `testserver/` reproduces its behaviour with strongSwan, xl2tpd and pppd so the
findings can be reproduced without the hardware.

Everything here was **observed**, not read out of an RFC. The primary source is
`testserver/CLIENT_NOTES.md`, which records the literal bytes, the probe results and the server log
lines behind each conclusion; this document keeps the durable conclusions and the reasoning. When the
two disagree, believe `CLIENT_NOTES.md` — it is the one with the hex dumps.

See also: [protocol.md](protocol.md) for what the client does about all this,
[troubleshooting.md](troubleshooting.md) for the symptom-shaped view.

## Contents

* [The Livebox Pro and how it maps onto the defaults](#the-livebox-pro-and-how-it-maps-onto-the-defaults)
* [strongSwan / charon](#strongswan--charon)
* [xl2tpd](#xl2tpd)
* [pppd](#pppd)
* [MTU and MRU](#mtu-and-mru)
* [What has not been verified](#what-has-not-been-verified)

## The Livebox Pro and how it maps onto the defaults

The router offers L2TP/IPsec PSK and nothing else — no IKEv2, no WireGuard, no OpenVPN — which is the
whole reason this project exists. Its settings, and the client field that has to match:

| Router setting | Value | Client default | Notes |
| --- | --- | --- | --- |
| Key exchange | IKEv1, **main mode**, pre-shared key | `exchangeMode = MAIN` | Aggressive mode is available in the client but is not needed here |
| Phase 1 proposal | AES-256-CBC / SHA2-256 / MODP-2048 | `AES_CBC_256` / `SHA2_256` / `MODP_2048` | strongSwan notation `ike=aes256-sha256-modp2048!` |
| Phase 2 proposal | ESP AES-256-CBC / HMAC-SHA2-256-128, **no PFS** | `ESP_AES_CBC_256` / `HMAC_SHA2_256_128` / `pfsGroup = null` | `esp=aes256-sha256!` |
| IPsec mode | **transport** | transport, always | `type=transport`, selectors `17/1701` |
| NAT traversal | forced | `forceUdpEncapsulation = true` | `forceencaps=yes` on the server side does the same thing from its end |
| L2TP | RFC 2661 on UDP/1701 inside the SA | as implemented | |
| PPP authentication | CHAP-MD5 offered; MS-CHAPv2 and PAP available | `[MSCHAP_V2, CHAP_MD5, PAP]` | The client Naks towards MS-CHAPv2 |
| Pushed DNS | two resolvers via the Microsoft IPCP options | `dnsOverride` empty → use what IPCP gave | **The Livebox pushes the same resolver twice**, which is why the client de-duplicates the list before handing it to the TUN |
| IPV6CP | **the Livebox does send it** | not implemented | The client answers with an LCP Protocol-Reject, exactly as pppd does. The lab has IPv6CP disabled by default, so this path is only exercised by enabling it |
| Peer MRU | below 1500 | `mtu = 1400` ceiling, then clamped to the peer's MRU | See [MTU and MRU](#mtu-and-mru) |

The one-proposal-per-phase design of the client is a direct consequence: the router accepts exactly
one transform set, so offering a menu buys nothing and only makes the failure mode less obvious.

## strongSwan / charon

The lab runs strongSwan configured to accept exactly one proposal in each phase, which is what makes
a from-scratch client verifiable — anything the server accepts is definitely right.

### Phase 1

* **Attribute encoding is flexible.** A prober sent nine variants of the SA payload. Lifetime
  attributes are entirely **optional**, may be TV or TLV, and **attribute order does not matter**.
  Several transforms may be offered and charon picks the first that matches, echoing exactly that one
  transform back — read the transform number in the reply to know which won.
* **The Key Length attribute is mandatory for AES** and forbidden for 3DES. Without it charon reads
  `AES_CBC` with no key size and answers `NO_PROPOSAL_CHOSEN`. This is the single most common cause
  of a rejection that looks inexplicable.
* **A rejection is an unencrypted informational** carrying `NO_PROPOSAL_CHOSEN`, from UDP/500, with
  the same cookies. It is easy to miss if you are only looking for a main-mode message 2.
* charon refuses aggressive mode with PSK by default, so main mode is the only option on a stock
  configuration.

### <a id="a-wrong-psk-does-not-produce-a-clean-error"></a>A wrong PSK does not produce a clean error

This is worth its own heading because it costs an hour every time.

`SKEYID` differs, so the server cannot decrypt main mode message 5. It logs something like
`invalid ID_V1 payload length, decryption failed?` and answers with an informational carrying
`PAYLOAD_MALFORMED` — **encrypted under the server's keys**, which the client also cannot decrypt.
From the client the symptom is simply "no response": retransmissions until the budget runs out.

Consequences for the client:

* The failure surfaces as `IKE_NO_RESPONSE` rather than `IKE_AUTH_FAILED`, which is why the live test
  for a wrong PSK accepts a set of kinds rather than one.
* If the handshake dies exactly at message 5/6, suspect the PSK or your `HASH_I`/`SKEYID` derivation,
  not the network.

### Rate limiting

charon's DoS protection counts **half-open IKE SAs per source IP** and, past a small default limit,
starts **silently dropping main mode message 1** — no reply at all, indistinguishable from the server
being down. The lab raises the limits so development is possible; a real Livebox has the defaults, so
a client that abandons handshakes will get blackholed.

Two practical consequences:

* **Use a fresh random initiator cookie for every connection attempt.** charon keys half-open SAs on
  the initiator cookie and treats a repeat as a *retransmission* of message 1; while the old half-open
  SA lives, a "new" attempt gets the cached response, or nothing at all if the payloads differ. The
  client does this; a hand-written probe tool must too.
* `0` is **not** "unlimited" in charon's limit settings. A large number is what works.

### NAT traversal

* The vendor ID for RFC 3947 is the MD5 of the literal string `"RFC 3947"`, and the draft ones are
  MD5s of their draft names — including a variant of draft-02 **with a trailing newline**, which the
  draft text accidentally contained and which several stacks hash that way. The client offers all of
  them and accepts either draft-02 form.
* **You must send a NAT-T vendor ID.** Without one the server will not offer NAT-T, will not float to
  4500, and will expect raw ESP — which an unrooted Android app cannot send.
* NAT-D payload type **20** with RFC 3947, and the hash is sized to the negotiated phase-1 hash: 32
  bytes with SHA-256, not 20. **The first NAT-D payload hashes the destination**, the rest the source.
* To claim you are behind a NAT, put a value the peer cannot reproduce in your own source NAT-D
  payload — hashing over port 0 is what this client does. The server logs
  `faking NAT situation to enforce UDP encapsulation` when it forces it, and
  `remote host is behind NAT` when the peer did.
* Once either side detects a NAT, **both** switch source *and* destination port to 4500 starting with
  main mode message 5. On 4500 every IKE message is prefixed with four zero bytes; ESP packets are
  not, because their first four bytes are a non-zero SPI.
* At MODP-2048 the messages stay small enough that **IKE fragmentation is never needed**, even though
  the server advertises support for it.

### Phase 2

* Encapsulation Mode must be **4 = UDP-Encapsulated-Transport** — not 2 (plain transport), and not
  the draft values 61443/61444, which belong to the draft dialects.
* Key Length is mandatory here too (attribute 6), same trap as phase 1.
* The Authentication Algorithm value for HMAC-SHA2-256 truncates the ICV to **128 bits**, i.e. 16
  bytes on the wire.
* **Omitting the Group Description attribute is how you say "no PFS".** Sending it requests PFS,
  which a server not configured for it will reject.
* The server **adds lifetime attributes to its answer** even when the request carried none, so the
  answer's SA payload is longer than the request's. Read the lifetime from the answer.
* The traffic selectors must be `ID_IPV4_ADDR`, protocol 17, with the **responder's** port set to
  1701. The initiator's port may be 0 (any) or the real one; both match. The resulting kernel policy
  only passes UDP to and from 1701, so anything else sent inside the SA is dropped.
* **NAT-OA payloads (type 21) are sent, initiator first then responder**, and echoed back. RFC 3947
  §5.2 requires them for UDP-encapsulated transport mode so the receiver can reconstruct the original
  addresses for checksum fix-ups. Behind a real NAT, put your **pre-NAT (internal)** address there.

### The data path and liveness

* A healthy SA reads, on both ends, `mode transport`, `auth-trunc hmac(sha256) … 128`,
  `enc cbc(aes)`, `encap type espinudp sport 4500 dport 4500`. That is the quickest check that
  encapsulation actually happened.
* **DPD is enabled** on a typical configuration: after a period of silence the server sends an
  informational `R-U-THERE` and expects `R-U-THERE-ACK`. In practice the L2TP HELLO and the LCP echoes
  keep the link busy so it rarely fires, but an idle client must answer it — this client does.
* charon sends NAT keepalives (a single `0xFF` byte on 4500) to peers it believes are natted, roughly
  every 20 s. Inbound ones are ignored; the client sends its own on the same period.

## xl2tpd

Measured requirements, from a prober that sent deliberately varied SCCRQs:

| SCCRQ contents | Result |
| --- | --- |
| Full AVP set | SCCRP |
| RFC 2661 mandatory AVPs only | SCCRP |
| No Host Name AVP | SCCRP — tolerated |
| No Protocol Version AVP | SCCRP — tolerated |
| **No Framing Capabilities AVP** | ZLB only — the request is ignored |
| **No Assigned Tunnel ID AVP** | ZLB only — ignored |
| **Message Type AVP not first** | ZLB only — ignored |

So the hard requirements are: **Message Type must be the first AVP**, and Framing Capabilities and
Assigned Tunnel ID must be present. The client sends the full set regardless.

Other behaviours worth knowing:

* **A bare ZLB is ambiguous.** It is both the normal acknowledgement and what you get back when the
  server ignores a malformed request. "Got a ZLB but no answer" therefore means *malformed*, not
  "still thinking".
* **Address the peer with the ids it assigned** — the Assigned Tunnel ID from its SCCRP and the
  Assigned Session ID from its ICRP. Its packets to you carry the ids you assigned.
* The server advertises a **Receive Window Size of 4**, so never have more than four unacknowledged
  control messages in flight towards it.
* Reusing an Assigned Tunnel ID gets `Peer requested tunnel N twice, ignoring second one`. Use fresh
  random ids per attempt.
* A missing **Tx Connect Speed** in the ICCN produces a warning but does not stop the session; Call
  Serial Number in the ICRQ and Framing Type in the ICCN are read and logged. The client sends all
  three.
* xl2tpd sends **HELLO** as a keepalive on an idle tunnel and expects a ZLB acknowledgement.
* AVP encoding puts the mandatory bit in the top bit of the first 16-bit word and the total length in
  the low ten bits; vendor 0 is IETF. The server sets the mandatory bit on everything except Firmware
  Revision and Vendor Name.

### The plaintext development path

`auto=add` on the strongSwan connection installs **no trap policy**, so **plaintext L2TP on UDP/1701
is not blocked**. The entire L2TP + PPP stack can be brought up with no IPsec at all and watched byte
by byte with tcpdump. This is the single most useful thing the lab offers.

The converse does not hold: **once ESP is in play, tcpdump on either endpoint cannot see the
decapsulated UDP/1701 traffic**, because the kernel re-injects the inner packet past the point where
tcpdump taps.

## pppd

* **PPP frames in L2TP have no HDLC framing**: no `7E` flags, no byte stuffing, no FCS. Just `FF 03`
  (address/control, always present because ACFC is never negotiated) followed by the **full two-byte
  protocol field** (PFC never negotiated either). Do not implement async-HDLC escaping.
* **The server offers CHAP with algorithm MD5 first.** That is pppd's internal digest preference
  order, not a policy choice. To get MS-CHAPv2, answer the LCP Configure-Request with a
  **Configure-Nak** naming `<auth chap 0x81>`; the server re-requests with MS-CHAPv2 and you Ack. For
  PAP, Nak with `<auth pap>`. For CHAP-MD5, just Ack the first request. One Nak is all it takes.
* **`auth` on its own makes pppd offer EAP first**, and `refuse-eap` does *not* change that — it only
  governs the direction in which *we* authenticate. Removing EAP from the offer requires explicit
  `require-chap` / `require-mschap-v2` / `require-pap`. This matters if you point the client at a
  stock pppd LNS, which will offer EAP.
* Options the server sends are only MRU, ACCM, Magic-Number and the authentication option. It sends
  neither PFC nor ACFC, and rejects CCP and VJ, so **there is no compression state to implement**.
* **LCP Echo-Requests every 30 s, link dropped after 5 unanswered.** The reply must echo the
  four-byte magic number.
* The server is patient with Configure-Request retries — considerably more than pppd's default — so a
  slow client is tolerated.
* **The CHAP-MD5 challenge length is random**, observed between 16 and 24 bytes. Do not assume 16.
* MS-CHAPv2's 49-byte response is exactly the RFC 2759 layout, and the Success message carries
  `S=<40 uppercase hex>` — the authenticator response. Verify it; this client does. MPPE is not
  negotiated, so the master keys are never needed.
* PAP is **client-initiated**: after LCP is up, send the Authenticate-Request without waiting for
  anything.
* IPCP: ask for address `0.0.0.0` and both DNS options as `0.0.0.0`, and take the real values from the
  Configure-Nak. DNS uses the Microsoft options 129 (primary) and 131 (secondary). The peer's address
  is a point-to-point peer, not a gateway on a subnet, hence the /32 on the TUN.

## MTU and MRU

The lab's LNS deliberately advertises an **MRU below the client's own header budget**. That is not an
accident and it is not tuning: it reproduces what a real Livebox does, and it is the only way to test
the MRU clamp.

A client that ignores the peer's MRU fails in the worst possible way — small packets get through and
large ones do not, so ping works, DNS works, and TLS hangs. The client therefore uses

```
effectiveMtu = min(header budget from the algorithm sizes, the peer's PPP MRU)
```

and logs the clamp when it happens. The live end-to-end test asserts the resulting TUN MTU, which is
what turns a regression here into a red test rather than a support ticket.

Note that `testserver/CLIENT_NOTES.md` and `testserver/README.md` were written when the lab
advertised a larger MRU than it does now; the shipped pppd options file and the live test are the
current truth if the three ever disagree.

## What has not been verified

Stated so nobody assumes coverage that does not exist:

* **The draft-02 / draft-03 NAT-T dialects on the wire.** The payload numbers and encapsulation-mode
  values are implemented from the drafts, but the lab server always negotiates RFC 3947, so the draft
  path has only ever been exercised by unit tests.
* **Omitting the NAT-OA payloads.** They are always sent; nobody has tested what the server does
  without them.
* **DPD actually firing.** The configuration is there but sessions in the lab are never idle long
  enough. The client's ability to answer `R-U-THERE` is covered by a hermetic test only.
* **IKE fragmentation.** Never needed at MODP-2048 message sizes.
* **A real NAT.** Client and server sit on the same Docker bridge, so NAT traversal is *forced* and
  exercised, but address translation itself is not. The NAT-OA path is exercised, not stressed.
* **Tunnel authentication (L2TP Challenge/Response).** The protocol side is implemented and unit
  tested; no lab server has ever asked for it, and there is no way to configure a tunnel secret from
  the app.
* **IPv6 inside the tunnel.** Not implemented at all; IPV6CP gets a Protocol-Reject.
