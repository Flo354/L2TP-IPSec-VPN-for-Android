# L2TP/IPsec VPN for Android

A native Android L2TP/IPsec PSK client that runs **entirely in userland** — no root, no `strongSwan`,
no WireGuard proxy, no kernel `xfrm` state. Android removed its built-in L2TP/IPsec support in
Android 12, leaving IKEv2/IPsec as the only option; this app puts L2TP/IPsec back on the device for
routers that offer nothing else (the Orange Livebox Pro fibre being the case it was written for).

Default proposals match the target hardware:

| Phase | Proposal |
| --- | --- |
| IKE phase 1 | `aes256-sha256-modp2048` (AES-256-CBC, HMAC-SHA-256, DH group 14) |
| IPsec phase 2 | `aes256-sha256` — AES-256-CBC + HMAC-SHA-256-128, ESP **transport** mode, no PFS |

Both security associations are rekeyed before they expire, so the tunnel stays up indefinitely
instead of dropping and reconnecting once an hour.

## How it works without root

An unprivileged Android app cannot open a raw IP socket, so it can never send an IP-protocol-50 ESP
packet, and it cannot ask the kernel to install an IPsec SA. Everything is therefore done in
process, on top of a single ordinary UDP socket:

```
VpnService TUN  ──► IP packet
                      └─ PPP frame                         (RFC 1661 / 1332 / 1994 / 2759)
                          └─ L2TPv2 data message           (RFC 2661)
                              └─ UDP 1701 → 1701           checksum 0, see below
                                  └─ ESP transport mode    (RFC 4303, AES-256-CBC + HMAC-SHA-256-128)
                                      └─ UDP 4500          (RFC 3948 UDP encapsulation)
                                          └─ DatagramSocket, VpnService.protect()ed
```

Three consequences are worth spelling out, because they drive most of the design:

* **ESP is always UDP-encapsulated.** The client advertises its NAT-D source hash computed over
  port `0`, which no responder can ever match, so the peer concludes there is a NAT in the path and
  switches to UDP/4500. This is exactly what strongSwan's `forceencaps=yes` does, and here it is not
  an optimisation but a requirement.
* **There is no inner IP header.** ESP runs in *transport* mode, so the protected data is the
  UDP/1701 datagram itself and the outer IP header of the UDP/4500 packet is the only one on the
  wire. The ICV covers the ESP header, IV and ciphertext but not the IP header, which is why NAT
  rewriting is harmless.
* **The inner UDP checksum is zero.** IPv4 allows it, and it side-steps the RFC 3948 §3.1.2
  checksum fix-up that would otherwise be needed once a NAT rewrites the source address. Linux's
  own L2TP implementation does the same.

## Modules

```
core/   pure Kotlin/JVM — the entire protocol stack, no Android SDK, unit-testable
  util/    bounds-checked big-endian readers/writers, hex/byte helpers, logging seam
  crypto/  DH MODP groups, HMAC PRF and key expansion, CBC ciphers, algorithm vocabulary
  ike/     ISAKMP codec, IKEv1 main/aggressive mode, quick mode, NAT-T, DPD, delete
  esp/     ESP transport-mode encode/decode, anti-replay window, UDP-encapsulation framing
  net/     IPv4/UDP codecs and the internet checksum
  l2tp/    L2TPv2 AVPs, control channel with Ns/Nr and retransmission, data path
  ppp/     LCP, PAP / CHAP-MD5 / MS-CHAPv2 (with its own MD4), IPCP with RFC 1877 DNS
  tunnel/  VpnConfig, platform seams, MTU budgeting, and L2tpIpsecTunnel which drives it all
app/    Android — VpnService, platform adapters, encrypted profile storage, Compose UI
testserver/  a real strongSwan + xl2tpd + pppd lab server in Docker, used by the E2E tests
```

Keeping the stack in a plain JVM module is what makes it testable: the whole client can be driven
against a real server from a JUnit test, with ordinary `DatagramSocket`s and an in-memory TUN.

## Status

Verified against a real strongSwan + xl2tpd + pppd server configured exactly like the target
router (`testserver/`):

| Check | Result |
| --- | --- |
| `:core` unit tests | 282 pass |
| `:app` unit tests | 30 pass |
| End-to-end against the live server | 4 pass — tunnel established, ICMP echo round-trips through the full stack |
| Rekeying against the live server | 1 pass — both SAs replaced, traffic never stops |
| PPP authentication | PAP, CHAP-MD5 and MS-CHAPv2 all negotiate and authenticate |
| Wrong PSK / wrong password | fail fast with the correct, distinguishable error |
| `:app:lintDebug` | no errors |

The negotiated result on the wire, read out of the client's own trace:
`AES_CBC_256/SHA2_256/MODP_2048` for phase 1, `ESP_AES_CBC_256/HMAC_SHA2_256_128` in
UDP-encapsulated transport mode for phase 2, MTU 1400.

## Building

```bash
./gradlew :core:test          # protocol unit tests
./gradlew :app:assembleDebug  # APK at app/build/outputs/apk/debug/
```

Requires JDK 21 and the Android SDK (compileSdk 37). Gradle 9.7 and AGP 9.2 — AGP now supplies
Kotlin for Android modules itself, so the `kotlin-android` plugin is deliberately absent.

## End-to-end tests against a real server

`testserver/` builds a container running strongSwan and xl2tpd configured exactly like the target
router. The live tests are skipped unless a server is pointed at:

```bash
testserver/run.sh                     # start the lab, prints the server IP
./gradlew :core:test -Dl2tp.test.server=172.28.0.10 --tests '*LiveServerE2eTest'
testserver/stop.sh
```

They establish the tunnel for real and then push an ICMP echo request through the TUN and wait for
the reply to come back up the whole stack.

Rekeying needs a lab with short SA lifetimes, because there is no point waiting an hour for one:

```bash
IKE_LIFETIME=3m ESP_LIFETIME=2m testserver/run.sh
./gradlew :core:test -Dl2tp.test.server=172.28.0.10 -Dl2tp.test.rekey=true --tests '*LiveRekeyTest'
```

That test watches both SAs get replaced and then pings again *after* the superseded ones have been
deleted, which is the case that would break if the server treated the IPsec SAs as children of the
ISAKMP SA they were negotiated under.

## Rekeying

Every IPsec and ISAKMP SA carries a lifetime, and when it runs out the peer stops accepting the
keys. The client replaces both before that happens:

* **Schedules off the negotiated lifetime, not the proposed one.** strongSwan echoes back whatever
  the initiator asked for, but a router that shortens it would otherwise leave the client
  renegotiating after the SA was already gone.
* **Rekeys at 75–85% of the lifetime**, jittered. Peers commonly rekey at 90%, so going first keeps
  the client on the initiator side of the exchange, which is much the simpler side.
* **Make before break.** The new outbound SA takes over immediately, while the SA it replaced stays
  valid for inbound traffic for another 30 seconds — the peer keeps using it until it has installed
  the new one. Inbound packets are demultiplexed on the SPI in the ESP header, so both generations
  are decrypted with the right keys.
* **Answers a rekey the peer starts.** A router on its own schedule will send a Quick Mode of its
  own; the client responds to it, and replays its answer if message 1 is repeated rather than
  negotiating a second SA.
* **Distinguishes a delete of the superseded SA from a delete of the live one.** The first is
  routine housekeeping after a rekey; only the second is a reason to act.
* Also triggers on ESP sequence-number exhaustion, and renegotiates phase 1 immediately if the peer
  drops the ISAKMP SA.

All of this runs on a maintenance thread that owns the ISAKMP queue, so a rekey — which blocks on
the peer for a few round trips — never stalls the packet pump.

## Configuration on the device

Server address, PSK, username and password are the only required fields. The advanced section
exposes the phase 1 / phase 2 proposals, IKE exchange mode, local identity type, PPP authentication
protocols, MTU and IPv6 blocking. Secrets are kept in `EncryptedSharedPreferences`.

MTU defaults to 1400. The stack also computes the largest MTU that survives every header
(`core/.../tunnel/Mtu.kt`) and uses the smaller of the two, which avoids the classic "ping works but
TLS hangs" symptom.
