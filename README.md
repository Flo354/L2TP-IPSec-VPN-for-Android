# L2TP/IPsec VPN for Android

A native Android L2TP/IPsec PSK client that runs **entirely in userland** — no root, no strongSwan,
no kernel `xfrm` state, no WireGuard proxy. Android removed its built-in L2TP/IPsec support in
Android 12, leaving IKEv2/IPsec as the only option; this app puts L2TP/IPsec back on the device for
routers that offer nothing else. It was written for an **Orange Livebox Pro** fibre router, which
offers L2TP/IPsec PSK and nothing else.

Every layer of the stack — ISAKMP/IKEv1, ESP, L2TPv2, PPP — is implemented in Kotlin inside the app
process, on top of one ordinary UDP socket.

> ### Provenance: this was written entirely by an AI
>
> **100 % of this repository was written by Claude** (Anthropic's model) — the protocol stack, the
> Android app, every test, the Docker lab and all of this documentation. It was produced in one
> extended session from a prompt describing the problem, written against the RFCs rather than ported
> from an existing L2TP/IPsec implementation. No line was hand-written afterwards.
>
> The human set the goal and the constraints, supplied the hardware, ran the app on a real Galaxy
> S25+ against a real Orange Livebox Pro, pasted the logcat back, and made the product calls — such
> as removing the plaintext credential fallback. That loop is what found three defects no test had
> caught: a reconnect loop that tore the tunnel down 27 ms after it came up, a teardown that never
> reached the router, and an MTU that ignored the peer's advertised MRU.
>
> **What that means if you are considering using it.** It has been verified by execution, not merely
> generated: it establishes a real tunnel against a real router and against a strongSwan lab, and the
> tests pin the RFC vectors. But **no human expert has reviewed the IKEv1 or ESP code**. Read it
> before you trust it, and judge it on the code and the tests rather than on where it came from.

## The layering

```
UDP/4500 datagram                    the only socket, VpnService.protect()ed
  └─ ESP transport mode              RFC 4303 + RFC 3948 UDP encapsulation
      └─ UDP 1701 → 1701             transport mode: there is NO inner IP header
          └─ L2TPv2 data message     RFC 2661
              └─ PPP frame           RFC 1661 / 1332 / 1994 / 2759
                  └─ the user's IP packet, from/to the VpnService TUN
```

Three consequences drive most of the design, and each is explained in
[docs/protocol.md](docs/protocol.md):

* **ESP is always UDP-encapsulated.** An unprivileged Android app cannot open a raw IP socket, so it
  can never send IP-protocol-50 ESP. The client forces encapsulation by computing its source NAT-D
  hash over port `0` — exactly strongSwan's `forceencaps=yes`. This is a requirement, not an
  optimisation.
* **There is no inner IP header.** ESP runs in *transport* mode, so the protected data is the
  UDP/1701 datagram itself. The ICV covers the ESP header, IV and ciphertext but not the IP header,
  which is why NAT rewriting on the path is harmless.
* **The inner UDP checksum is zero.** IPv4 permits it, and it side-steps the RFC 3948 §3.1.2
  checksum fix-up. Linux's own L2TP implementation does the same.

## Modules

```
core/         pure Kotlin/JVM — the whole protocol stack, no Android SDK, unit-testable
  util/         bounds-checked big-endian readers/writers, hex helpers, logging seam
  crypto/       DH MODP groups, HMAC PRF and key expansion, CBC ciphers, algorithm vocabulary
  ike/          ISAKMP codec, IKEv1 main/aggressive mode, quick mode, NAT-T, DPD, Delete
  esp/          ESP transport-mode encode/decode, anti-replay window, UDP-encapsulation framing
  net/          IPv4/UDP codecs and the internet checksum
  l2tp/         L2TPv2 AVPs, control channel with Ns/Nr and retransmission, data path
  ppp/          LCP, PAP / CHAP-MD5 / MS-CHAPv2 (with its own MD4), IPCP with RFC 1877 DNS
  tunnel/       VpnConfig, platform seams, MTU budgeting, and L2tpIpsecTunnel which drives it all
app/          Android — VpnService, platform adapters, encrypted profile + credential storage, Compose UI
testserver/   a real strongSwan + xl2tpd + pppd lab in Docker, driven by the live tests
```

Keeping the stack in a plain JVM module is what makes it testable: the entire client can be driven
against a real server from a JUnit test, with ordinary `DatagramSocket`s and an in-memory TUN.

## Defaults

| Phase | Proposal |
| --- | --- |
| IKE phase 1 | `aes256-sha256-modp2048` — AES-256-CBC, HMAC-SHA-256, DH group 14, PSK, main mode |
| IPsec phase 2 | `aes256-sha256` — AES-256-CBC + HMAC-SHA-256-128, ESP **transport** mode, no PFS |
| PPP auth | MS-CHAPv2, then CHAP-MD5, then PAP |

These match the Livebox Pro exactly; see [docs/interoperability.md](docs/interoperability.md).

## Building and running

```bash
./gradlew :core:test          # protocol unit tests (the live ones self-skip)
./gradlew :app:test           # Android-free app-layer tests
./gradlew :app:assembleDebug  # APK at app/build/outputs/apk/debug/
```

Requires the Android SDK (`compileSdk 37`, `minSdk 26`) and a JDK the Gradle wrapper accepts. The
Kotlin Android plugin is deliberately absent from `:app` — AGP supplies Kotlin for Android modules
itself.

On the device: create a profile — server address, pre-shared key, user name and password — and press
Connect. Several profiles can be saved, with one marked active; they can be edited, duplicated and
deleted. The advanced section exposes the phase 1 / phase 2 proposals, exchange mode, local identity,
PPP authentication list, MTU, DNS override and the IPv6 blackhole. Full field reference in
[docs/configuration.md](docs/configuration.md).

**A saved pre-shared key or password can never be displayed again.** The credentials live in a store
the UI is handed *without a getter*, so a screen has no way to read one back; a saved field offers
Replace and Clear rather than a masked value. What that protects against, and what it does not, is in
[docs/security.md](docs/security.md).

## Status

Verified against the Docker lab in `testserver/` (strongSwan + xl2tpd + pppd configured like the
target router) and against the real Livebox Pro:

| Check | Result |
| --- | --- |
| Tunnel establishment | IKE phase 1 → phase 2 → L2TP → PPP → TUN, end to end |
| Data path | ICMP echo round-trips through the whole stack |
| PPP authentication | PAP, CHAP-MD5 and MS-CHAPv2 all negotiate and authenticate |
| Rekeying | both SAs replaced, by us and by the server, without interrupting traffic |
| Wrong PSK / wrong password | fail fast with distinguishable, actionable errors |
| Test suite | `:core` and `:app` both green; the handful of live tests self-skip without the lab |
| Static analysis | `:app:lintDebug` reports no issues; both modules compile without warnings |
| Credential storage | **not verified on a device** — read-only review plus plain-JVM tests against a fake store, because `AndroidKeyStore` does not exist off-device |

Known limitations are listed honestly in each document, and collected in
[docs/architecture.md](docs/architecture.md#known-limitations). The credential handling has its own
honest account in [docs/security.md](docs/security.md#what-is-not-claimed).

## Documentation

| Document | What it covers |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | Module layout, the layering, the threading model, the platform seams |
| [docs/protocol.md](docs/protocol.md) | What is implemented at each layer, with RFCs — and the non-obvious decisions |
| [docs/rekeying.md](docs/rekeying.md) | SA lifetimes, the jittered deadline, make-before-break, what is not covered |
| [docs/android.md](docs/android.md) | `VpnService` lifecycle, `protect()`, foreground service, profile storage, reconnect, the traps |
| [docs/configuration.md](docs/configuration.md) | Every field of `VpnConfig` and `VpnProfile`, the two secrets, the validation rules |
| [docs/security.md](docs/security.md) | What protects the credentials, the threat model, the never-reveal guarantee, and what is not claimed |
| [docs/testing.md](docs/testing.md) | Hermetic tests, the Docker lab, how to run each suite |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Getting logs off a device, every `TunnelErrorKind`, observed symptoms |
| [docs/interoperability.md](docs/interoperability.md) | The Livebox Pro's settings, and what the lab taught us about strongSwan and xl2tpd |

[docs/README.md](docs/README.md) is the index, with suggested reading orders.

`testserver/CLIENT_NOTES.md` holds the raw byte-level findings from the lab and is worth reading
before touching anything on the wire.
