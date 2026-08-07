# Testing

The strategy is two-layered: **hermetic** tests that pin the protocol against RFC known-answer
vectors and fake peers, and **live** tests that drive the real client against a real strongSwan +
xl2tpd + pppd server in Docker.

The two catch different things. A hermetic test catches a transposed byte in a key schedule. A live
test catches the assumption that was never written down — that AES needs a Key Length attribute, that
a peer advertises an MRU below your header budget, that a router ignores the next SCCRQ if it never
saw your StopCCN.

See also: `testserver/README.md` for operating the lab, `testserver/CLIENT_NOTES.md` for the
byte-level findings the client was built from, [interoperability.md](interoperability.md) for the
durable conclusions.

## Contents

* [Running the tests](#running-the-tests)
* [The Docker lab](#the-docker-lab)
* [Live tests](#live-tests)
* [The rekey labs](#the-rekey-labs)
* [How the live tests self-skip](#how-the-live-tests-self-skip)
* [Hermetic tests](#hermetic-tests)
* [Two knob namespaces](#two-knob-namespaces)

## Running the tests

```bash
./gradlew :core:test          # the protocol stack; live tests self-skip
./gradlew :app:test           # the Android-free app classes
./gradlew test                # both
./gradlew :app:assembleDebug  # APK
```

Both modules use **JUnit 4**. `:core` always runs with `java.net.preferIPv4Stack=true`.

## The Docker lab

`testserver/` builds a Debian container running **strongSwan, xl2tpd and pppd**, configured to match
exactly what the target Livebox Pro offers: one IKE proposal, one ESP proposal, transport mode,
forced encapsulation.

```bash
testserver/run.sh     # build the image, create the network, start the server, attach this container
testserver/verify.sh  # prove the lab itself works, end to end
testserver/stop.sh    # remove the containers; the network is left in place
```

`run.sh` is idempotent — it tears down and recreates the container every time — and it also attaches
*the calling container* to the lab network, so JVM tests running there can reach the server directly.

### Coordinates the tests hard-code

| | |
| --- | --- |
| Server IP | `172.28.0.10` |
| Docker network | `l2tplab`, `172.28.0.0/16`, gateway `172.28.0.1` |
| Pre-shared key | `TestPreSharedKey2024!` |
| User / password | `vpnuser` / `VpnPass123` |
| LNS address / client pool | `10.10.10.1` / `10.10.10.100–199` |
| Pushed DNS | `10.10.10.1`, `8.8.8.8` |
| Ports | UDP 500 (IKE), 4500 (IKE + ESP-in-UDP), 1701 (L2TP) |

They are hard-coded on purpose so the tests can hard-code them too. **This is test infrastructure —
do not deploy it anywhere.**

### Prerequisites

The container runs privileged with `NET_ADMIN` and `SYS_MODULE`, mounts the host's `/lib/modules`
read-only, and creates `/dev/net/tun` and `/dev/ppp` itself if the runtime did not. The entrypoint
also disables reverse-path filtering — leaving `rp_filter` on is the classic reason L2TP/IPsec
silently fails inside a container.

If you run the tests from inside another container, the verification client is started as a
**sibling**, so the capture directory must exist at the same path on the docker host.

### Lab knobs (OS environment variables)

Read by `run.sh` and the entrypoint, which rewrite the configuration in place before starting:

| Variable | Default | Effect |
| --- | --- | --- |
| `PPP_AUTH` | `any` | Restrict the server's PPP offer to `chap`, `mschapv2` or `pap`. Unknown values warn and fall back. |
| `IKE_LIFETIME` | `8h` | `ikelifetime=` |
| `ESP_LIFETIME` | `1h` | `lifetime=` |
| `REKEY` | `no` | `rekey=` — set `yes` to make the **server** initiate rekeys |
| `MARGINTIME` | `9m` | how early the server rekeys, with `rekeyfuzz=0%` |
| `VERIFY_QUICK` | unset | `verify.sh` runs only the MS-CHAPv2 client |

### What verify.sh proves

It is worth running before blaming the client. It checks that the container is up on the right IP;
that strongSwan has the connection loaded with the expected `ike=`/`esp=`/`type=transport`/
`forceencaps=yes` and the right PSK; that all three UDP ports are bound; that a hand-rolled L2TP
probe gets an SCCRP and a hand-rolled IKE prober gets the expected accept/reject verdicts for nine
main-mode SA variants; and finally that a **real strongSwan+xl2tpd client container** completes the
whole path — ESP SA in transport mode with `espinudp` encapsulation, a `ppp0` address from the pool,
a successful ping to the LNS — for MS-CHAPv2, CHAP-MD5 and PAP, plus one run with the client's own
`forceencaps` off to prove the server's setting is doing the work.

## Live tests

Two classes in `core/src/test/.../core/e2e`, both opt-in.

### `LiveServerE2eTest`

| Test | What it proves |
| --- | --- |
| establishes the tunnel and carries an ICMP echo end to end | the whole stack works: the assigned address is from the pool, NAT-T is in use, the DNS list is de-duplicated, **the TUN MTU respects the peer's MRU**, and an ICMP echo injected into the fake TUN comes back with the right identifier, sequence, addresses and payload |
| a wrong pre-shared key fails phase 1 authentication | the failure is one of `IKE_AUTH_FAILED` / `IKE_NO_RESPONSE` / `IKE_PROPOSAL_REJECTED` — the set is wide because a bad PSK genuinely looks like "no response" (see [interoperability.md](interoperability.md#a-wrong-psk-does-not-produce-a-clean-error)) |
| a wrong PPP password fails after the IPsec SA is up | the kind is `PPP_AUTH_FAILED` **and** the recorded states include `L2TP_SESSION`, proving everything below PPP worked |
| authenticates over PAP, CHAP-MD5 and MS-CHAPv2 | each protocol pinned individually, asserting which one was actually used |

The MTU assertion is the one to keep an eye on: the lab deliberately advertises an MRU **below** the
client's own header budget, so this test is what catches a regression in the MRU clamp.

### Running them

```bash
testserver/run.sh
./gradlew :core:test -Dl2tp.test.server=172.28.0.10 --tests '*LiveServerE2eTest'
testserver/stop.sh
```

Passing `-Dl2tp.test.server` also turns on standard-stream logging, so the client's own trace is
visible.

Credentials can be overridden:

```bash
-Dl2tp.test.psk=…  -Dl2tp.test.user=…  -Dl2tp.test.password=…
```

with defaults matching the lab (`TestPreSharedKey2024!` / `vpnuser` / `VpnPass123`).

## The rekey labs

Rekeying needs short SA lifetimes — there is no point waiting an hour.

### Client-initiated

```bash
IKE_LIFETIME=3m ESP_LIFETIME=2m testserver/run.sh
./gradlew :core:test -Dl2tp.test.server=172.28.0.10 -Dl2tp.test.rekey=true --tests '*LiveRekeyTest'
```

The short lifetimes on the **client** side are set directly on `VpnConfig` inside the test, not
through a property, because strongSwan echoes back whatever the initiator proposes rather than
imposing its own. The lab's matching expiries are what make the test meaningful: if the rekey failed,
the server would tear the SAs down and the ping would fail.

The test connects, pings, waits for both rekey counters to increase while asserting the tunnel has not
died, pings again, then **waits past the overlap window and pings a third time**. That last ping is
the point of the whole test — it is the case that breaks if an implementation treats the ESP SAs as
children of the ISAKMP SA they were negotiated under, or mistakes the peer's routine delete of the
superseded SA for a teardown. It also asserts the TUN address never changed, i.e. that the tunnel did
not quietly reconnect underneath.

### Server-initiated (the responder path)

```bash
ESP_LIFETIME=2m IKE_LIFETIME=30m REKEY=yes MARGINTIME=60s testserver/run.sh
./gradlew :core:test -Dl2tp.test.server=172.28.0.10 -Dl2tp.test.rekey.responder=true \
    --tests '*LiveRekeyTest'
```

This one uses the **default** client lifetimes on purpose: our own rekey timer is three quarters of an
hour away, so anything that happens in the next two minutes can only have come from the peer. It
proves the client answers a Quick Mode it did not start and keeps carrying traffic afterwards.

## How the live tests self-skip

JUnit 4's `Assume.assumeTrue`. Every live test begins with an assumption on
`-Dl2tp.test.server`; the rekey tests stack a second assumption on their own flag. Without the
properties the tests are reported as **skipped**, not failed, so `./gradlew :core:test` is green on a
machine with no Docker.

A blank property counts as absent, so `-Dl2tp.test.server=` does not accidentally enable them.

| Property | Default | Enables |
| --- | --- | --- |
| `l2tp.test.server` | none — this is the master switch | all live tests |
| `l2tp.test.psk` | `TestPreSharedKey2024!` | |
| `l2tp.test.user` | `vpnuser` | |
| `l2tp.test.password` | `VpnPass123` | |
| `l2tp.test.rekey` | `false` | the client-initiated rekey test |
| `l2tp.test.rekey.responder` | `false` | the server-initiated rekey test |

Exactly these six properties are forwarded from the Gradle JVM into the test JVM; nothing is read
from OS environment variables on the JVM side.

### Test doubles the live tests use

* `TestUdpSocketFactory` — a plain `DatagramSocket`, using the same throwaway-connect trick as the
  Android factory to learn a real local address (`InetAddress.getLocalHost()` is wrong on a
  multi-homed host, and IKE identities and NAT-D hashes are computed over it).
* `FakeTun` / `FakeTunProvider` — an in-memory TUN with `inject()` and `awaitInbound()`, which is how
  the ICMP probe gets in and out.
* `IcmpEcho` — a self-contained IPv4/ICMP builder and parser that deliberately does **not** use the
  production `net` package, so the probe is independent of the code under test.

## Hermetic tests

Everything else. Two techniques.

### RFC known-answer vectors

Where a wrong implementation is indistinguishable from a right one until a real peer disagrees, the
expected values come from the standard rather than from the code:

| Area | Source of truth |
| --- | --- |
| AES-CBC | NIST SP 800-38A |
| HMAC PRF | RFC 4231 |
| MD4 | RFC 1320 appendix A.5, the complete suite |
| MS-CHAPv2 | RFC 2759 §9.2, checked step by step |
| Internet checksum | RFC 1071 §3 worked example |
| IKEv1 key schedule | pinned values from an independent implementation of RFC 2409 §5, including the appendix B expansion path |
| MODP primes | length and primality checked, because they were transcribed by hand |
| ESP | its own pinned encode/decode vector, plus the RFC 4303 §2.4 pad pattern and the sequence-space limit |
| L2TP AVP hiding | the RFC 2661 §4.3 transform re-derived inside the test |

### Fake peers

Where the interesting behaviour is a conversation, the test plays the other side:

| Double | Drives | Notes |
| --- | --- | --- |
| `FakeIkeResponder` + `FakeIkeTransport` | `IkeV1Negotiator` | Shares the message codec with production code but **derives every key independently from the RFC 2409 formulas**, so a transposition in the production key schedule shows up as two sides that disagree rather than as two sides that are wrong together. |
| `PppTestPeer` (`FakeLns`, `PppHarness`, `FakeClock`) | `PppSession` | Enough of RFC 1661/1334/1994/2759/1332 to negotiate against, with a switch to Configure-Reject the DNS options instead of naking them. |
| the L2TP tunnel test's own `FakeLns` | `L2tpTunnel` | Asserts the sequencing and the AVPs of everything the client sends. |

`FakeClock` — a virtual clock advanced by every wait — is what lets retransmission, backoff and
timeout paths be exercised without a test that sleeps.

### Coverage by package

| Package | What is covered |
| --- | --- |
| `crypto` | ciphers, PRF, DH agreement and padding, prime sanity |
| `esp` | the SA end to end, the anti-replay window's every edge, UDP-encapsulation classification |
| `ike` | ISAKMP codec round trips, SA attribute TV/TLV forms, main and aggressive mode, wrong PSK, NAT-D and NAT-OA, rekeying from both ends |
| `l2tp` | header and AVP wire format, AVP hiding and tunnel authentication, a full establishment against a fake LNS |
| `net` | checksum, IPv4 header, UDP datagram including the zero-checksum case |
| `ppp` | framing, control packets, MD4, MS-CHAPv2, a full negotiation plus hand-crafted corner cases |
| `tunnel` | the MTU budget, and the orchestrator's failure handling — a server that never answers, or a socket that dies underneath, must become a bounded, correctly attributed failure rather than a hang or a spin |
| `:app` | the persistence layer (profile list, credential vault, schema-1 migration), the form reducer and validator, the secret-field commit rules, profile → `VpnConfig` conversion, start-action dispatch, the log ring buffer, the reconnect backoff |

The orchestrator's *happy* path is not hermetic on purpose — it needs a real server, and that is what
`LiveServerE2eTest` is for.

### The `:app` persistence tests

Everything in `data/` is exercised against `FakePreferences`, an in-memory `SharedPreferences` that
can be made to throw `SecurityException` the way the encrypted one does — per key, or wholesale, and
switchable mid-test so a store can be made to come back to life. `StoreFixture` wires the real
`PreferenceProfileStore` and `PreferenceSecretVault` over it with `Dispatchers.Unconfined` standing
in for `Dispatchers.IO`, so the suspending work runs to completion on the calling thread and the
tests need no scheduler: the ordering guarantees being asserted are the production ones.

The properties worth knowing are pinned there rather than in prose: that a delete wipes the profile's
credentials, that editing a profile never destroys a secret the user did not touch, that the
schema-1 migration makes the credentials durable **before** it drops the old plaintext keys, and that
a store which refuses a write leaves the app working for the session rather than throwing.

**What this cannot cover: `AndroidKeyStore` does not exist on a plain JVM**, so nothing here
exercises the real `EncryptedSharedPreferences`. There is no `androidTest` source set. See
[security.md](security.md#what-is-not-claimed).

## Two knob namespaces

Easy to confuse, so:

* **Lab-side knobs are OS environment variables** consumed by `run.sh` and the container entrypoint:
  `PPP_AUTH`, `IKE_LIFETIME`, `ESP_LIFETIME`, `REKEY`, `MARGINTIME`, `VERIFY_QUICK`. They change what
  the *server* does.
* **Test-side knobs are JVM system properties** (`-Dl2tp.test.*`) forwarded by `core/build.gradle.kts`.
  They change what the *client* does and which tests run.

A rekey test needs both, which is why the commands above set an environment variable on `run.sh` and
a system property on `gradlew`.
