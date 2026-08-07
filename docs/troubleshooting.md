# Troubleshooting

How to get useful diagnostics off a device, what each failure kind actually means, and a table of
symptoms that have really been observed with their causes.

See also: [protocol.md](protocol.md) for why the stack does what it does,
[interoperability.md](interoperability.md) for peer-specific behaviour,
[android.md](android.md) for the two traps that produce the most confusing symptoms.

## Contents

* [Getting logs off a device](#getting-logs-off-a-device)
* [Reading the log](#reading-the-log)
* [What each TunnelErrorKind means](#what-each-tunnelerrorkind-means)
* [Observed symptoms and their causes](#observed-symptoms-and-their-causes)
* [Isolating a layer](#isolating-a-layer)
* [Capturing packets](#capturing-packets)

## Getting logs off a device

Turn on **Debug logging** in the profile's advanced section first. It raises the stack to `DEBUG`,
which adds per-packet lines, and it takes effect on the next connect.

### With a cable

```bash
adb logcat View:S "*:D" | grep L2TP
```

The `View:S` is not decoration. Compose's `View` tag produces a continuous stream of platform noise
that buries everything else; silencing it is what makes the log readable. Every line from this app is
tagged `L2TP.<component>`, so the `grep` catches the whole stack and nothing else.

To watch a single layer:

```bash
adb logcat -s L2TP.IKEv1 L2TP.Tunnel     # the handshake
adb logcat -s L2TP.l2tp L2TP.ppp         # the session
adb logcat -s L2TP.Service L2TP.Tun      # the Android side
```

| Tag | Component |
| --- | --- |
| `L2TP.Service` | `L2tpVpnService` — lifecycle, reconnect decisions, network changes |
| `L2TP.Tunnel` | `L2tpIpsecTunnel` — state transitions, SA installation, rekeys |
| `L2TP.IKEv1` | the negotiator — proposals, NAT-T, phase 1 and 2, informational exchanges |
| `L2TP.l2tp` | the L2TP control channel — SCCRQ/SCCRP/ICRQ/ICRP, Ns/Nr, ZLBs, HELLO |
| `L2TP.ppp` | LCP, authentication, IPCP |
| `L2TP.UdpSocket` | socket creation, `protect()`, the local address |
| `L2TP.Tun` | the `VpnService.Builder` result |
| `L2TP.Profiles` | profile storage, including the unencrypted-fallback warning |

### Without a cable

The app has an **in-app log screen** — the list icon in the top bar. It renders the same records from
an in-memory ring buffer (the most recent few hundred lines), auto-scrolls to the tail, colours
warnings and errors, and has copy / share / clear buttons. That exists precisely because debugging an
IKE negotiation against a consumer router usually happens on a phone with no cable attached.

The share button produces plain text, which is the right thing to attach to a bug report.

**Secrets are never logged.** The pre-shared key and the password are redacted even in the profile's
own `toString()`. Key material derived from them is not printed either.

## Reading the log

A healthy connection produces roughly this shape:

```
Service   Connecting to <host> (<profile>)
UdpSocket Opened protected UDP socket <local>:<port>
UdpSocket Local address for this tunnel: <local>
Tunnel    socket bound to <local>:<port>, server <ip>
IKEv1     phase 1 established: AES_CBC_256/SHA2_256/MODP_2048, NAT-T=RFC_3947, localNat=true, ...
Tunnel    floating IKE to UDP/4500
Tunnel    IKE phase 1 up: ...
IKEv1     phase 2 established: in=0x… out=0x… ESP_AES_CBC_256/HMAC_SHA2_256_128 encap=4 lifetime=…s
Tunnel    IPsec SA up: ...
Tunnel    negotiated tunnel MTU: …
l2tp      opening the L2TP control connection as 'android' (tunnel id …)
l2tp      LNS '<name>' accepted the control connection with tunnel id …
l2tp      L2TP session established: ...
ppp       starting LCP negotiation (mru=…, auth=…)
ppp       LCP opened (peer mru=…, auth=MSCHAP_V2)
ppp       authenticated with MSCHAP_V2
ppp       PPP is up: PppResult(localAddress=…, remoteAddress=…, dnsServers=…, mru=…)
Tunnel    lowering the tunnel MTU from … to …; the peer asked for MRU …      ← if clamped
Tun       TUN up: <addr>/32 mtu=… dns=… ipv6=blocked
```

**Where it stops is the diagnosis.** The state names in `TunnelState` map onto the blocks above, and
the connect watchdog reports the state that stalled rather than whatever I/O error the socket close
produced — that is the difference between "check your PSK" and "check your password".

## What each TunnelErrorKind means

| Kind | User-facing label | What it means | What to check |
| --- | --- | --- | --- |
| `DNS_FAILURE` | Server name could not be resolved | `InetAddress.getByName` failed | The server field; whether the device has working DNS at all; a literal IP will bypass it |
| `NETWORK_UNREACHABLE` | Network unreachable | **Never produced.** A dead network surfaces as `IKE_NO_RESPONSE` | — |
| `IKE_NO_RESPONSE` | No response from the server | The peer did not answer an exchange within the retransmission budget, or the connect watchdog fired during phase 1 or 2 | UDP 500 and 4500 reachable; a firewall in the way; **a wrong PSK looks exactly like this** — see below; a peer rate-limiting half-open SAs |
| `IKE_PROPOSAL_REJECTED` | The server rejected the phase 1 proposal | `NO_PROPOSAL_CHOSEN`, or the responder echoed a transform we did not offer | The phase 1 and phase 2 algorithm settings against the router's; the Key Length rule for AES |
| `IKE_AUTH_FAILED` | Wrong pre-shared key | `HASH_R` did not verify, or a Quick Mode hash did not verify | The pre-shared key; the identity type if the peer keys its PSK on one. **Not retried** — retrying is how accounts get locked out |
| `IPSEC_SA_FAILED` | IPsec SA could not be established | The peer did not negotiate NAT traversal at all; or it chose plain ESP instead of UDP-encapsulated; or a rekey failed repeatedly | Whether the peer supports NAT-T; whether `forceUdpEncapsulation` was turned off; the rekey log lines |
| `L2TP_FAILED` | L2TP negotiation failed | No SCCRP/ICRP, an unusable message, a control message unacknowledged after the retry budget, or the peer sent StopCCN/CDN during the handshake | Whether the router still holds a stale session (see the teardown trap); whether it requires tunnel authentication, which cannot currently be configured |
| `PPP_AUTH_FAILED` | Wrong user name or password | PAP Nak, CHAP Failure, or an MS-CHAPv2 authenticator-response mismatch | The credentials. An authenticator mismatch specifically means the *server* does not know the password, which points at a proxy or a misconfigured RADIUS. **Not retried** |
| `PPP_FAILED` | PPP negotiation failed | LCP or IPCP did not converge, the peer stopped answering echoes, loopback was detected, IPCP finished without an address, or the peer rejected IPCP entirely | Whether the allowed authentication list contains something the peer offers; whether the peer is pushing an option the client rejects |
| `TUN_UNAVAILABLE` | The VPN interface could not be created | `VpnService.Builder.establish()` returned null | VPN consent was revoked, or another VPN app took over |
| `PEER_DISCONNECTED` | The server closed the tunnel | StopCCN or CDN while connected, or the pump ended cleanly | The router's own logs; an idle timeout; a session limit |
| `INTERNAL` | Internal error | An invalid configuration, or an unexpected exception | The log line immediately before it |

## Observed symptoms and their causes

Real symptoms, from the lab and from the target router.

### Handshake

| Symptom | Cause | Fix |
| --- | --- | --- |
| **No reply at all to main mode message 1**, repeatedly, after several failed attempts — looks exactly like the server being down | strongSwan's DoS protection counts half-open IKE SAs per source IP and starts *silently dropping* message 1 past a small limit | Wait it out. The lab raises the limits; a real router has the defaults, so an abandoning client gets blackholed. Note that `0` is **not** "unlimited" in charon's configuration |
| A "new" attempt gets a stale answer, or nothing, when payloads changed | A repeated initiator cookie is treated by charon as a *retransmission* of message 1 while the old half-open SA lives | The client already uses a fresh random cookie per attempt; if you write a probe tool, do the same |
| `NO_PROPOSAL_CHOSEN` with a proposal that looks correct | **AES without a Key Length attribute.** charon reads it as "AES-CBC of unspecified size" and rejects | The client sends it automatically; if you change the algorithm vocabulary, keep `needsKeyLengthAttribute` right — and never send it for 3DES |
| `NO_PROPOSAL_CHOSEN` | A genuine algorithm mismatch | Match the router's `ike=` / `esp=` exactly. Only one transform is offered, so there is no fallback |
| **The handshake dies at main mode message 5/6** with no useful error, reported as `IKE_NO_RESPONSE` | **A wrong pre-shared key.** SKEYID differs, so the server cannot decrypt message 5 and answers with an informational encrypted under *its* keys, which the client cannot decrypt either. There is no clean error on the wire | Check the PSK first, and the `HASH_I`/SKEYID derivation second |
| Phase 1 fails with "the server did not negotiate NAT traversal" | The peer advertised no NAT-T vendor ID | The peer must support RFC 3947 or one of the drafts. An unrooted Android client cannot carry ESP any other way |
| Phase 2 fails with "the server selected plain ESP" | `forceUdpEncapsulation` was turned off, or the peer ignored the NAT-D hint | Turn it back on. See [protocol.md](protocol.md#why-encapsulation-is-forced) |

### L2TP

| Symptom | Cause | Fix |
| --- | --- | --- |
| The peer answers the SCCRQ with a bare **ZLB and nothing else** | A malformed control message. A ZLB is *also* what xl2tpd returns when it ignores a request, so "got a ZLB but no answer" means malformed, not "still thinking" | The Message Type AVP must be **first**; Framing Capabilities and Assigned Tunnel ID must be present |
| `Peer requested tunnel N twice, ignoring second one` in the server log | A reused Assigned Tunnel ID | The client randomises them per attempt; a probe tool must too |
| **The reconnect hangs at `L2TP_TUNNEL`** after a previous disconnect, with no error | The router never saw the teardown and is still holding the old session, so it ignores the new SCCRQ | This is the teardown-ordering trap — see [android.md](android.md#the-teardown-ordering-trap). If it has already happened, wait for the router's own timeout |

### PPP

| Symptom | Cause | Fix |
| --- | --- | --- |
| Authentication never starts | The peer offered a protocol not in `allowedPppAuth` and the Nak was not accepted | Widen `allowedPppAuth`, or check the log for which protocol the peer asked for |
| A stock pppd LNS offers **EAP** | `auth` alone makes pppd offer EAP first; `refuse-eap` does *not* remove it from the offer | The client Naks towards its preferred protocol, which resolves it. On a server you control, use explicit `require-chap` / `require-mschap-v2` / `require-pap` |
| "loopback detected" | The peer echoed our magic number | Something on the path is reflecting frames; genuinely a looped line |
| MS-CHAPv2 fails with an authenticator-response mismatch | The server does not actually know the password | Not a client bug — check the server's credential store |
| The tunnel comes up but IPCP assigned nothing | The peer's address pool is exhausted, or IPCP finished without a Nak | The server's pool |

### After the tunnel is up

| Symptom | Cause | Fix |
| --- | --- | --- |
| **Ping works but TLS hangs**, web pages start and stall, SSH connects then freezes | The classic MTU failure: only full-size packets are dropped | The client already clamps to the peer's MRU. If it still happens, the *path* MTU is below 1500 — lower the profile's MTU. See [protocol.md](protocol.md#mtu-the-header-budget-and-the-mru-clamp) |
| **The app connects and disconnects instantly**, in a loop | Watching the *default* network: once the VPN is up, the default network for our own uid **is** the VPN | The connectivity-callback trap — see [android.md](android.md#the-connectivity-callback-trap). Never use `registerDefaultNetworkCallback` without a `NOT_VPN` filter |
| The tunnel establishes but nothing passes at all | A socket that was not `protect()`ed, so the tunnel's own packets are routed into the tunnel | Every socket must be protected; a refusal is treated as fatal on purpose |
| **The tunnel dies at a fixed interval** with no error | An SA expired without being rekeyed: rekeying disabled, or a schedule computed from *our* proposed lifetime rather than the responder's answer | See [rekeying.md](rekeying.md#why-the-responders-lifetime-and-not-ours) |
| **The tunnel dies a few seconds after every rekey** | The peer's routine Delete of the *superseded* SA was mistaken for a teardown of the live one | See [rekeying.md](rekeying.md#telling-deletes-apart) |
| A brief gap in traffic right after a rekey | The superseded inbound SA was retired too early, or inbound was demultiplexed on "the current SA" instead of on the SPI | See [rekeying.md](rekeying.md#make-before-break); raise `saOverlapMs` for a slow peer |
| IPv6 traffic bypasses the VPN | `blockIpv6` turned off on a dual-stack network | Turn it back on |
| A red banner: the pre-shared key and password are stored unencrypted | The device keystore refused to provide an encrypted store | The app falls back to private preferences and says so. Nothing is migrated between the two stores, so the profile may also look empty |
| Debug lines missing after enabling the switch | The level is applied when a connection starts | Reconnect |

## Isolating a layer

The single most useful debugging technique from the lab, and it still applies:

**Develop and debug the L2TP and PPP layers without IPsec first.** With a strongSwan configuration
that uses `auto=add`, no trap policy is installed, so plaintext L2TP on UDP/1701 is *not* blocked. You
can bring up the entire L2TP + PPP stack against the server's port 1701 with no encryption at all,
watch every byte with `tcpdump`, and only then wrap it in ESP.

The reverse is not true: **once ESP is in play you cannot see the decapsulated UDP/1701 traffic with
tcpdump on either endpoint**, because the kernel re-injects the inner packet past the point where
tcpdump taps. That is why the plaintext step is worth the setup.

Phase 1 is in the clear on UDP/500, so IKE up to the port float is directly readable too. Only the
encrypted messages 5/6 and Quick Mode need the server's own decrypted trace.

Order that works: **plaintext L2TP + PPP → IKE phase 1 → Quick Mode → ESP.**

## Capturing packets

On the lab, from the container:

```bash
tcpdump -i any -n -s0 -w /out/cap.pcap 'udp port 500 or udp port 4500 or udp port 1701'
tcpdump -r /out/cap.pcap -n -vvv -X
```

strongSwan's own decrypted view is more useful than a capture for anything after the port float:

```bash
docker exec l2tp-server ipsec stroke loglevel ike 4
docker exec l2tp-server ipsec stroke loglevel enc 4   # hex-dumps every payload after decryption
docker exec l2tp-server tail -f /var/log/charon.log
docker exec l2tp-server ipsec statusall
docker exec l2tp-server ip xfrm state
```

`ip xfrm state` is the quickest check that encapsulation really happened: a healthy SA reads
`mode transport` and `encap type espinudp sport 4500 dport 4500`.

`testserver/verify.sh` runs a full known-good client through the same server, so if it passes and the
Kotlin client does not, the difference is in the client.
