# Configuration reference

Every knob, what it means, what it defaults to, and when you would change it.

There are two records. `VpnConfig` (in `:core`) is what the protocol stack reads. `VpnProfile` (in
`:app`) is what the user edits and what is persisted; it exposes a subset of `VpnConfig` and converts
to it. Everything `VpnProfile` does not expose stays at its `VpnConfig` default.

See also: [protocol.md](protocol.md) for what these values do on the wire,
[android.md](android.md#profile-storage) for how the profile is stored.

## Contents

* [VpnProfile — what the user can set](#vpnprofile--what-the-user-can-set)
* [Validation rules](#validation-rules)
* [VpnConfig — what the stack reads](#vpnconfig--what-the-stack-reads)
* [Phase1Proposal and Phase2Proposal](#phase1proposal-and-phase2proposal)
* [Identity](#identity)
* [Algorithm vocabulary](#algorithm-vocabulary)
* [Fields VpnProfile does not expose](#fields-vpnprofile-does-not-expose)
* [Constants that are not configurable](#constants-that-are-not-configurable)

## VpnProfile — what the user can set

Deliberately free of Android types so it can be unit-tested on a plain JVM. Its `toString()` redacts
the pre-shared key and the password.

### Connection

| Field | Type | Default | Meaning / when to change |
| --- | --- | --- | --- |
| `name` | `String` | `"L2TP/IPsec"` | Display name, also the `VpnService.Builder` session label shown in system settings. Cosmetic. |
| `server` | `String` | `""` | Host name or literal IPv4 address of the concentrator. **Required.** Trimmed before use. |
| `presharedKey` | `String` | `""` | IKE pre-shared key. **Required.** Stored encrypted, never logged. Passed through verbatim — leading/trailing spaces are *not* stripped, because they may be part of the key. |
| `username` | `String` | `""` | PPP user name. Trimmed. |
| `password` | `String` | `""` | PPP password. Passed through verbatim. Stored encrypted, never logged. |

### Phase 1 (ISAKMP SA)

| Field | Type | Default | When to change |
| --- | --- | --- | --- |
| `exchangeMode` | `IkeExchangeMode` | `MAIN` | Set `AGGRESSIVE` only for a peer that refuses main mode. Aggressive mode leaks the initiator identity in the clear and is weaker against offline PSK cracking. |
| `phase1Encryption` | `IkeEncryption` | `AES_CBC_256` | Match the router's `ike=` proposal. |
| `phase1Hash` | `IkeHash` | `SHA2_256` | Same. This is also the PRF — IKEv1 has no separate PRF negotiation. |
| `phase1DhGroup` | `DhGroup` | `MODP_2048` (group 14) | Same. Group 2 (1024-bit) only for old hardware. |

### Phase 2 (IPsec SA)

| Field | Type | Default | When to change |
| --- | --- | --- | --- |
| `phase2Encryption` | `EspEncryption` | `ESP_AES_CBC_256` | Match the router's `esp=` proposal. |
| `phase2Integrity` | `EspIntegrity` | `HMAC_SHA2_256_128` | Same. |
| `phase2PfsGroup` | `DhGroup?` | `null` | `null` means **no PFS**, which is what most consumer routers expect and what `esp=aes256-sha256!` (no `-modpNNNN` suffix) means on strongSwan. Set a group only if the peer has PFS enabled; a mismatch is rejected. |

### PPP and the interface

| Field | Type | Default | Meaning / when to change |
| --- | --- | --- | --- |
| `allowedPppAuth` | `List<PppAuthProtocol>` | `[MSCHAP_V2, CHAP_MD5, PAP]` | Protocols offered, **in order of preference**. The first entry is what the client Naks towards when the peer offers something else. Narrow it to one entry to prove which protocol a peer is really using. Must not be empty. |
| `mtu` | `Int` | `1400` | A **ceiling**. The stack computes the largest MTU that survives every header and then clamps to the peer's PPP MRU; this value is a third clamp on top. Lower it if you suspect a smaller path MTU — see [protocol.md](protocol.md#mtu-the-header-budget-and-the-mru-clamp). Must be 576–1500. |
| `dnsServers` | `String` | `""` | Free-text override, split on commas, semicolons or whitespace. Empty means "use whatever IPCP negotiated". Set it when the pushed resolvers are unreachable through the tunnel. |
| `blockIpv6` | `Boolean` | `true` | Adds a `::/0` route with no IPv6 address, so IPv6 is blackholed. **Leave it on.** Off means every dual-stack connection quietly leaks around an IPv4-only VPN. |

### Advanced / diagnostic

| Field | Type | Default | Meaning / when to change |
| --- | --- | --- | --- |
| `identityType` | `IkeIdentityType` | `AUTO_IPV4` | ISAKMP identity type. `AUTO_IPV4` sends the socket's real local address, which is what road-warrior clients do. Change it only for a peer that keys its PSK on a named identity. |
| `identityValue` | `String` | `""` | The identity payload contents. Ignored when the type is `AUTO_IPV4`; **required** otherwise. Trimmed. |
| `forceUdpEncapsulation` | `Boolean` | `true` | Advertise a bogus source NAT-D hash so the peer always encapsulates ESP in UDP/4500. **Do not turn this off** unless you are deliberately testing a peer's behaviour: an unrooted Android app cannot send or receive plain ESP, so the tunnel will negotiate and then carry nothing. See [protocol.md](protocol.md#why-encapsulation-is-forced). |
| `debugLogging` | `Boolean` | `false` | Raises the Android logger to `DEBUG`, which adds per-packet lines. Turn on when reproducing a handshake problem, off afterwards — it is noisy. |

### Derived properties

| Property | Definition |
| --- | --- |
| `dnsServerList` | `dnsServers` split on `[,;\s]+`, trimmed, empties dropped |
| `localIdentity` | `IkeIdentity(AUTO_IPV4, "")` when the type is `AUTO_IPV4`, otherwise `IkeIdentity(type, identityValue.trim())` |

### Constants

| Constant | Value |
| --- | --- |
| `DEFAULT_NAME` | `"L2TP/IPsec"` |
| `DEFAULT_MTU` | `1400` |
| `MIN_MTU` / `MAX_MTU` | `576` / `1500` |
| `DEFAULT_PPP_AUTH` | `[MSCHAP_V2, CHAP_MD5, PAP]` |

## Validation rules

`VpnProfile.validate()` mirrors `VpnConfig`'s `require` blocks so the UI can put the message next to
the offending field instead of letting the constructor throw. Messages are plain English rather than
string resources, which is what keeps the class Android-free.

| Field | Rule | Message |
| --- | --- | --- |
| `SERVER` | not blank | `Server address is required` |
| `SERVER` | no whitespace | `Server address cannot contain spaces` |
| `SERVER` | matches a permissive host pattern (letters, digits, `.`, `_`, `-`, `:`, `[`, `]`) | `Not a valid host name or IP address` |
| `PRESHARED_KEY` | not empty | `Pre-shared key is required` |
| `MTU` | 576–1500 | `MTU must be between 576 and 1500` |
| `IDENTITY_VALUE` | non-blank when the identity type is not `AUTO_IPV4` | `An identity value is required for <TYPE>` |
| `DNS_SERVERS` | every entry is an IPv4 dotted quad or an IPv6 literal | `'<value>' is not an IP address` (first offender only) |
| `PPP_AUTH` | at least one protocol | `At least one PPP authentication protocol must be allowed` |

The three `SERVER` rules are mutually exclusive; the rest accumulate. The host pattern is
deliberately permissive — the resolver has the final word.

**`username` and `password` are not validated.** An empty one is accepted and the peer rejects it at
PPP time, which produces a clearer error than a form that refuses to submit.

## VpnConfig — what the stack reads

`VpnConfig`'s constructor enforces: `serverHost` not blank, `presharedKey` not empty, `mtu` in
576–1500, `allowedPppAuth` not empty.

### Identity and credentials

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `serverHost` | `String` | — | Required. Resolved once at the start of the connect sequence. |
| `presharedKey` | `String` | — | Required. UTF-8 encoded for the key schedule. |
| `username` | `String` | — | PPP. |
| `password` | `String` | — | PPP. |
| `localIdentity` | `IkeIdentity` | `IkeIdentity(AUTO_IPV4, "")` | See [Identity](#identity). |

### Proposals

| Field | Type | Default |
| --- | --- | --- |
| `exchangeMode` | `IkeExchangeMode` | `MAIN` |
| `phase1` | `Phase1Proposal` | see below |
| `phase2` | `Phase2Proposal` | see below |
| `allowedPppAuth` | `List<PppAuthProtocol>` | `[MSCHAP_V2, CHAP_MD5, PAP]` |

### Transport

| Field | Type | Default | When to change |
| --- | --- | --- | --- |
| `forceUdpEncapsulation` | `Boolean` | `true` | See above; effectively mandatory on Android. |
| `ikePort` | `Int` | `500` | Only for a peer on a non-standard IKE port. |
| `natTraversalPort` | `Int` | `4500` | Only for a peer on a non-standard NAT-T port. |
| `l2tpPort` | `Int` | `1701` | The *inner* UDP port, used on both ends of the inner datagram and in the traffic selectors. Almost never changes. |

### Interface

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `mtu` | `Int` | `1400` | Ceiling, as above. |
| `dnsOverride` | `List<String>` | empty | Empty means "use whatever IPCP negotiated". The final list is de-duplicated, because a peer that pushes the same resolver twice — a Livebox does — would otherwise install it twice. |
| `blockIpv6` | `Boolean` | `true` | The `::/0` blackhole. |
| `l2tpHostName` | `String` | `"android"` | Advertised in the L2TP Host Name AVP. Some LNSes log it; xl2tpd tolerates the AVP being absent entirely. |

### Timing and resilience

| Field | Type | Default | What it controls | When to change |
| --- | --- | --- | --- | --- |
| `connectTimeoutMs` | `Int` | `45_000` | The connect watchdog: the deadline for the **whole** establishment, and also the per-phase deadline for the L2TP and PPP negotiations. | Raise on a very slow link. Lower to fail faster in tests. |
| `ikeRetransmitTimeoutMs` | `Int` | `3_000` | The first IKE retransmission timeout. Doubles per attempt, capped at eight times this value. | Raise for a high-latency peer. |
| `ikeMaxRetransmits` | `Int` | `5` | Attempts before an exchange gives up with `IKE_NO_RESPONSE`. | |
| `natKeepaliveIntervalMs` | `Int` | `20_000` | RFC 3948 §4 keepalive period — a single `0xFF` byte to port 4500. Matches charon's own default. | Lower if a NAT on the path has a shorter UDP timeout. |
| `l2tpHelloIntervalMs` | `Int` | `60_000` | L2TP HELLO period. Doubles as the liveness probe for the whole stack, since a HELLO has to survive ESP. | Lower to notice a dead peer faster, at the cost of traffic. |
| `rekeyEnabled` | `Boolean` | `true` | Whether SAs are replaced before they expire. | Off only to diagnose a peer that mishandles rekeying; the tunnel will then drop when the first SA expires. |
| `saOverlapMs` | `Int` | `30_000` | How long a superseded IPsec SA keeps being accepted inbound, and how long a superseded ISAKMP context stays reachable. | Raise for a peer that is slow to install a new SA. See [rekeying.md](rekeying.md#make-before-break). |

### Diagnostics

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `debugLogging` | `Boolean` | `false` | **Currently unused inside `:core`** — the level is set on the Android logger instead. Kept because it belongs to the configuration conceptually. |

## Phase1Proposal and Phase2Proposal

```kotlin
Phase1Proposal(
    encryption = IkeEncryption.AES_CBC_256,
    hash       = IkeHash.SHA2_256,
    dhGroup    = DhGroup.MODP_2048,
    lifetimeSeconds = 3 * 3600,          // 3 hours
)

Phase2Proposal(
    encryption = EspEncryption.ESP_AES_CBC_256,
    integrity  = EspIntegrity.HMAC_SHA2_256_128,
    pfsGroup   = null,                    // no PFS
    lifetimeSeconds = 3600,               // 1 hour
)
```

The two defaults spell `ike=aes256-sha256-modp2048!` and `esp=aes256-sha256!` in strongSwan's
notation, which is exactly what the target router offers.

**`lifetimeSeconds` is a proposal, not a promise.** The rekey schedule follows whatever the responder
answers with; see [rekeying.md](rekeying.md#why-the-responders-lifetime-and-not-ours). Neither field
is exposed in `VpnProfile`, so a user cannot change them — the live rekey tests set them directly on
`VpnConfig`.

Only one transform is ever offered per phase. A responder that answers with anything else aborts the
negotiation rather than being accommodated.

## Identity

```kotlin
IkeIdentity(type = IkeIdentityType.AUTO_IPV4, value = "")
```

| Type | ISAKMP ID type | Payload contents |
| --- | --- | --- |
| `AUTO_IPV4` | 1 (`ID_IPV4_ADDR`) | the socket's real local address, protocol and port zeroed |
| `IPV4_ADDR` | 1 | the configured dotted quad, or the local address if blank |
| `FQDN` | 2 | the value, UTF-8 |
| `USER_FQDN` | 3 | the value, UTF-8 (an e-mail-shaped identity) |
| `KEY_ID` | 11 | the value, UTF-8 |

The identity is an input to `HASH_I`, so it must be exactly what the peer expects. A peer with a
wildcard PSK (`%any %any : PSK …`, which is the usual L2TP road-warrior setup) accepts any of these.

Note that `AUTO_IPV4` and `IPV4_ADDR` deliberately carry the same wire value; they differ only in
where the address comes from.

## Algorithm vocabulary

Only what the target hardware might offer is implemented. Combined-mode ciphers (AES-GCM) would need
a different ESP layout and are not supported.

| Enum | Values | Wire notes |
| --- | --- | --- |
| `IkeEncryption` | `TRIPLE_DES_CBC`, `AES_CBC_128`, `AES_CBC_192`, `AES_CBC_256` | AES **must** carry a Key Length attribute; 3DES must **not**. |
| `IkeHash` | `MD5`, `SHA1`, `SHA2_256`, `SHA2_384`, `SHA2_512` | Also the PRF. |
| `DhGroup` | `MODP_1024` (2), `MODP_1536` (5), `MODP_2048` (14) | Primes are the verbatim RFC values, checked for length and primality by a test. |
| `EspEncryption` | `ESP_3DES`, `ESP_AES_CBC_128`, `ESP_AES_CBC_192`, `ESP_AES_CBC_256` | Transform id 12 for all AES sizes; the size comes from Key Length. |
| `EspIntegrity` | `HMAC_MD5_96`, `HMAC_SHA1_96`, `HMAC_SHA2_256_128`, `HMAC_SHA2_384_192`, `HMAC_SHA2_512_256` | SHA-2 attribute values and ICV truncation lengths per RFC 4868. |
| `PppAuthProtocol` | `PAP`, `CHAP_MD5`, `MSCHAP_V2` | Order in `allowedPppAuth` is preference order. |
| `IkeExchangeMode` | `MAIN`, `AGGRESSIVE` | |

## Fields VpnProfile does not expose

These stay at their `VpnConfig` defaults on a device. Change them by editing `VpnConfig`, or set them
directly when driving the stack from a test.

`ikePort`, `natTraversalPort`, `l2tpPort`, `l2tpHostName`, `rekeyEnabled`, `saOverlapMs`,
`ikeRetransmitTimeoutMs`, `ikeMaxRetransmits`, `connectTimeoutMs`, `natKeepaliveIntervalMs`,
`l2tpHelloIntervalMs`, `Phase1Proposal.lifetimeSeconds`, `Phase2Proposal.lifetimeSeconds`.

There is also no way to configure an **L2TP tunnel secret**, so a peer that sends a Challenge AVP in
its SCCRP fails with a clear message. The protocol side is implemented; only the plumbing is missing.

## Constants that are not configurable

Compiled in, listed here so you do not go looking for a setting that does not exist.

### Rekeying

| Constant | Value | Meaning |
| --- | --- | --- |
| rekey fraction | 75 %–85 % of the lifetime, uniform | when a replacement starts |
| minimum rekey delay | 10 s | floor, so a tiny lifetime cannot busy-loop |
| rekey retry delay | 15 s | after a failed attempt |
| maximum consecutive rekey failures | 3 | then the tunnel fails with `IPSEC_SA_FAILED` |
| ESP rekey threshold | 16 packets below `2^32` | sequence-space exhaustion |

### Tunnel plumbing

| Constant | Value | Meaning |
| --- | --- | --- |
| maintenance period | 250 ms | how often rekeys and keepalives are considered |
| shutdown grace (`:core`) | 2 s | how long the socket outlives a stop so the teardown can leave |
| maximum consecutive socket read failures | 16 | then the reader gives up rather than spinning |
| IKE queue / L2TP queue depth | 32 / 256 datagrams | |
| ESP anti-replay window | 64 | packets |

### PPP

| Constant | Value |
| --- | --- |
| restart timer | 3 s |
| maximum Configure-Requests | 10 |
| maximum PAP Authenticate-Requests | 5 |
| maximum Terminate-Requests | 3 |
| LCP echo interval | 20 s |
| maximum unanswered echoes | 5 |
| authentication timeout | 30 s |
| overall negotiation timeout | 60 s |
| default MRU when the option is rejected | 1500 |

### L2TP

| Constant | Value |
| --- | --- |
| control retransmit timeout | 1 s, doubling, capped at 16 s |
| maximum retransmits | 5 |
| advertised Receive Window Size | 8 |

### Android

| Constant | Value |
| --- | --- |
| reconnect backoff | 2 s doubling to a 60 s cap, no attempt limit |
| delay after a network handover | 1 s |
| network-change debounce | 3 s |
| socket close grace (service backstop) | 3 s |
| worker join timeout on destroy | 3 s |
| in-app log ring buffer | 500 lines |
