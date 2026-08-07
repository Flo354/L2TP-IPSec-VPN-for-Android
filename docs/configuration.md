# Configuration reference

Every knob, what it means, what it defaults to, and when you would change it.

There are three records, and the split between them is the important part:

| Record | Module | Holds |
| --- | --- | --- |
| `VpnConfig` | `:core` | everything the protocol stack reads, **including the two credentials** |
| `VpnProfile` | `:app` `data/` | what the user edits and what is persisted — **no secret of any kind** |
| `SecretVault` / `SecretReader` | `:app` `data/` | the pre-shared key and the PPP password, keyed by profile id |

`VpnProfile` exposes a subset of `VpnConfig`; everything it does not expose stays at its `VpnConfig`
default. A `VpnConfig` is assembled at connect time from a profile plus the two secrets read out of
the vault, and nowhere else.

See also: [protocol.md](protocol.md) for what these values do on the wire,
[android.md](android.md#profile-storage) for how profiles are stored,
[security.md](security.md) for what protects the credentials.

## Contents

* [Profiles and secrets are separate](#profiles-and-secrets-are-separate)
* [VpnProfile — what the user can set](#vpnprofile--what-the-user-can-set)
* [The two secrets](#the-two-secrets)
* [Validation rules](#validation-rules)
* [How a profile becomes a VpnConfig](#how-a-profile-becomes-a-vpnconfig)
* [VpnConfig — what the stack reads](#vpnconfig--what-the-stack-reads)
* [Phase1Proposal and Phase2Proposal](#phase1proposal-and-phase2proposal)
* [Identity](#identity)
* [Algorithm vocabulary](#algorithm-vocabulary)
* [Fields VpnProfile does not expose](#fields-vpnprofile-does-not-expose)
* [Constants that are not configurable](#constants-that-are-not-configurable)

## Profiles and secrets are separate

The pre-shared key and the PPP password used to be two more `String` fields on `VpnProfile`. They are
not any more, and the separation is structural rather than a convention:

* `VpnProfile` is a plain record with a stable `id` and the non-secret settings. Anything holding a
  profile — a text field, a `copy()`, a crash reporter walking the object graph — can reach nothing
  sensitive, because there is nothing sensitive to reach.
* The credentials live in `SecretVault`, which the UI is handed and which **has no getter**. It can
  say whether a secret exists (`isSet`) and replace or delete one (`store`, `clear`, `clearAll`).
* `SecretReader` — one `read` method — is the single read path, and only the tunnel worker is given
  one.

The consequence for anyone extending the form: **you cannot pre-fill a saved credential**, because
no code under `ui/` can obtain one. The form shows a fixed placeholder with **Replace** and **Clear**
instead. See [security.md](security.md#the-never-reveal-guarantee).

## VpnProfile — what the user can set

Deliberately free of Android types so it can be unit-tested on a plain JVM. Its `toString()` is
written out by hand even though there is nothing secret left to print, so that *adding* a secret to
the class cannot leak it by default.

### Identity of the profile itself

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `id` | `String` | `VpnProfile.newId()` — a random UUID | Stable identity. Keys this profile's rows in the preference store **and** its entries in the vault. Never reused: recycling one would hand a new profile the previous tenant's credentials, which is why it is a UUID and not a list index. |
| `name` | `String` | `"L2TP/IPsec"` | Display name, also the `VpnService.Builder` session label shown in system settings. Must not be blank. |

`displayName` falls back to the server address and then to `DEFAULT_NAME` for a profile the user
never named.

### Connection

| Field | Type | Default | Meaning / when to change |
| --- | --- | --- | --- |
| `server` | `String` | `""` | Host name or literal IPv4 address of the concentrator. **Required.** Trimmed before use. |
| `username` | `String` | `""` | PPP user name. **Not a secret** — it is shown in the profile list and can appear in the log. Trimmed. |

The pre-shared key and the password are **not** fields here; see [The two secrets](#the-two-secrets).

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
| `debugLogging` | `Boolean` | `false` | Raises the Android logger to `DEBUG`, which adds per-packet lines. Applied when a connection starts, so it takes effect on the next connect. Turn on when reproducing a handshake problem, off afterwards — it is noisy. |

### Derived values

Two free-text fields need interpreting before the stack can use them. Both are computed properties
on `VpnProfile` itself, so the form validator and the service's connect path cannot drift apart:

| Property | Definition |
| --- | --- |
| `VpnProfile.dnsServerList` | `dnsServers` split on `[,;\s]+`, trimmed, empties dropped |
| `VpnProfile.localIdentity` | `IkeIdentity(AUTO_IPV4, "")` when the type is `AUTO_IPV4`, otherwise `IkeIdentity(type, identityValue.trim())` |
| `VpnProfile.displayName` | `name`, falling back to `server`, then to the default name |

`ui/profile/ProfileListModel.kt` holds the list-shaped helpers: `orderedForDisplay` (by lower-cased
name under `Locale.ROOT`, then by id, so the order cannot change under a travelling user),
`duplicateNameFor` (`Home` → `Home (copy)` → `Home (copy 2)`, without piling up suffixes) and
`newProfileName`.

> **Maintenance note.** `VpnProfile` also carries member equivalents (`dnsServerList`,
> `localIdentity`) and a `toVpnConfig` / `buildVpnConfig` pair, none of which the app currently
> calls — the live path is `prepareConnect` below. They are covered by their own tests, so both
> copies compile and pass; if you change a rule, change it in both or delete one.

### Constants

| Constant | Value |
| --- | --- |
| `DEFAULT_NAME` | `"L2TP/IPsec"` |
| `DEFAULT_MTU` | `1400` |
| `MIN_MTU` / `MAX_MTU` | `576` / `1500` |
| `DEFAULT_PPP_AUTH` | `[MSCHAP_V2, CHAP_MD5, PAP]` |
| `newId()` | a fresh random UUID |
| `blank(name)` | an empty profile with a fresh id, for the "add a connection" flow |

## The two secrets

Both are addressed by `(profileId, SecretKind)`:

| `SecretKind` | Store key | Required? |
| --- | --- | --- |
| `PRESHARED_KEY` | `secret.<id>.psk` | **yes** — validation and `VpnConfig` both refuse without it |
| `PASSWORD` | `secret.<id>.password` | no — plenty of concentrators use an empty one |

Neither is trimmed anywhere: leading and trailing spaces may be part of the value.

### Editing one

A secret field in the form is in exactly one of three states, driven by `SecretIntent`:

| Intent | What the field shows | What saving does (`SecretCommit`) |
| --- | --- | --- |
| `KEEP` | the `••••••••` placeholder with **Replace** / **Clear** (or an empty editable field when nothing is stored) | `Keep` — the vault is not touched |
| `REPLACE` | an editable password field with a reveal toggle and **Keep the saved one** | `Store` if something was typed, **`Keep` if not** |
| `CLEAR` | "Will be removed when you save", with **Undo** | `Clear` |

The row that matters is `REPLACE` with nothing typed: the user tapped **Replace**, changed their
mind, and left the field empty. Treating that as "store an empty secret" — or worse as a clear —
would silently destroy a working credential during an unrelated edit. It is a `Keep`.

Clearing is always confirmed by a dialog, because it is unrecoverable.

**Duplicating a profile copies no secrets.** They are filed under the original's id in a store the UI
cannot read, so there is nothing to copy even in principle; the snackbar says so. **Deleting a
profile wipes both of its secrets**, and the confirmation dialog says that too.

## Validation rules

`ProfileFormState.validate()` (in `ui/profile/`) mirrors `VpnConfig`'s `require` blocks so the UI can
put the message next to the offending field instead of letting the constructor throw. Messages are
plain English rather than string resources, which is what keeps the class Android-free and
unit-testable.

| Field | Rule | Message |
| --- | --- | --- |
| `NAME` | not blank | `A profile name is required` |
| `SERVER` | not blank | `Server address is required` |
| `SERVER` | no whitespace | `Server address cannot contain spaces` |
| `SERVER` | matches a permissive host pattern (letters, digits, `.`, `_`, `-`, `:`, `[`, `]`) | `Not a valid host name or IP address` |
| `PRESHARED_KEY` | a key will exist after saving | `A pre-shared key is required` |
| `MTU` | the text parses to 576–1500 | `MTU must be between 576 and 1500` |
| `IDENTITY_VALUE` | non-blank when the identity type is not `AUTO_IPV4` | `An identity value is required for <TYPE>` |
| `DNS_SERVERS` | every entry is an IPv4 dotted quad or an IPv6 literal | `'<value>' is not an IP address` (first offender only) |
| `PPP_AUTH` | at least one protocol | `At least one PPP authentication protocol must be allowed` |

The three `SERVER` rules are mutually exclusive; the rest accumulate. The host pattern is
deliberately permissive — the resolver has the final word.

**The pre-shared key rule is the one that is not a straight mirror.** It cannot read a value, because
nothing in the UI can. It is checked through `SecretFieldModel.isSatisfied`, which is derived from
the same `commit()` the writer uses — so the validator and the writer can never disagree about
whether a secret is about to exist. A profile whose key was saved months ago validates without the UI
ever seeing it, and a freshly typed key validates before the vault has seen it.

**MTU is validated as text, not as a number.** The field keeps the user's characters while editing;
parsing on every keystroke turned a half-deleted `14` into an error the user could not read past.
`toProfile()` does the conversion once, on save.

**`username` and the password are not validated.** An empty one is accepted and the peer rejects it
at PPP time, which produces a clearer error than a form that refuses to submit.

Errors are only drawn once the user has earned them: a field must have been touched, or a save must
have been refused (`showAllErrors`), before its message appears.

## How a profile becomes a VpnConfig

`prepareConnect` in `service/ConnectPreparation.kt` is the **only** place in the app where a profile
and its secrets are combined. It is a plain function over plain values, so its failure paths are
testable without a device, a keystore or a service, and it runs on the tunnel worker thread — never
on the main looper, and nowhere `ui/` can reach it.

It decides *whether* to connect; the field-by-field mapping itself lives in `VpnProfile.toVpnConfig`,
which it delegates to. There is deliberately only one copy of that mapping: an earlier version had
two, they had already drifted apart, and the test that was supposed to catch a dropped field was
pointed at the copy the app did not use.

```
active profile  ─┐
psk  (CharArray) ─┼─► prepareConnect ─► Ready(VpnConfig) | Rejected(reason)
password (CharArray) ┘
```

| Outcome | Reason |
| --- | --- |
| `Rejected` | `No VPN profile is selected. Create one and mark it active.` |
| `Rejected` | `A pre-shared key is required` — deliberately the same words as the form's own message, so the user recognises it |
| `Rejected` | whatever `VpnConfig`'s own `require` block said, if the profile was written by an older build or edited outside the app |
| `Ready` | the assembled `VpnConfig` |

A `null` password is treated as an empty one, which is what a peer that authenticates on the
pre-shared key alone expects.

The two `CharArray`s belong to the caller, which wipes them in a `finally` as soon as the config has
been built. That is only a partial win — `VpnConfig` takes `String`s, so from that point the values
are immutable heap objects for the life of the tunnel. See
[security.md](security.md#the-recommendation-on-the-table-a-secret-value-class).

## VpnConfig — what the stack reads

`VpnConfig`'s constructor enforces: `serverHost` not blank, `presharedKey` not empty, `mtu` in
576–1500, `allowedPppAuth` not empty. Those messages travel on an exception, which goes further than
a log line, so they name the offending field and never quote a value.

Its `toString()` is written out by hand and reduces both credentials to `<redacted>` / `<unset>` —
**never a length**. See [security.md](security.md#redaction).

### Identity and credentials

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `serverHost` | `String` | — | Required. Resolved once at the start of the connect sequence. |
| `presharedKey` | `String` | — | Required. UTF-8 encoded for the key schedule. Never logged. |
| `username` | `String` | — | PPP. |
| `password` | `String` | — | PPP. Never logged. |
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
| `debugLogging` | `Boolean` | `false` | **Currently unused inside `:core`** — the stack emits at every level and the injected `VpnLogger` decides what to keep. The Android service reads this flag and sets its sink's threshold. Kept on `VpnConfig` because it belongs to the configuration conceptually. |

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
Note that a tunnel secret would be a *third* credential and belongs in `SecretVault` with the other
two, not on `VpnProfile`.

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
| deferred ISAKMP queue depth | 16 datagrams | messages handed back during a phase-1 rekey; see [rekeying.md](rekeying.md#messages-for-the-superseded-sa-are-handed-back-not-dropped) |
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
| profile-store readiness timeout on the worker | 15 s |
| in-app log ring buffer | 500 lines |

### Persistence

| Constant | Value |
| --- | --- |
| profile schema version | 2 |
| encrypted preference file | `vpn-profile-encrypted` |
| legacy file from builds that had a plaintext fallback | `vpn-profile` (read once, then deleted) |
| migrated single-profile id | `legacy` |
