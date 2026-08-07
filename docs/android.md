# Android integration

Everything in `:app`: the `VpnService` lifecycle, the platform adapters, the reconnect policy, and
the two traps that produce the most confusing symptoms in the whole project.

See also: [architecture.md](architecture.md#platform-seams) for the seams `:app` implements,
[configuration.md](configuration.md) for the profile, [troubleshooting.md](troubleshooting.md) for
getting logs off a device.

## Contents

* [Shape of the app module](#shape-of-the-app-module)
* [The VpnService lifecycle](#the-vpnservice-lifecycle)
* [Why protect() matters](#why-protect-matters)
* [The TUN](#the-tun)
* [Foreground service, notification and permissions](#foreground-service-notification-and-permissions)
* [The connectivity-callback trap](#the-connectivity-callback-trap)
* [The teardown ordering trap](#the-teardown-ordering-trap)
* [The reconnect policy](#the-reconnect-policy)
* [Profile storage](#profile-storage)
* [Logging](#logging)
* [Consent and the UI](#consent-and-the-ui)
* [Limitations](#limitations)

## Shape of the app module

```
com.arcansecurity.vpn.l2tpipsec
  Labels.kt              human-readable names for every protocol enum, deliberately not in strings.xml
  data/
    VpnProfile           the configuration record, free of Android types, converts to core's VpnConfig
    ProfileValidation    per-field rules mirroring VpnConfig's require blocks
    ProfileRepository    a single profile in EncryptedSharedPreferences, exposed as a StateFlow
  platform/
    AndroidUdpSocketFactory   protected sockets and a real local address
    AndroidTunProvider        VpnService.Builder
    AndroidLogger             logcat + an in-memory ring buffer
    LogRingBuffer             the buffer, Android-free so it unit-tests
  service/
    L2tpVpnService       the VpnService: worker thread, reconnect loop, connectivity, notification
    ReconnectPolicy      exponential backoff, Android-free so it unit-tests
    VpnStatusRepository  the one-way channel from the service to the UI
    VpnNotifications     the ongoing status notification
  ui/                    Compose: MainActivity, the profile form, the status card, the logs sheet
```

**Nothing binds to the service.** The UI and the service communicate through process singletons —
`VpnStatusRepository` for state, `AndroidLogger.shared` for the log, `ProfileRepository` for the
configuration. There is no `onBind`, no AIDL, no broadcast. The Activity can be destroyed and
recreated while the tunnel keeps running, and the status card is correct the instant it recomposes.

## The VpnService lifecycle

The service accepts two actions and **no intent extras** — it loads the profile from storage itself,
which is why the UI persists the draft before connecting.

| Action | Effect |
| --- | --- |
| `…action.CONNECT` | validate the stored profile, then start the worker |
| `…action.DISCONNECT` | stop |
| anything else | log and stop |

`onStartCommand` calls the notification push **first, unconditionally**, before looking at the
action: the service may have been launched with `startForegroundService`, in which case it owes the
system a `startForeground()` call within a few seconds whatever it is about to do. It returns
`START_NOT_STICKY`.

Starting the tunnel, in order:

1. Guard against a double connect with an atomic flag.
2. Load the profile and validate it. An invalid profile is reported as an `INTERNAL` failure with the
   joined messages and does not start anything.
3. Set the log level from the profile's debug switch, clear the stop flag, reset the backoff.
4. Publish `onStarting()`, push the notification, register the connectivity callback.
5. Start **one** daemon thread, `l2tp-tunnel`, which runs the reconnect loop. `L2tpIpsecTunnel.run()`
   blocks, so it must never be on the main looper.

The reconnect loop, per attempt:

```
runOnce()  →  build VpnConfig, resolve the host, build the socket factory and TUN provider,
              construct L2tpIpsecTunnel, call run() (blocking)
           →  Stopped   → leave the loop
           →  Ended     → treat as PEER_DISCONNECTED, retryable
           →  Failed    → carries its own TunnelErrorKind and a retryable flag
publish the failure, decide whether to retry, sleep the backoff, go again
```

`onRevoke()` — the system or another VPN app took the permission — stops the tunnel.
`onDestroy()` stops it, joins the worker with a timeout and unregisters the connectivity callback.

### The listener

The service implements `TunnelListener` and forwards everything to `VpnStatusRepository`, with two
deliberate asymmetries:

* `onConnected` **resets the reconnect backoff** — a connection that got this far invalidates the
  sequence.
* `onStats` updates the repository but **never touches the notification**: stats arrive about once a
  second and rebuilding a notification that often is pure waste.

## Why protect() matters

`VpnService.protect(socket)` marks a socket's traffic as exempt from the VPN's own routes. Without
it, the moment the TUN is established with a `0.0.0.0/0` route, the tunnel's own UDP/4500 packets
would be routed *into* the tunnel they are carrying. The connection deadlocks in a routing loop and
the symptom is a tunnel that establishes and then immediately stops passing anything.

So:

* Every socket the factory hands out is protected before it is used, and **a refusal is fatal** — the
  socket is closed and an exception thrown, rather than quietly continuing with something that cannot
  work.
* The throwaway route-probe socket is protected too. During a reconnect the old TUN may still be up,
  and an unprotected probe would learn the tunnel's address instead of the real one.

The other half of the socket factory's job is the local address. The socket is bound to the wildcard
address so the kernel can pick the source per destination, which means the socket reports `0.0.0.0`.
The IKE identity payload and both NAT-D hashes are computed over the local address, so a wildcard
would make the peer's NAT detection nonsense. The real address is found by connecting a throwaway UDP
socket to the peer and reading its local address — `connect()` on UDP is purely local, no packet
leaves the device — falling back to the first non-loopback IPv4 address of an interface that is up,
and finally to loopback.

`SO_TIMEOUT` is applied lazily and only when it changes, and a zero timeout is coerced to one
millisecond, because Java reads zero as "block forever" and that is never what the caller means.

## The TUN

`AndroidTunProvider` drives `VpnService.Builder`, in this order:

| Call | Value | Why |
| --- | --- | --- |
| `setSession` | the profile name | what the system VPN entry shows |
| `setMtu` | the effective MTU from `:core` | `min(header budget, peer MRU)`, see [protocol.md](protocol.md#mtu-the-header-budget-and-the-mru-clamp) |
| `addAddress` | the IPCP-assigned address, prefix 32 | a point-to-point link, not a subnet |
| `addRoute` | `0.0.0.0/0` | full-tunnel IPv4 |
| `addDnsServer` | each entry, individually guarded | one unusable entry must not lose the others |
| `addRoute` | `::/0`, when `blockIpv6` | **a blackhole, not a path** |
| `setBlocking(true)` | | the packet pump reads the descriptor from a dedicated thread |
| `setConfigureIntent` | opens the app | what the system settings VPN entry links to |
| `setMetered(false)`, `setUnderlyingNetworks(null)` | API 29+ | attribute traffic to the system default network so the VPN follows handovers instead of pinning itself |

The IPv6 blackhole deserves the emphasis: a `::/0` route is added **without any IPv6 address**, so
Android has nowhere to send v6 packets and drops them. An IPv4-only tunnel with a live IPv6 uplink
would otherwise quietly leak every dual-stack connection around the VPN.

`establish()` returning `null` means consent was revoked; `:core` turns that into `TUN_UNAVAILABLE`.

The raw descriptor is handed back to the service as well as being wrapped, because **closing it is
the only way to cancel the uplink thread's blocking read**.

## Foreground service, notification and permissions

Android 14 requires a typed foreground service and **there is no VPN type**, so the service declares
`specialUse` with a justification string in the manifest:

```xml
<service
    android:name=".service.L2tpVpnService"
    android:exported="true"
    android:foregroundServiceType="specialUse"
    android:permission="android.permission.BIND_VPN_SERVICE">
    <intent-filter><action android:name="android.net.VpnService" /></intent-filter>
    <property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"
              android:value="@string/fgs_special_use_subtype" />
</service>
```

`exported="true"` looks alarming and is not: the service is gated behind `BIND_VPN_SERVICE`, which
only the system holds, so no third-party app can reach it. Exporting it is what lets the platform
bind it for always-on VPN.

| Permission | Why |
| --- | --- |
| `INTERNET` | obvious |
| `ACCESS_NETWORK_STATE` | the connectivity callbacks |
| `FOREGROUND_SERVICE` | the ongoing service |
| `FOREGROUND_SERVICE_SPECIAL_USE` | the typed foreground service on Android 14+ |
| `POST_NOTIFICATIONS` | requested at runtime on API 33+ |

The foreground start passes the `specialUse` type on API 34+ and the plain two-argument form below
that. A failure to enter the foreground is caught and logged rather than fatal: the tunnel still
runs, it just will not survive an aggressive Doze.

The notification channel is created at **low importance** — the notification is a status line and a
Disconnect button, not something worth buzzing the phone over. It is ongoing (non-dismissable),
alerts only once so updates are silent, is local-only so it is never bridged to a watch, and carries
one action wired through `PendingIntent.getForegroundService` rather than `getService`, because the
tap can arrive while the app is in the background where a plain `startService` would be refused.

Backups are disabled outright — the preferences hold an IKE pre-shared key and a PPP password, and
neither cloud backup nor device-to-device transfer may carry them off the handset.

## The connectivity-callback trap

**This is the one that makes the app "connect and disconnect instantly".**

The tunnel has to notice when the underlying network changes: the IKE SA and both NAT-D hashes are
bound to the source address it negotiated on, so once the default network moves, that address is
gone and the only correct answer is to rebuild from scratch.

The obvious implementation — `registerDefaultNetworkCallback` — is wrong, and wrong in a way that
looks like a bug somewhere else entirely:

> Once the VPN is up, **the default network for our own uid is the VPN.** Registering `tun0` looks
> exactly like a handover, so the app tears down the tunnel it has just finished building, and the
> rebuild does it again. That is an infinite reconnect loop.

What the service does instead:

* Build a `NetworkRequest` with `NET_CAPABILITY_INTERNET` **and `NET_CAPABILITY_NOT_VPN`**.
* On API 31+, use `registerBestMatchingNetworkCallback`. It reports only the single best match, which
  with VPNs filtered out is exactly the underlying network the tunnel is built on.
* Below API 31 there is no best-match callback. Watching every matching network would fire whenever a
  second one merely becomes *available*, so the fallback is the default-network callback plus a
  belt-and-braces `TRANSPORT_VPN` check inside `onAvailable` that ignores our own tun. A handover that
  happens while the tunnel is up may be missed there; the L2TP keepalive notices it soon enough.
* The **first** `onAvailable` only records the baseline. Only a genuine change of network triggers a
  rebuild.
* `onLost` clears the record but deliberately does **not** trigger a reconnect: losing the underlying
  network without a replacement just leaves the tunnel to fail on its own.
* Changes are **debounced**. A handover resets the backoff, so anything that fires this repeatedly
  turns into a tight reconnect loop; rate-limiting keeps a future mistake here merely slow instead of
  fatal, and real handovers never arrive that fast.

When a genuine change is seen, the service sets a pending-handover flag, publishes `RECONNECTING`,
and interrupts the tunnel. The loop then treats it as *not* a peer failure: it resets the backoff and
retries after a short fixed delay, because the new interface needs a moment to get an address. A
further handover during that sleep cuts it short.

## The teardown ordering trap

**The second trap, and it only shows up on the *next* connection.**

When the user presses Disconnect, the naive implementation closes everything at once. That kills the
tunnel instantly — and it also throws away the polite teardown:

* PPP Terminate-Request
* L2TP CDN then StopCCN
* ISAKMP Delete for the IPsec SA, then for the ISAKMP SA

A router that never sees those keeps the old session alive until its own dead-peer detection notices,
which can be minutes. **A Livebox in that state then ignores the next SCCRQ entirely**, so the
reconnect hangs at `L2TP_TUNNEL` with no error, and the user's experience is "it stopped working
after I disconnected once".

So the ordering is:

1. Set the stop flag.
2. **Close the TUN.** That is the one read no timeout will ever interrupt, and closing the descriptor
   is how it is cancelled. It also stops new user traffic immediately.
3. **Leave the sockets open.** The control path still has to push the teardown out of them. The
   transports allow sends after a stop request precisely for this.
4. Wake anything sleeping in a backoff.
5. Start a reaper that sleeps a grace period and *then* closes the sockets, as a backstop for a
   control thread that is wedged somewhere it cannot see the flag.

`:core` has its own version of the same grace period; the service's is deliberately the longer of the
two, since it is only the backstop.

## The reconnect policy

Kept free of Android types so it unit-tests on a plain JVM.

```
2 s, 4 s, 8 s, 16 s, 32 s, 60 s, 60 s, 60 s, …
```

Doubling from two seconds, saturating at a one-minute cap. Aggressive enough to ride out a
two-second cell handover, polite enough not to hammer a router that is simply switched off. **There
is no attempt cap** — retries continue at one minute until the user stops.

| Verdict | `TunnelErrorKind` |
| --- | --- |
| **Never retried** | `IKE_AUTH_FAILED`, `PPP_AUTH_FAILED` |
| Retried | everything else |

Authentication failures are never retried: a wrong pre-shared key or a wrong password will not fix
itself, and retrying is how accounts get locked out.

The backoff resets when the tunnel connects, when a connection is started, and on a network handover.
Two failures bypass the policy entirely and stop immediately — an invalid configuration, and an
unimplemented code path — because neither will succeed on a retry.

## Profile storage

A single profile, stored in `EncryptedSharedPreferences` as flat key/value entries — no JSON, no
database. Preference *names* are encrypted deterministically (AES-256-SIV, which is what makes
lookups possible) and *values* with AES-256-GCM, both through androidx.security with the default
master key in the Android keystore. The code never handles an IV or a nonce itself.

**If the keystore refuses to give an encrypted store**, the repository logs a warning and falls back
to plain private `SharedPreferences` under a different file name, exposes `usesEncryptedStorage =
false`, and the UI shows a red banner saying the pre-shared key and password are stored unencrypted.
Nothing is migrated between the two files, so a device that flips from one to the other appears to
have lost its profile.

Unknown or unparseable enum values fall back to the default with a warning rather than throwing, so a
downgrade or a hand-edited store does not brick the app.

`VpnProfile.toString()` is overridden to redact the pre-shared key and the password. Nothing else
stringifies them.

## Logging

`AndroidLogger` writes every record to logcat under the tag `L2TP.<component>` **and** to an
in-memory ring buffer that the in-app log screen renders. The reason for the second sink: debugging
an IKE negotiation against a consumer router usually happens on a phone with no cable attached, where
`adb logcat` is not an option.

The level is `INFO` by default and raised to `DEBUG` by the profile's debug switch, applied when a
connection starts.

Tags in use: `Service`, `Profiles`, `UdpSocket`, `Tun` from `:app`; `Tunnel`, `IKEv1`, `l2tp`, `ppp`
from `:core`. See [troubleshooting.md](troubleshooting.md#getting-logs-off-a-device).

## Consent and the UI

`VpnService.prepare()` returns an Intent the first time — the system consent dialog — and the service
must not be started until it comes back `RESULT_OK`. The order in the Activity is:

1. Validate and **persist** the draft profile. This is how the service later finds it; the profile is
   never passed in an Intent.
2. On API 33+, request `POST_NOTIFICATIONS` if it is not granted. This is fire-and-forget — the
   consent dialog is launched immediately after, so a first run queues two system dialogs.
3. `VpnService.prepare()`; launch the consent Intent if non-null, otherwise start the service
   directly.

The draft is also persisted in `onStop()`, so whatever was typed survives the process being killed in
the background. That persists an *invalid* draft too — validation only gates connecting, not saving.

The single button follows the tunnel state: Connect when idle or failed, Cancel with a spinner while
the handshake is in progress, Disconnect when connected. The profile form is editable only when idle
or failed.

## Limitations

* **No always-on / boot support beyond what the platform gives for free.** The service is bindable by
  the platform, but there is no boot receiver and no explicit always-on handling.
* **No per-app split tunnelling.** `addDisallowedApplication`, `addAllowedApplication` and
  `allowBypass` are never called; the tunnel applies to every app.
* **One profile**, not a list.
* **The host is resolved twice** — once by the service, once by `:core` — so a DNS change between the
  two would be picked up inconsistently. Harmless in practice, but it is redundant work.
* **A decryption failure of an individual stored value is not handled.** If the keystore rotates
  under an existing encrypted store, the exception propagates out of the repository's constructor.
  The handled case is the store failing to open at all.
* **`VpnConfig.debugLogging` is carried into `:core` but never read there.** The debug level is set on
  the Android logger instead, so the field currently does nothing.
