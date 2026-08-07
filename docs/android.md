# Android integration

Everything in `:app`: the `VpnService` lifecycle, the platform adapters, the reconnect policy, and
the two traps that produce the most confusing symptoms in the whole project.

See also: [architecture.md](architecture.md#platform-seams) for the seams `:app` implements,
[configuration.md](configuration.md) for the profile, [security.md](security.md) for what protects
the credentials, [troubleshooting.md](troubleshooting.md) for getting logs off a device.

## Contents

* [Shape of the app module](#shape-of-the-app-module)
* [Nothing touches storage on the main thread](#nothing-touches-storage-on-the-main-thread)
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
    VpnProfile           one saved connection: a stable id and the non-secret settings, Android-free
    ProfileStore         the list of profiles as StateFlows; PreferenceProfileStore implements it
    ProfileStorage       the key/value layout, the schema-1 → 2 migration; Android-free enough to fake
    SecretVault          isSet / store / clear / clearAll — the credential store WITHOUT a getter
    SecretReader         read — the single read path, handed only to the tunnel worker
    EncryptedPreferences opens EncryptedSharedPreferences; the threat model is written up in it
    LazyPreferences      opens the store exactly once, off the main thread, and never throws
    VpnStorage           the entry point, and where the read/write split is handed out
  platform/
    AppComponents        the store + vault + reader triple, built once per process, never on main
    AndroidUdpSocketFactory   protected sockets and a real local address
    AndroidTunProvider        VpnService.Builder
    AndroidLogger             logcat + an in-memory ring buffer
    LogRingBuffer             the buffer, Android-free so it unit-tests
  service/
    L2tpVpnService       the VpnService: worker thread, reconnect loop, connectivity, notification
    ConnectPreparation   profile + secrets → VpnConfig, Android-free so it unit-tests
    StartAction          which Intent action means what, Android-free so it unit-tests
    ReconnectPolicy      exponential backoff, Android-free so it unit-tests
    VpnStatusRepository  the one-way channel from the service to the UI
    VpnNotifications     the ongoing status notification
  ui/
    MainActivity         the only Activity: consent, notification permission, the Compose tree
    VpnController        the process-wide state holder: navigation, the edit session, the list
    VpnApp               three screens over one Activity, plus the logs bottom sheet
    profile/             the form's reducer, validator, secret-field model and naming helpers
    screens/             Home, the profile list, the profile editor
    components/          the text fields, the secret field, the status card
```

**Nothing binds to the service.** The UI and the service communicate through process singletons —
`VpnStatusRepository` for state, `AndroidLogger.shared` for the log, `AppComponentsHolder` for the
profiles and their credentials. There is no `onBind`, no AIDL, no broadcast. The Activity can be
destroyed and recreated while the tunnel keeps running, and the status card is correct the instant it
recomposes.

## Nothing touches storage on the main thread

This is a rule, not a preference, and it shapes several types that would otherwise look
over-engineered.

Opening the credential store generates or unwraps an Android Keystore key and then reads and decrypts
a file: tens of milliseconds on a good day, and on a cold start with a busy keymaster enough to show
up as a dropped frame or an ANR. It used to happen synchronously inside `MainActivity.onCreate` and
inside `Service.onStartCommand`. It no longer happens on either.

| Rule | How it is enforced |
| --- | --- |
| Construction is free | `VpnStorage` and `PreferenceProfileStore` allocate and schedule; `LazyPreferences` does not touch the disk until somebody **suspends** on `await()`. |
| Every mutator is `suspend` | `ProfileStore.upsert` / `delete` / `setActive` do their work inside `Dispatchers.IO`. |
| The UI never blocks | `AppComponentsHolder.get` is `suspend` and builds on `Dispatchers.IO`. `VpnController` launches on `Dispatchers.Main.immediate` and `withContext(IO)`s anything that reads. |
| The service never blocks the looper | `AppComponentsHolder.getBlocking` exists **only** for the tunnel worker, which is already off the main thread and has no coroutine scope. Calling it from the main thread is a bug. |
| Loading is a visible state, not a stall | `ProfileStore.state` starts at `LOADING` and the app draws a spinner ("Opening the profile store…") until it leaves it. |
| Opening the editor is asynchronous | `SecretVault.isSet` reads a keystore-backed file, so `VpnController.openEditor` publishes `EditorState.Loading`, probes on `Dispatchers.IO`, and only then hands the form its answers. |
| Pressing Connect is asynchronous | The pre-flight check probes the vault too, so `MainActivity.requestConnect` calls back on the main thread once the controller knows. |

The one deliberately blocking call in the whole layer is `SecretReader.read`, and its KDoc says so:
it waits for the store to be open and for any queued write to land, because returning `null` because
a write had not finished would look to the user exactly like a wrong pre-shared key. It is called
from the tunnel worker and nowhere else.

## The VpnService lifecycle

The service accepts **no intent extras** — it loads the active profile and its credentials from
storage itself, on its own worker thread. What an incoming start command means is decided in
`StartAction.kt`, kept free of Android types so the dispatch unit-tests:

| Action | Effect |
| --- | --- |
| `…action.CONNECT` | start the worker |
| `android.net.VpnService` | **also a connect** — this is how the platform starts always-on VPN, and the manifest advertises support for it, so treating it as anything else would leave always-on permanently broken |
| `…action.DISCONNECT` | stop |
| `null` (the system redelivered a command of its own) | keep a running tunnel, stop otherwise |
| anything else | log and stop |

`onStartCommand` calls the notification push **first, unconditionally**, before looking at the
action: the service may have been launched with `startForegroundService`, in which case it owes the
system a `startForeground()` call within a few seconds whatever it is about to do. It returns
`START_NOT_STICKY` — a VPN that silently reappears after the process was killed is worse than one the
user restarts, and always-on does not rely on it because the platform restarts the service itself.

Starting the tunnel, in order:

1. Guard against a double connect with an atomic flag.
2. Clear the stop flag and reset the backoff.
3. Publish `onStarting()`, push the notification.
4. Start **one** daemon thread, `l2tp-tunnel`. `L2tpIpsecTunnel.run()` blocks, so it must never be on
   the main looper.

**Nothing is read in step 1–4.** Loading the active profile means opening a keystore-backed store,
and reading its secrets means a second round of keystore work; both used to happen on the line that
starts the tunnel, which is the main looper — and the system is timing the service against the few
seconds it allows before it kills a foreground service that has not called `startForeground`.

The worker's first job is therefore `loadConfiguration()`:

1. Get `AppComponents` (blocking, but this is the worker).
2. Wait for `ProfileStore.state` to leave `LOADING`, with a **15-second timeout**. Always-on VPN can
   start the service during boot while the keystore is still warming up, so the wait is generous —
   but finite, because a store that never becomes readable has to surface as a failure rather than
   hang the service.
3. Read the active profile's two secrets through `SecretReader`.
4. `prepareConnect(profile, psk, password)` → `Ready(VpnConfig)` or `Rejected(reason)`.
5. Wipe both `CharArray`s in a `finally`, whatever happened.

A `Rejected` is a configuration problem: it is reported as an `INTERNAL` failure with that reason and
**does not enter the retry loop**, because retrying will not conjure a pre-shared key.

Only once that has succeeded does the worker register the connectivity callback and enter the
reconnect loop. Registering it earlier would mean unregistering it on every rejected connect.

The reconnect loop, per attempt:

```
runOnce()  →  resolve the host, build the socket factory and TUN provider,
              construct L2tpIpsecTunnel, call run() (blocking)
           →  Stopped   → leave the loop
           →  Ended     → treat as PEER_DISCONNECTED, retryable
           →  Failed    → carries its own TunnelErrorKind and a retryable flag
publish the failure, decide whether to retry, sleep the backoff, go again
```

The `VpnConfig` is built **once**, before the loop, and every attempt reuses it. That is what makes a
profile edited mid-connection unable to half-apply itself to a live tunnel; the editor says as much
on screen ("Changes here take effect the next time you connect"). Only the profile's name and the
resolved server host are copied out for the notification.

`onRevoke()` — the system or another VPN app took the permission — stops the tunnel.
`onDestroy()` stops it, unregisters the connectivity callback and leaves the foreground, in that
order. It deliberately does **not** join the worker: `onDestroy` runs on the main looper, the thread
can take seconds to unwind its polite teardown, and by then it owns nothing still open — blocking the
looper on it would trade a leak we do not have for an ANR we would.

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
              android:value="Maintains a user-initiated L2TP/IPsec VPN tunnel: …" />
</service>
```

The justification is spelled out **literally** in the manifest rather than behind `@string/…`: a
resource reference survives the merge as an unresolved id, and this value exists to be read straight
off the manifest by Google Play's tooling and by whoever reviews the app. The same words belong in
the Play Console declaration.

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
neither cloud backup nor device-to-device transfer may carry them off the handset. That takes **two**
declarations, `android:allowBackup="false"` and `res/xml/data_extraction_rules.xml`, because they
cover different Android versions; see [security.md](security.md#backup-and-device-transfer).

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

A **list** of profiles with one marked active, stored in `EncryptedSharedPreferences` as flat
key/value entries — no JSON, no database. Preference *names* are encrypted deterministically
(AES-256-SIV, which is what makes lookups possible) and *values* with AES-256-GCM, both through
androidx.security with a master key in the Android keystore. The code never handles an IV or a nonce
itself. What that actually protects against is in [security.md](security.md#threat-model).

### The layout

```
schema.version           2
profile.order            id1,id2,id3          <- the list order, verbatim
profile.active           id2
profile.<id>.name        …                    <- one row per field, non-secret only
profile.<id>.server      …
…
secret.<id>.psk          …                    <- owned by PreferenceSecretVault
secret.<id>.password     …
```

The order is an explicit comma-separated string rather than a `StringSet`, because a `StringSet` comes
back in hash order and the list would rearrange itself on every restart.

A write replaces the whole profile namespace rather than patching the rows that changed — that is
what makes a delete leave no orphan behind, and there are a handful of profiles at most, so it is one
batched edit either way. The rows to drop come from the *previously stored order*, never from
`SharedPreferences.getAll()`, which on an encrypted store decrypts every value — including both
credentials of every profile — just to enumerate key names.

Ids are random UUIDs. Sequential indices were rejected because an index is reused the moment a
profile in the middle of the list is deleted, and the next profile to take it would inherit the
deleted one's stored credentials.

### The credential store

The two secrets never appear on `VpnProfile`. They live under `secret.<id>.<kind>` in the same file,
behind two interfaces over the same object:

* **`SecretVault`** — `isSet` / `store` / `clear` / `clearAll` — is what the UI gets. There is no
  getter, so a screen cannot display a saved credential. See
  [security.md](security.md#the-never-reveal-guarantee).
* **`SecretReader`** — `read` — is handed only to the tunnel worker.

Writes are queued: `SecretVault` is called from click handlers and must not block, so `store` and
`clear` park the value in memory and wake a flush on `Dispatchers.IO`. A value is therefore visible
to `isSet` and to `read` immediately, and durable shortly after. **A flush that throws leaves the
entry queued**, so the current process keeps working against a store that has stopped accepting
writes; the log says so and the credential is gone after a restart.

`isSet` is answered from an in-memory presence map, seeded by probing with `contains` per key — never
by enumerating, for the `getAll` reason above. The map is seeded **before** the store publishes
`READY`, because that is the moment the UI starts trusting `isSet`, and a form that opens with "no
pre-shared key set" on a profile that has one is a bug report.

### Failure is a state, not an exception

`EncryptedSharedPreferences` throws `SecurityException` out of *every* getter once its keyset no
longer matches the data on disk — a wiped or rotated master key, which is what a restore onto another
handset or some OS upgrades leave behind. Every read and write in `data/` is wrapped, and the outcome
is a state on `ProfileStore`:

| `ProfileStoreState` | Meaning | What the UI does |
| --- | --- | --- |
| `LOADING` | the store has not been opened yet | a spinner; `isSet` is not yet meaningful |
| `READY` | loaded. An empty list here is a first run, not a failure | the normal screens |
| `UNREADABLE` | what was on disk could not be read, and the list is empty | a red banner saying the profiles were cleared and why |

A failed read **discards everything rather than keeping what was readable**: every value in an
encrypted store is sealed under the same keyset, so a failure is all-or-nothing in practice, and
where it is not, a list showing half a profile is worse than an honest empty one. The first
successful write puts the store back to `READY`.

The flows are also updated whether or not a write lands. A store that will not take the write is no
reason to refuse the connection the user is about to ask for with exactly those settings.

Unknown or unparseable enum values fall back to the default with a warning rather than throwing, so a
downgrade or a hand-edited store does not brick the app. That is a *parse* failure, not a read
failure, and it is handled per field.

### The plaintext fallback

If the keystore refuses to give an encrypted store, `VpnStorage.open` logs a warning and falls back
to plain private `SharedPreferences` under `vpn-profile`, `ProfileStore.usesEncryptedStorage` becomes
`false`, and the home screen shows a red banner saying the pre-shared key and password are stored
unencrypted.

Falling back rather than failing is deliberate: the only screen that could fix a broken keystore is
the one that would fail to open, and forcing a user to retype a pre-shared key on every restart ends
with the key written down somewhere worse. The banner makes the trade visible.

### The single-profile migration

Schema 1 stored one profile at the top level with unprefixed keys, its pre-shared key under `psk` and
its PPP password under `password`. Users have working setups in that shape, so the migration brings
one forward as a single profile **with both credentials intact**.

The order is the whole difficulty:

1. Read the schema-1 profile — from the encrypted store, or, if that has nothing, from the plaintext
   fallback file. The second source matters because a device whose keystore has *since started
   working again* would otherwise open an empty encrypted store and silently lose the user's setup.
2. `SecretVault.store` both credentials.
3. **`flushNow()` — and only a confirmed durable write lets step 4 happen.** If it fails, the profile
   is usable for this session and the migration is retried on the next start.
4. Write the schema-2 rows, then delete the schema-1 keys **including the two plaintext secrets**.

A migration interrupted anywhere before step 4 simply happens again next time: the migrated profile's
id is the fixed string `legacy`, so repeating it produces the same profile rather than a second copy.

The trigger is `version < 2` **and** an empty profile list. Both halves matter: the version alone
would resurrect a migrated profile the user has since deleted if the schema-1 cleanup had failed, and
emptiness alone would overwrite a schema-2 store the user has just emptied. A store with nothing to
migrate gets the schema stamped so it is never looked at again.

### Deleting

`ProfileStore.delete` calls `SecretVault.clearAll(id)` **before** removing the profile row, so a
store that dies halfway leaves an orphan row rather than an orphan credential. If the deleted profile
was the active one, the profile that slid into its place becomes active, else the new last one, else
none. The confirmation dialog says the credentials go with it and cannot be recovered.

### Redaction

`VpnProfile.toString()` is written out by hand even though there is nothing secret left to print, so
that adding a secret to the class cannot leak it by default — and `VpnProfileTest` fails the build if
a secret-shaped property appears on it at all. `VpnConfig.toString()` reduces both credentials to a
presence marker with no length. See [security.md](security.md#redaction).

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

Three screens over one Activity — Home, the profile list, the profile editor — plus the logs on a
bottom sheet. Navigation is a plain back stack in `VpnController` rather than a navigation library:
there are three destinations, one of them has an argument, and the state holder already outlives the
Activity, which is the only thing a library would have bought.

`VpnController` is a **process singleton, not a `ViewModel`**. The tunnel outlives the Activity by
design, and the status the UI shows has to be correct the instant a recreated Activity recomposes.
It holds no secret and there is no code path by which it could: the `SecretVault` it talks to can
only answer "is one set" and be handed a replacement, and the characters of a replacement arrive as
an argument to `saveEditor`, which wipes them before it returns.

Home is the landing screen rather than the list, because most installations have exactly one profile
and making those users walk through a list of one to reach the connect button would be paying for the
rare case with the common one. The list is one tap away; tapping a row makes it active, and edit /
duplicate / delete are behind the row's overflow so the primary gesture cannot be confused with a
destructive one. The active profile is marked with a badge and deliberately **not** hoisted to the
top of the list — a list that reorders itself the moment you tap a row makes it very easy to activate
the wrong profile twice in a row.

The connect handshake: `VpnService.prepare()` returns an Intent the first time — the system consent
dialog — and the service must not be started until it comes back `RESULT_OK`.

1. **A pre-flight check on the active profile**, asynchronously, because it probes the vault. No
   active profile, or a failed validation, produces a sentence on screen (and opens the editor)
   instead of a foreground service that starts and immediately fails. The service re-checks all of
   this on its own worker anyway — it has to, since always-on VPN can start it with no UI at all.
2. On API 33+, request `POST_NOTIFICATIONS` if it is not granted. **The two system dialogs are
   chained, not launched together**: firing both in the same frame stacks the VPN consent on top of
   the permission prompt, and whichever the user answers first silently answers for the other. Either
   answer carries on to step 3 — the permission only decides whether the notification is visible, not
   whether the foreground service may run.
3. `VpnService.prepare()`; launch the consent Intent if non-null, otherwise start the service
   directly.

**There is no draft profile any more.** Saving is explicit, and the connect path reads what was
saved; nothing is persisted behind the user's back and nothing invalid is ever written. Editing a
profile while the tunnel is up is allowed, with a line on the form saying the changes apply on the
next connect.

The single button follows the tunnel state: Connect when idle or failed, Cancel with a spinner while
the handshake is in progress, Disconnect when connected. It is disabled when there is no active
profile.

## Limitations

* **No always-on / boot support beyond what the platform gives for free.** The service handles the
  `android.net.VpnService` start action, so always-on works, but there is no boot receiver and no
  explicit always-on state of its own.
* **No per-app split tunnelling.** `addDisallowedApplication`, `addAllowedApplication` and
  `allowBypass` are never called; the tunnel applies to every app.
* **Profiles cannot be exported or imported.** There is no file format and no share action — which is
  also the only reason nobody has had to decide what such a file would do about the credentials.
* **The host is resolved twice** — once by the service, once by `:core` — so a DNS change between the
  two would be picked up inconsistently. Harmless in practice, but it is redundant work.
* **A keystore that rotates under an existing store loses every profile**, not just the unreadable
  value. That is deliberate (see above), but it is a real data loss and the banner is the only
  warning the user gets.
* **`androidx.security-crypto` is deprecated** and the migration off it has been declined for now;
  the reasoning is in [security.md](security.md#androidxsecurity-crypto-is-deprecated).
* **`VpnConfig.debugLogging` is carried into `:core` but never read there.** The debug level is set on
  the Android logger instead, so the field currently does nothing inside the stack.
