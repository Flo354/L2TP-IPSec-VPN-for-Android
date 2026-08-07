# Security of the credential handling

What this app does with an IKE pre-shared key and a PPP password, what actually protects them, and —
the part most documents skip — what does not.

The short version: **the encryption protects the credentials at rest against a copy of the data
directory, and against nothing else.** That is worth having and it is not a vault. Everything below
either supports that sentence or qualifies it.

See also: [android.md](android.md#profile-storage) for the storage layout and the migration,
[configuration.md](configuration.md) for the fields, [architecture.md](architecture.md#the-data-layer)
for where the types live.

## Contents

* [What is stored, and where](#what-is-stored-and-where)
* [What actually encrypts what](#what-actually-encrypts-what)
* [Threat model](#threat-model)
* [The never-reveal guarantee](#the-never-reveal-guarantee)
* [Where a secret can still leak](#where-a-secret-can-still-leak)
* [Redaction](#redaction)
* [Backup and device transfer](#backup-and-device-transfer)
* [Known weaknesses and deliberate decisions](#known-weaknesses-and-deliberate-decisions)
* [The recommendation on the table: a Secret value class](#the-recommendation-on-the-table-a-secret-value-class)
* [What is not claimed](#what-is-not-claimed)

## What is stored, and where

Two secrets per profile, and nothing else in the app is treated as one.

| Secret | `SecretKind` | Where it comes from | Where it goes |
| --- | --- | --- | --- |
| IKE pre-shared key | `PRESHARED_KEY` | the profile form | the ISAKMP key schedule (`SKEYID`) |
| PPP password | `PASSWORD` | the profile form | PAP / CHAP-MD5 / MS-CHAPv2 |

Everything else — server address, user name, algorithm choices, MTU, DNS list — is **not** a secret
and lives in `VpnProfile`, which has no secret-shaped field at all. `VpnProfileTest` enumerates the
class and fails the build if one appears.

Both files are in the app's private directory (`/data/data/<package>/shared_prefs/`), which no other
app can read whatever the encryption does.

| File | Contents |
| --- | --- |
| `vpn-profile-encrypted.xml` | the profile rows **and** both credentials, all encrypted; also the two wrapped Tink keysets |
| `vpn-profile.xml` | written only by builds before the fallback was removed. It is read once, its contents are moved into the encrypted store, and it is then deleted |

Credentials are keyed by profile id and kind:

```
secret.<profile-id>.psk
secret.<profile-id>.password
```

The profile id is a random UUID, never a list index — recycling one would hand a newly created
profile the deleted tenant's credentials. Deleting a profile calls `SecretVault.clearAll`, and it
does so **before** the profile row is removed, so a store that dies halfway leaves an orphan row
rather than an orphan credential.

## What actually encrypts what

Three layers, and only the innermost key is in hardware. The reasoning is written up in
`data/EncryptedPreferences.kt`; this is the summary.

```
AndroidKeyStore                  MasterKey, AES-256-GCM, alias _androidx_security_master_key_
  │  wraps (android-keystore:// KMS URI)
  ├─ Tink keyset, AES256-SIV ──► encrypts preference NAMES (deterministically)
  └─ Tink keyset, AES256-GCM ──► encrypts preference VALUES (name as associated data)
                                 │
                                 └─ the pre-shared key and the PPP password
```

1. **The master key.** `MasterKey.Builder(...).setKeyScheme(AES256_GCM).build()` asks
   `AndroidKeyStore` for a 256-bit AES-GCM key, created on first use. Its material never leaves the
   keystore; the app only ever holds a handle. The generated spec does **not** require user
   authentication, and that is deliberate: the tunnel has to be able to reconnect while the screen is
   locked, and a key gated on unlock would make always-on VPN and background reconnects impossible.
2. **Two Tink keysets.** `EncryptedSharedPreferences` does not use the master key on the data. It
   generates one AES256-SIV keyset for names and one AES256-GCM keyset for values, wraps both with
   the master key, and stores them **inside the same XML file** under the reserved keys
   `__androidx_security_crypto_encrypted_prefs_key_keyset__` and `…_value_keyset__`. A copy of the
   file therefore contains the wrapped keysets; what it does not contain is the master key that
   unwraps them.
3. **The entries.** Names deterministically (that is what makes a lookup by name possible at all),
   values with AES-256-GCM.

**Is it hardware-backed?** The master key is, on every device this app realistically runs on: a
TEE-backed keymaster has been required for new devices since Android 7 and `minSdk` here is 26. Where
it is not — an emulator, a device with a software keymaster — the key silently degrades to software
and `MasterKey.isKeyStoreBacked()` still reports `true`. There is no promise to be had, so none is
made here.

## Threat model

| Attacker | What they get | Why |
| --- | --- | --- |
| **Another app on the device** | Nothing | The file is in this app's private directory. **UID separation is what stops them, not the encryption.** |
| **An offline copy of the data directory** — a stolen flash image, an `adb backup`, a forensic dump of an unlocked-but-not-rooted handset | Ciphertext plus two wrapped keysets | The master key is not in the copy and cannot be extracted from the handset it came from. **This is where the encryption earns its place**: the credentials are not recoverable offline. |
| **Root on the running device, or a compromised app process** (a malicious dependency, a debugger on a debuggable build) | **Everything** | Keystore keys are non-exportable but they are *usable* by whoever can act as this app's UID, and root can. The heap is readable too, and the live `VpnConfig` holds both credentials as `String`. **No storage scheme fixes this** — not a hand-rolled AES-GCM store, not StrongBox, not `CharArray` secrets. |
| **Someone holding the phone** | Nothing from storage | Userdata is encrypted at rest by file-based encryption, and an idle handset's keys are not available before first unlock. The exposure was always the app's *own screens*, which is exactly what the vault design closes. |

Read the third row before deciding any of the improvements below are urgent. It is the row that
decides what the others are worth.

## The never-reveal guarantee

**A credential that has been saved can never be displayed again.** This is enforced by the type
system, not by a UI convention.

```
                  ┌──────────────────────────────────────────┐
  ui/  ──────────►│ SecretVault                              │  no getter exists
                  │   isSet   store   clear   clearAll       │
                  └──────────────────────────────────────────┘
                                        ▲
                             one and the same object
                                        ▼
                  ┌──────────────────────────────────────────┐
  tunnel worker ─►│ SecretReader                             │  the only read path
                  │   read                                   │
                  └──────────────────────────────────────────┘
```

* `SecretVault` — what the UI is handed — can answer *whether* a secret exists and can replace or
  delete one. **It has no method that returns one.** A screen cannot pre-fill a password field "just
  this once", a log line cannot interpolate a key, and a contributor cannot add either without
  changing the interface and being asked why in review.
* `SecretReader` — one `read` method — is handed only to the tunnel worker, through
  `VpnStorage.secretReader` and `AppComponents.secrets`. Nothing under `ui/` imports the type.
* Both are views of the *same* `PreferenceSecretVault` instance, so there is one copy of the data and
  one cache. The separation that matters is at the hand-out point, not two stores.
* Consequently the form shows a fixed `••••••••` placeholder with **Replace** and **Clear** for a
  saved secret. There is no reveal toggle there, because there is nothing in the process to reveal.
  The reveal toggle exists only on a field the user is *currently typing into*, and it resets on
  focus loss.
* Validation asks `isSet`, never a value. "A pre-shared key is required" is satisfied by a secret the
  UI cannot see.
* `ProfileFormState` carries a `typedLength: Int` for each secret, not the characters — the reducer
  and the validator do their work without ever being handed a value, and `remember` (never
  `rememberSaveable`) keeps the typed characters out of the saved-instance-state bundle the system
  writes to disk.
* Duplicating a profile copies no secrets, and *cannot*: they are filed under the original's id in a
  store the UI cannot read. The snackbar says so rather than letting the user discover it when
  authentication fails.

## Where a secret can still leak

Being honest about the edges of the guarantee above:

* **`VpnConfig` holds `String` secrets.** From the moment `prepareConnect` builds one, the pre-shared
  key and the password are immutable heap objects that cannot be wiped and that live as long as the
  tunnel does. The `CharArray`s the vault returns *are* wiped, in a `finally`, as soon as the config
  is built — but the `String`s they became survive. Narrowing this is what
  [the `Secret` proposal](#the-recommendation-on-the-table-a-secret-value-class) is about.
* **Compose text fields produce an unwipeable `String` per keystroke.** `OutlinedTextField` is
  `String`-valued; typing an eight-character key allocates eight strings, all of which stay on the
  heap until a garbage collector that has no reason to hurry gets to them. `CharArray.wipe()` is
  applied to everything the app *can* wipe, and it cannot touch these.
* **Screenshots and the recents thumbnail.** `FLAG_SECURE` is **not** set on the Activity. A
  screenshot taken while a secret field is revealed captures it, and so may the recents thumbnail.
  Setting the flag would also make the in-app log screen unscreenshottable, which is the one screen
  users are asked to capture for bug reports; the trade has not been made either way yet, and it is a
  one-line change if it should be.
* **IME learning dictionaries.** Secret fields declare `KeyboardType.Password`, which asks the IME
  not to learn from them. Honouring that is the IME's choice, and a third-party keyboard is outside
  this app's control entirely.
* **A device the user has already lost control of.** See the third row of the threat model.

## Redaction

Nothing that reaches a `VpnLogger` is private. The app writes every record to logcat *and* to an
in-memory ring buffer behind a screen with **copy** and **share** buttons, so a log line is a
publication channel rather than a private debugging aid.

`redacted(secret)` in `core/util/Logging.kt` returns `<unset>` or `<redacted>` — and nothing else.

**The length is withheld on purpose.** Printing it is tempting: it looks harmless and it catches a
stray trailing space in a pasted pre-shared key. But the length is exactly the parameter that sets
the cost of guessing the key, and a trace pasted into a support ticket should not narrow that search.
`RedactionTest` pins the property that the output does not vary with the input at all.

Four `toString()`s are written out by hand rather than generated, each because the generated one
would publish something:

| Type | What the generated one would print |
| --- | --- |
| `VpnConfig` | the pre-shared key and the PPP password, in full |
| `VpnProfile` | nothing secret today — kept explicit so that *adding* a secret cannot leak it by default |
| `L2tpAvp` | an AVP body, which for a Challenge Response is authentication material and for a parsed hidden AVP is recovered cleartext |
| `PppControlPacket` / `PppOption` | a control-packet body, which for a PAP Authenticate-Request **is literally the cleartext password** |

Nothing logs an `L2tpAvp` or a `PppControlPacket` today. `CredentialSecrecyTest` and
`VpnConfigSecrecyTest` pin the property anyway, because a `$packet` in a future diagnostic is one
edit away and is exactly the kind of change nobody re-audits.

## Backup and device transfer

Both are needed, and they cover different Android versions:

| Mechanism | What it does | Applies to |
| --- | --- | --- |
| `android:allowBackup="false"` | clears `FLAG_ALLOW_BACKUP`, so the backup manager skips the app entirely | API 26–30 it is the whole story; from Android 12 it covers **cloud backup only** |
| `res/xml/data_extraction_rules.xml` | excludes **every** domain from both `<cloud-backup>` and `<device-transfer>` | Android 12+ |

From Android 12, device-to-device transfer is governed *solely* by `dataExtractionRules`, so without
the rules file a new handset would receive the pre-shared key and the PPP password during setup.
Below Android 12 the rules file does not exist and `allowBackup="false"` is what stops it. Neither
attribute is redundant.

The exclusions are spelled out one domain at a time rather than left as an empty element, because an
empty `<cloud-backup>` means "take everything". The `device_*` domains — direct-boot / device-
protected storage — are excluded too, so moving credentials there later cannot silently opt them back
into a backup.

Note the `tools:ignore="DataExtractionRules"` on `<application>`: lint asks for a
`fullBackupContent` file alongside, which on API 26–30 would never be consulted because
`allowBackup="false"` already skips the app.

## Known weaknesses and deliberate decisions

Each of these is a decision, not an oversight. The reasoning is what makes it reviewable.

### `androidx.security-crypto` is deprecated

The library is deprecated in full and gets no fixes. It also carries a failure mode this project has
already been bitten by: once the keyset no longer matches the data — a restore onto another handset,
some OS upgrades — *every* getter throws `SecurityException`. That is why every read and write in
`data/` is wrapped and why `ProfileStoreState.UNREADABLE` exists.

The replacement Google points at is a hand-rolled store: one `AndroidKeyStore` AES-256-GCM key, an
explicit 12-byte IV per record, ciphertext in a file or a `DataStore`. The crypto is about eighty
lines. The cost is elsewhere:

* **The migration** — reading the old store to write the new one, on devices whose old store may be
  exactly the one that throws, with a user's working VPN credentials as the thing being moved.
* **The testing** — `AndroidKeyStore` does not exist on a plain JVM.
  `KeyStore.getInstance("AndroidKeyStore")` throws `NoSuchProviderException` in this module's unit
  tests, so a hand-rolled store could only be covered behind an interface with a fake, plus
  instrumented tests on a device. **This module has no `androidTest` source set at all today.**

So the move is warranted eventually and was declined for now: *shipping a credential store whose only
real exercise is manual is a worse defect than the deprecation.* When it happens it should be its own
change, with device tests, not folded into a persistence rewrite.

The suppression is confined to `data/EncryptedPreferences.kt`, which contains nothing else, so it can
never quietly hide an unrelated deprecation.

### There is no fallback: no keystore, no app

An earlier version dropped to plain private `SharedPreferences` when the keystore refused, with the
pre-shared key and the password unencrypted in the app's data directory, and rendered a red banner
saying so. That has been removed.

The reasoning for keeping it was that the only screen able to fix a broken keystore is the one that
would fail to open, and that forcing a user to retype a pre-shared key ends with the key written down
somewhere worse. The reasoning against it won: a banner does not make cleartext credentials
acceptable, and the offline-copy row of the threat model above is the one case the encryption exists
for — a fallback silently deletes that protection precisely when something has already gone wrong
with the device.

So `VpnStorage.open` has no `catch`. If the keystore-backed store cannot be opened, `ProfileStore`
reports `UNREADABLE`, the home screen replaces the whole interface with an explanation, and the
service refuses to connect: there is no pre-shared key it is willing to have read. The state is
terminal rather than degraded, and a test pins that a store which fails to open does not come back
`READY`.

Reinstalling normally clears it, since a fresh install generates a fresh master key.

### StrongBox is not requested

`MasterKey.Builder.setRequestStrongBoxBacked(true)` is one call, and 1.1.0 gates it behind
`PackageManager.hasSystemFeature(...)` so asking is safe. It is not asked because:

* it would only apply to installs created **after** the change — the builder reuses an existing key
  under the same alias untouched — so devices that already have one would not benefit;
* it cannot be tested from here;
* it buys nothing against the attacker who actually matters (root / compromised process), and the
  attacker it does help against (offline copy) is already defeated by a TEE-backed key.

### Deterministic name encryption leaks structure

AES256-SIV over preference names is what makes a lookup by name possible at all, and the price is
that an observer of the file can see how many entries exist, that two entries have the same name, and
that a given entry changed. Nothing here puts anything sensitive in a *name*: the credential keys are
`secret.<uuid>.psk` and `secret.<uuid>.password`, so what leaks is "this install has N profiles, each
with up to two credentials" — which the file size leaks anyway.

### Enumeration is avoided on purpose

`SharedPreferences.getAll()` on an encrypted store decrypts **every** value as it goes. Asking "does
a password exist for this profile?" through `getAll` would therefore pull every profile's credentials
into the heap. `PreferenceSecretVault.seedPresence` probes with `contains` per key instead, and
`writeProfiles` derives the rows to drop from the previously stored order rather than from `getAll`.
Both are correctness-neutral and exist only to keep plaintext out of the heap.

### Credentials that could not be written stay in memory

If the store refuses a write, the queued credential is kept in `PreferenceSecretVault.pending` for
the life of the process and an error is logged. The tunnel therefore works for this session and stops
working after a restart. Failing the save instead would leave the user with a profile that cannot
connect and no way to understand why.

## The recommendation on the table: a `Secret` value class

The obvious "fix" for `VpnConfig` holding `String` secrets is to change them to `CharArray`. The
recommendation is **not** that — it is a `@JvmInline value class Secret`, and the argument deserves to
be presented fairly because the `CharArray` case is not stupid.

**The case for `CharArray`:** a `String` cannot be wiped, so the credentials are readable in a heap
dump for as long as the tunnel lives. A `CharArray` can be zeroed the moment it has been consumed.

**Why the win is largely illusory here:**

* `CharArray` ripples through everything — `VpnConfig`, the IKE key schedule, the PPP authenticators,
  and the Compose text fields — turning a data-shape change into a wide refactor of code that is
  currently correct.
* Android hands you `String`s upstream regardless. The user typed into an `OutlinedTextField`, which
  is `String`-valued; those copies exist before any of this code runs and survive whatever the tunnel
  layer does. Wiping the last copy while the first eight are still on the heap is theatre.
* The attacker who can read the heap is the attacker who can also use the keystore key as our UID.
  See the third row of the threat model.

**What a value class buys instead:**

```kotlin
@JvmInline
value class Secret(private val value: String) {
    override fun toString(): String = "<redacted>"
    internal fun expose(): String = value
}
```

* It **redacts by design, at compile time**, everywhere — no hand-written `toString()` to keep in
  sync, no secrecy test needed to catch the next field somebody adds.
* It makes "this is a credential" a property of the *type*, so `expose()` is a grep-able,
  review-able act rather than an ordinary field read.
* It costs nothing at runtime (it erases to the underlying reference).
* And it is exactly the right place to put a `CharArray` **later**, behind an unchanged public
  surface, if heap residency ever becomes a real requirement rather than a theoretical one.

That last point is the whole argument: the value class is the cheap move that keeps the expensive
move available.

## What is not claimed

Stated plainly, because the rest of this document reads more confidently than the evidence supports:

* **None of this has been verified on a device by execution.** What exists is a read-only review of
  the code plus plain-JVM unit tests against a **fake** `SharedPreferences` — `FakePreferences`,
  which can be made to throw `SecurityException` the way the encrypted store does. Those tests cover
  the store's ordering guarantees, the schema-1 migration (including that the credentials are durable
  *before* the old plaintext keys are dropped), the delete-wipes-secrets rule, and the "editing a
  profile must never destroy a secret the user did not touch" rule.
* **`AndroidKeyStore` is unavailable off-device**, so nothing here exercises the real
  `EncryptedSharedPreferences`, the real master key, or the real wrapping. The claim "the master key
  is not in an offline copy" rests on the library's documented behaviour, not on an experiment run
  from this repository.
* **There is no instrumented test suite.** `testInstrumentationRunner` is configured in
  `app/build.gradle.kts` but no `androidTest` source set exists.
* **No penetration test, no heap-dump inspection, no forensic extraction** has been attempted against
  a built APK.
* **No third-party review.** This document is the author's own account of the design.

If any of that changes, this section is the first thing to update.
