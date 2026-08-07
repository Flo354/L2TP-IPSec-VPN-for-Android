// androidx.security:security-crypto is deprecated as a whole, with no replacement inside the
// library: the migration Google points at is hand-rolled AES-GCM over an Android Keystore key,
// which means rewriting the credential store and migrating what is already on disk. The trade-off
// is argued in the threat model below. Until it is done, the deprecation is confined to this file —
// which contains nothing else — so the suppression can never quietly hide an unrelated one.
@file:Suppress("DEPRECATION")

package com.arcansecurity.vpn.l2tpipsec.data

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Opens [fileName] as an [EncryptedSharedPreferences] backed by an AES-256-GCM key held in the
 * Android keystore. This is where the pre-shared keys and the PPP passwords live.
 *
 * ## What actually encrypts what
 *
 * Three layers, and only the innermost one is in hardware:
 *
 *  1. **The master key.** [MasterKey.KeyScheme.AES256_GCM] asks `AndroidKeyStore` for a 256-bit
 *     AES-GCM/NoPadding key under the alias `_androidx_security_master_key_`, created on first use
 *     with `setUserAuthenticationRequired(false)` — deliberately, since the tunnel has to be able
 *     to reconnect while the screen is locked. The key material never leaves the keystore; the app
 *     only ever holds a handle to it.
 *  2. **Two Tink keysets.** `EncryptedSharedPreferences` does not use the master key on the data.
 *     It generates an AES256-SIV keyset for preference *names* and an AES256-GCM keyset for
 *     *values*, and stores both — wrapped by the master key, via the `android-keystore://` KMS URI
 *     — inside the same XML file, under the reserved keys
 *     `__androidx_security_crypto_encrypted_prefs_key_keyset__` and `…_value_keyset__`.
 *  3. **The entries.** Names are encrypted deterministically (that is what makes a lookup by name
 *     possible at all), values with AES-256-GCM using the name as associated data.
 *
 * Deterministic name encryption leaks a little by construction: an observer of the file can see how
 * many entries exist, that two entries have the same name, and that a given entry changed. Nothing
 * here puts anything sensitive in a *name* — [PreferenceSecretVault] keys are `secret.<uuid>.psk`.
 *
 * ## Is it hardware-backed?
 *
 * The master key is, on every device this app supports in practice. A TEE-backed keymaster has
 * been required for new devices since Android 7, and `minSdk` here is 26. Where it is not — an
 * emulator, a device with a software keymaster — the key degrades to software without telling us,
 * and `MasterKey.isKeyStoreBacked()` would still say true. There is no promise to be had.
 *
 * StrongBox (a discrete secure element) is *not* requested. It is one builder call, and 1.1.0 gates
 * it behind `PackageManager.hasSystemFeature("android.hardware.strongbox_keystore")` so asking is
 * safe — but it would only apply to installs created after the change (`MasterKeys.getOrCreate`
 * reuses an existing alias untouched), it cannot be tested from here, and it buys nothing against
 * the attacker who actually matters below.
 *
 * ## Threat model — what an attacker gets
 *
 *  * **Another app on the device.** Nothing. The file is in this app's private directory and UID
 *    separation, not the encryption, is what stops them.
 *  * **A copy of the data directory** — a stolen flash image, an `adb backup`, a forensic dump of
 *    an unlocked-but-not-rooted handset. Ciphertext and two wrapped keysets. The master key is not
 *    in the copy and cannot be extracted from the handset it came from, so this is where the
 *    encryption earns its place: the credentials are not recoverable offline. Cloud backup and
 *    device-to-device transfer are separately disabled in the manifest and in
 *    `res/xml/data_extraction_rules.xml`, so the copy should not exist in the first place.
 *  * **Root on the running device.** Everything. Keystore keys are non-exportable but they are
 *    *usable* by whoever can act as this app's UID, and root can. It can also simply read the
 *    process's heap. No storage scheme fixes this, and none of the alternatives below would either.
 *  * **A compromised app process** (a malicious dependency, a debugger attached to a debuggable
 *    build). Everything, same reason.
 *  * **Someone holding the phone.** Nothing from storage — userdata is encrypted at rest by FBE and
 *    an idle handset's keys are not available before first unlock. The app's own screens are the
 *    exposure, which is exactly what [SecretVault] having no getter is for.
 *
 * The honest summary: this protects credentials **at rest against an offline copy**, and nothing
 * else. It is worth having and it is not a vault.
 *
 * ## Should this move off androidx.security-crypto?
 *
 * Eventually yes, and not yet. The library is deprecated in full, gets no fixes, and carries a
 * failure mode we have already been bitten by: once the keyset no longer matches the data — a
 * restore onto another handset, some OS upgrades — *every* getter throws `SecurityException`
 * (`getDecryptedObject` is declared `throws SecurityException`), which is why every read and write
 * in this package is wrapped and why [ProfileStoreState.UNREADABLE] exists.
 *
 * The replacement is a hand-rolled store: one `AndroidKeyStore` AES-256-GCM key, an explicit
 * 12-byte IV per record, ciphertext in a file or a `DataStore`. The cost is not the crypto, which
 * is about eighty lines. It is:
 *
 *  * **the migration** — reading the old store to write the new one, on devices whose old store may
 *    be exactly the one that throws, with a user's working VPN credentials as the thing being moved;
 *  * **the testing** — `AndroidKeyStore` does not exist on a plain JVM. `KeyStore.getInstance
 *    ("AndroidKeyStore")` throws `NoSuchProviderException` in this module's unit tests, so a
 *    hand-rolled store could only be covered behind an interface with a fake, plus instrumented
 *    tests on a device. This module has no instrumented test infrastructure today, and shipping a
 *    credential store whose only real exercise is manual is a worse defect than the deprecation.
 *
 * So: keep it, keep the failure contained, and do the move as its own change with device tests —
 * not folded into a persistence rewrite.
 *
 * @throws java.security.GeneralSecurityException or [java.io.IOException] when the keystore is
 *   unavailable; the caller decides what to do about it. See `VpnStorage.open`.
 */
internal fun openEncryptedPreferences(context: Context, fileName: String): SharedPreferences {
    val masterKey = MasterKey.Builder(context.applicationContext)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()
    return EncryptedSharedPreferences.create(
        context.applicationContext,
        fileName,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )
}
