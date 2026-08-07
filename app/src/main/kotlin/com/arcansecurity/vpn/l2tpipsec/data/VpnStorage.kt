package com.arcansecurity.vpn.l2tpipsec.data

import android.content.Context
import com.arcansecurity.vpn.l2tpipsec.core.util.Log
import com.arcansecurity.vpn.l2tpipsec.core.util.VpnLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob

/**
 * The persistence layer's entry point, and the place where the read/write split is enforced.
 *
 * The UI asks for [profileStore] and [secretVault]; the service additionally asks for
 * [secretReader]. All three are views of the same two objects, so there is one copy of the data —
 * but a screen that only ever sees a [SecretVault] cannot read a credential back, because the type
 * it holds has no method that would.
 *
 * Construction is free: no store is opened until something suspends on it, so calling any of these
 * from `onCreate` or `onStartCommand` costs nothing on the main thread.
 */
object VpnStorage {

    /** The saved connections. Loads itself in the background; watch [ProfileStore.state]. */
    fun profileStore(context: Context, logger: VpnLogger): ProfileStore = get(context, logger).store

    /** The credential store, write-only by construction. Hand this to the UI. */
    fun secretVault(context: Context, logger: VpnLogger): SecretVault = get(context, logger).vault

    /**
     * The credential store's read path. **Service only**, and off the main thread: it is what
     * [buildVpnConfig] needs at connect time, and handing it to a screen would give that screen the
     * ability to display a stored password.
     */
    fun secretReader(context: Context, logger: VpnLogger): SecretReader = get(context, logger).vault

    @Volatile
    private var instance: Storage? = null

    /** Process-wide singleton: the service and the UI must see the same profiles and secrets. */
    private fun get(context: Context, logger: VpnLogger): Storage =
        instance ?: synchronized(this) {
            instance ?: Storage(context.applicationContext, logger).also { instance = it }
        }
}

private class Storage(context: Context, logger: VpnLogger) {

    private val log = Log(TAG, logger)

    /**
     * Never cancelled: it outlives every Activity and the service, and the work on it is short
     * bursts of I/O. [SupervisorJob] so one failed write cannot take the rest down with it.
     */
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val prefs = LazyPreferences(Dispatchers.IO, log) { open(context, log) }

    val vault = PreferenceSecretVault(prefs, scope, Dispatchers.IO, log)

    val store = PreferenceProfileStore(
        prefs = prefs,
        secrets = vault,
        scope = scope,
        io = Dispatchers.IO,
        log = log,
        legacySource = {
            // Only interesting when we did get the encrypted store: otherwise it is the very file
            // we are already reading from.
            if (prefs.await() != null) {
                context.getSharedPreferences(PLAIN_FILE, Context.MODE_PRIVATE)
            } else {
                null
            }
        },
    )

    companion object {
        private const val TAG = "Profiles"
    }
}

/**
 * Opens the keystore-backed store. There is deliberately no fallback.
 *
 * An earlier version dropped to plaintext preferences when the keystore refused, on the grounds
 * that the only screen able to fix a broken keystore is the one that would fail to open. That trade
 * was rejected: it means a pre-shared key and a VPN password sitting unencrypted in the app's data
 * directory, which is precisely the case the encryption exists for, and a warning banner does not
 * make it acceptable. If the keystore will not cooperate the app does not run — see
 * [openEncryptedPreferences] for what it is that would otherwise be given away.
 */
private fun open(context: Context, log: Log): OpenedPreferences {
    log.d { "opening the keystore-backed preference store" }
    return OpenedPreferences(openEncryptedPreferences(context, ENCRYPTED_FILE))
}

private const val ENCRYPTED_FILE = "vpn-profile-encrypted"

/**
 * The file older builds fell back to when the keystore was unavailable. It is still read once and
 * then deleted: those installs have credentials sitting in the clear, and moving them into the
 * encrypted store and erasing the source is strictly better than leaving them there.
 */
private const val PLAIN_FILE = "vpn-profile"
