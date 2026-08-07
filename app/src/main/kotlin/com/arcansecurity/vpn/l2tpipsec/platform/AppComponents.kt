package com.arcansecurity.vpn.l2tpipsec.platform

import android.content.Context
import com.arcansecurity.vpn.l2tpipsec.data.ProfileStore
import com.arcansecurity.vpn.l2tpipsec.data.SecretReader
import com.arcansecurity.vpn.l2tpipsec.data.SecretVault
import com.arcansecurity.vpn.l2tpipsec.data.VpnStorage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * The data-layer objects the UI and the service share, wired up exactly once per process.
 *
 * Building them opens a keystore-backed store and reads a file. That is tens to hundreds of
 * milliseconds of work on a cold start, and it used to happen inside `MainActivity.onCreate` and
 * inside `onStartCommand` — both on the main looper, both a visible jank at best and a StrictMode
 * violation at worst. Nothing here may be constructed from the main thread, which is why the only
 * two entry points are a `suspend` one and an explicitly-blocking one.
 */
class AppComponents(
    val profiles: ProfileStore,
    /** Write-and-probe access to the secrets. This is what `ui/` is allowed to hold. */
    val vault: SecretVault,
    /** The single read path. Only the tunnel worker thread may touch it. */
    val secrets: SecretReader,
)

object AppComponentsHolder {

    @Volatile
    private var instance: AppComponents? = null
    private val lock = Any()

    /** For the UI: builds on [Dispatchers.IO] and never blocks the caller's thread. */
    suspend fun get(context: Context): AppComponents =
        instance ?: withContext(Dispatchers.IO) { build(context) }

    /**
     * For the service's tunnel worker, which is already off the main looper and has no coroutine
     * scope of its own. Calling this from the main thread is a bug.
     */
    fun getBlocking(context: Context): AppComponents = instance ?: build(context)

    private fun build(context: Context): AppComponents = synchronized(lock) {
        instance ?: createComponents(context).also { instance = it }
    }
}

/**
 * The only place outside `data/` that names the persistence layer's factory. Everything above and
 * everything downstream works against the interfaces, which is what keeps [SecretReader] out of
 * `ui/`: a screen is handed the [SecretVault] view of the same object and has no method that could
 * return a stored credential.
 */
private fun createComponents(context: Context): AppComponents {
    val logger = AndroidLogger.shared
    return AppComponents(
        profiles = VpnStorage.profileStore(context, logger),
        vault = VpnStorage.secretVault(context, logger),
        secrets = VpnStorage.secretReader(context, logger),
    )
}
