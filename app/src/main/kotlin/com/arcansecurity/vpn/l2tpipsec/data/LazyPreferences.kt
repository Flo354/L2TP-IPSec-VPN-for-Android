package com.arcansecurity.vpn.l2tpipsec.data

import android.content.SharedPreferences
import com.arcansecurity.vpn.l2tpipsec.core.util.Log
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** An opened store. There is only one kind: the keystore-backed one, or nothing. */
internal class OpenedPreferences(val prefs: SharedPreferences)

/**
 * Opens a [SharedPreferences] exactly once, off the main thread, and hands the same instance to
 * everyone who asks afterwards.
 *
 * This exists because the previous design opened `EncryptedSharedPreferences` from
 * the old blocking profile repository, which ran synchronously inside `MainActivity.onCreate` and inside
 * `Service.onStartCommand`. That call generates or unwraps a keystore key and reads and decrypts a
 * file: tens of milliseconds on a good day, and on a cold start with a busy keymaster enough to
 * show up as a dropped frame or an ANR. Nothing here touches the disk until somebody suspends on
 * [await].
 *
 * `null` from [await] means the keystore-backed store could not be opened. There is no fallback by
 * design, so that is terminal: the store reports [ProfileStoreState.UNREADABLE] and the app refuses
 * to connect. Returning `null` rather than throwing keeps the failure out of a constructor, where
 * it would take the process with it.
 */
internal class LazyPreferences(
    private val io: CoroutineDispatcher,
    private val log: Log,
    private val open: () -> OpenedPreferences,
) {

    private val mutex = Mutex()
    private var attempted = false
    private var opened: OpenedPreferences? = null

    /** The store, or `null` if it could not be opened. Never throws. */
    suspend fun await(): OpenedPreferences? = mutex.withLock {
        if (!attempted) {
            attempted = true
            opened = withContext(io) {
                runCatching(open).getOrElse {
                    log.e("The keystore-backed preference store could not be opened; the app cannot run", it)
                    null
                }
            }
        }
        opened
    }
}
