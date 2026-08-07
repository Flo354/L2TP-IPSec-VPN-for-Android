package com.arcansecurity.vpn.l2tpipsec.data

import android.content.SharedPreferences
import com.arcansecurity.vpn.l2tpipsec.core.util.Log
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** An opened store, and whether it turned out to be the encrypted one. */
internal class OpenedPreferences(
    val prefs: SharedPreferences,
    /** `false` when the keystore refused and this is the plaintext fallback. */
    val encrypted: Boolean,
)

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
 * [open] is expected to have already dealt with a broken keystore by falling back to a plaintext
 * store; returning `null` from [await] means even that failed, which leaves the app with no
 * persistence at all rather than with an exception thrown out of a constructor.
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
                    log.e("No preference store could be opened; nothing will be persisted", it)
                    null
                }
            }
        }
        opened
    }
}
