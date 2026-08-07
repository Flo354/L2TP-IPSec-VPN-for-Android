package com.arcansecurity.vpn.l2tpipsec.data

import androidx.core.content.edit
import com.arcansecurity.vpn.l2tpipsec.core.util.Log
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.ConcurrentHashMap

/** The two credentials a profile needs; everything else about a profile is [VpnProfile]. */
enum class SecretKind { PRESHARED_KEY, PASSWORD }

/**
 * The credential store as the **UI** sees it: it can tell whether a secret exists and it can
 * replace one, but it has no way to read one back.
 *
 * That is the whole point, and it is a property of the *type*, not of anyone's discipline. There is
 * no `get`, so a screen cannot pre-fill a password field "just this once", a log line cannot
 * interpolate a key, and a future contributor cannot add either without changing this interface and
 * being asked why in review. The read path is [SecretReader], which the UI is never handed.
 *
 * Every method is non-blocking and never throws. Writes are queued to disk in the background —
 * opening the keystore-backed store is real I/O and this interface is called from click handlers —
 * so a value is visible to [isSet] and to [SecretReader.read] immediately, and durable shortly
 * after. A store that refuses the write degrades to "kept in memory for this process" with an entry
 * in the log; it never surfaces as an exception.
 */
interface SecretVault {

    /**
     * Whether a secret of [kind] is on file for [profileId].
     *
     * This is what validation and the UI have instead of the value: a form shows "set — tap to
     * replace" rather than a masked field it could never re-fill correctly.
     *
     * Meaningful once [ProfileStore.state] has left [ProfileStoreState.LOADING]; before that the
     * store has not been opened yet and everything reads as unset.
     */
    fun isSet(profileId: String, kind: SecretKind): Boolean

    /**
     * Replaces the secret of [kind] for [profileId]. An empty [secret] is a [clear].
     *
     * The array is copied; the caller keeps ownership of theirs and should [wipe] it once the
     * field it came from is dismissed.
     */
    fun store(profileId: String, kind: SecretKind, secret: CharArray)

    fun clear(profileId: String, kind: SecretKind)

    /** Forgets both secrets of [profileId]. [ProfileStore.delete] calls this. */
    fun clearAll(profileId: String)
}

/**
 * The single read path, for building a [com.arcansecurity.vpn.l2tpipsec.core.tunnel.VpnConfig] at
 * connect time. The UI never receives this type: `VpnStorage.secretVault` hands out the same object
 * seen as a [SecretVault], and only `VpnStorage.secretReader` widens it back.
 */
interface SecretReader {

    /**
     * The stored secret, or `null` when there is none — or when the store could not be read.
     *
     * **Blocking**: it waits for the keystore-backed store to be open and for any queued write to
     * land. Call it from the tunnel worker, never from the main thread.
     *
     * The returned array belongs to the caller, who should [wipe] it as soon as the value has been
     * consumed. It is a fresh copy: mutating it does not corrupt the store.
     */
    fun read(profileId: String, kind: SecretKind): CharArray?
}

/** What [wipe] leaves behind, spelled as an escape so no raw NUL byte ends up in the source. */
private const val NUL: Char = '\u0000'

/**
 * Zeroises a plaintext secret in place.
 *
 * Worth doing even though it is not airtight — a `String` built from the array, a `StringBuilder`
 * inside a Compose text field or a copy the JIT hoisted all survive it. It shortens the window in
 * which a heap dump contains the key, and it costs one line.
 */
fun CharArray.wipe() {
    fill(NUL)
}

/**
 * [SecretVault] and [SecretReader] over a [android.content.SharedPreferences] — in production the
 * keystore-backed one from [openEncryptedPreferences]. See that file for what the encryption is
 * actually worth.
 *
 * One class implements both interfaces on purpose: there is a single copy of the data and a single
 * cache, and the separation that matters is the one at the hand-out point, not two stores.
 *
 * ## Why writes are queued
 *
 * [SecretVault] is called from the UI thread and must not block, but the underlying store performs
 * keystore operations and file I/O on every write. So [store] and [clear] park the value in
 * [pending] and wake a flush on [io]; [read] consults [pending] before the disk, which keeps
 * "save the profile, then connect" coherent no matter how the two are interleaved. A flush that
 * throws leaves the entry in [pending], so the current process keeps working against a store that
 * has stopped accepting writes.
 */
internal class PreferenceSecretVault(
    private val prefs: LazyPreferences,
    private val scope: CoroutineScope,
    private val io: CoroutineDispatcher,
    private val log: Log,
) : SecretVault, SecretReader {

    /**
     * Which secrets exist, so [isSet] answers without touching the disk.
     *
     * Entries written here by [store] and [clear] are authoritative and [seedPresence] will not
     * overwrite them — a credential stored while the store was still opening must not be forgotten
     * when the load lands.
     */
    private val presence = ConcurrentHashMap<String, Boolean>()

    /** Secrets not yet on disk. An empty array is a pending delete. */
    private val pending = ConcurrentHashMap<String, CharArray>()

    private val flushLock = Mutex()

    override fun isSet(profileId: String, kind: SecretKind): Boolean =
        presence[secretKey(profileId, kind)] == true

    override fun store(profileId: String, kind: SecretKind, secret: CharArray) {
        val key = secretKey(profileId, kind)
        pending[key] = secret.copyOf()
        presence[key] = secret.isNotEmpty()
        scheduleFlush()
    }

    override fun clear(profileId: String, kind: SecretKind) {
        val key = secretKey(profileId, kind)
        pending[key] = CharArray(0)
        presence[key] = false
        scheduleFlush()
    }

    override fun clearAll(profileId: String) {
        SecretKind.entries.forEach { clear(profileId, it) }
    }

    override fun read(profileId: String, kind: SecretKind): CharArray? {
        val key = secretKey(profileId, kind)
        // Deliberately blocking: this runs on the tunnel worker, and returning null because a write
        // had not landed yet would look to the user like a wrong pre-shared key.
        return runBlocking {
            // Opened outside the flush lock: flush() opens the store before taking that lock too,
            // and taking the two in the opposite order here would be a deadlock waiting for a
            // slow first keystore access.
            val store = prefs.await()
            flushLock.withLock {
                pending[key]?.let { queued ->
                    return@withLock queued.takeIf { it.isNotEmpty() }?.copyOf()
                }
                if (store == null) return@withLock null
                try {
                    store.prefs.getString(key, null)?.takeIf { it.isNotEmpty() }?.toCharArray()
                } catch (e: Throwable) {
                    // Never name the profile's secret, only the profile.
                    log.e("The stored $kind for profile $profileId could not be read", e)
                    null
                }
            }
        }
    }

    /**
     * Attempts every queued write now.
     *
     * @return `true` when nothing is left queued, i.e. the credentials are on disk. The migration
     *   waits for this before it lets the old plaintext copies be deleted.
     */
    internal suspend fun flushNow(): Boolean {
        flush()
        return pending.isEmpty()
    }

    private fun scheduleFlush() {
        scope.launch(io) { flush() }
    }

    private suspend fun flush() {
        val store = prefs.await() ?: return
        flushLock.withLock {
            if (pending.isEmpty()) return
            val batch = pending.toMap()
            try {
                store.prefs.edit {
                    batch.forEach { (key, value) ->
                        if (value.isEmpty()) remove(key) else putString(key, String(value))
                    }
                }
            } catch (e: Throwable) {
                log.e(
                    "${batch.size} credential(s) could not be written to the store; they are kept " +
                        "in memory for this process only and will be gone after a restart",
                    e,
                )
                return
            }
            // remove(key, value) compares by identity for arrays, which is exactly what we want:
            // an entry replaced by a newer store() while the write was in flight stays queued.
            batch.forEach { (key, value) ->
                if (pending.remove(key, value)) value.wipe()
            }
        }
    }

    /**
     * Makes [isSet] meaningful for [profileIds]. [PreferenceProfileStore] calls it as it finishes
     * loading, which is why the UI must wait for [ProfileStoreState.READY] before trusting [isSet].
     *
     * It probes with [android.content.SharedPreferences.contains] rather than enumerating: `getAll`
     * on an encrypted store decrypts every value as it goes, so asking "does a password exist"
     * would pull every profile's credentials into the heap.
     *
     * [java.util.Map.putIfAbsent] because a [store] or [clear] that happened while the store was
     * still opening is newer than anything on disk and must win.
     */
    internal suspend fun seedPresence(profileIds: Collection<String>) {
        if (profileIds.isEmpty()) return
        val store = prefs.await() ?: return
        try {
            profileIds.forEach { id ->
                SecretKind.entries.forEach { kind ->
                    val key = secretKey(id, kind)
                    if (store.prefs.contains(key)) presence.putIfAbsent(key, true)
                }
            }
        } catch (e: Throwable) {
            log.e("The credential store could not be probed; every secret reads as unset", e)
        }
    }

    companion object {
        internal const val SECRET_PREFIX = "secret."

        internal fun secretKey(profileId: String, kind: SecretKind): String = when (kind) {
            SecretKind.PRESHARED_KEY -> "$SECRET_PREFIX$profileId.psk"
            SecretKind.PASSWORD -> "$SECRET_PREFIX$profileId.password"
        }
    }
}
