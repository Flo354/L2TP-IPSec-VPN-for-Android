package com.arcansecurity.vpn.l2tpipsec.data

import android.content.SharedPreferences
import com.arcansecurity.vpn.l2tpipsec.core.util.Log
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Where the store is in its one-shot load. The UI renders a spinner for [LOADING]. */
enum class ProfileStoreState {
    LOADING,

    /** Loaded. The list may still be empty — that is a first run, not a failure. */
    READY,

    /**
     * What was on disk could not be read and the list is empty. Recoverable in the sense that the
     * user can create a profile and the store will start persisting again; not recoverable in the
     * sense that the old one is gone. Say so on screen.
     */
    UNREADABLE,
}

/**
 * The saved connections.
 *
 * Everything is a [StateFlow] because loading happens off the main thread and the screen has to be
 * able to render before it finishes; nothing here blocks and nothing here throws.
 */
interface ProfileStore {

    /** The saved profiles, in a stable order that survives a reload. */
    val profiles: StateFlow<List<VpnProfile>>

    /** The profile a connect attempt would use; `null` only when there are none. */
    val activeProfileId: StateFlow<String?>

    val state: StateFlow<ProfileStoreState>

    /**
     * `false` when the platform's encrypted store could not be used and we fell back to plaintext
     * preferences. The UI must say so: on such a device the pre-shared key and the password sit
     * unencrypted in the app's private directory.
     */
    val usesEncryptedStorage: StateFlow<Boolean>

    /** Adds [profile], or replaces the one with the same id, keeping its place in the list. */
    suspend fun upsert(profile: VpnProfile)

    /** Removes the profile and **wipes its secrets**. Unknown ids are ignored. */
    suspend fun delete(id: String)

    /** Ignored when [id] is not a known profile. */
    suspend fun setActive(id: String)
}

/** The profile a connect attempt would use, or `null`. */
val ProfileStore.activeProfile: VpnProfile?
    get() = activeProfileId.value?.let { active -> profiles.value.firstOrNull { it.id == active } }

/**
 * Suspends until the one-shot load has finished, successfully or not.
 *
 * This is how the service gets a profile without the blocking the old blocking profile repository call that
 * used to sit in `onStartCommand`.
 */
suspend fun ProfileStore.awaitLoaded(): ProfileStoreState =
    state.first { it != ProfileStoreState.LOADING }

/**
 * [ProfileStore] over a [SharedPreferences] — in production the keystore-backed one.
 *
 * ## Nothing here touches the disk on the caller's thread
 *
 * The store is constructed cheaply and schedules its own load; every mutator is `suspend` and does
 * its work inside [io]. The previous design opened `EncryptedSharedPreferences` from a getter that
 * `MainActivity.onCreate` and `Service.onStartCommand` both called synchronously, which put a
 * keystore round trip and a file read on the main thread at the worst possible moment.
 *
 * ## Failure is a state, not an exception
 *
 * `EncryptedSharedPreferences` throws `SecurityException` out of *every* getter once its keyset no
 * longer matches the data on disk — a wiped or rotated master key, which is what a restore onto a
 * different handset or some OS upgrades leave behind. Every read and every write here is wrapped;
 * a failure becomes [ProfileStoreState.UNREADABLE] and an empty list that the user can immediately
 * start filling in again, and the first successful write puts the store back to
 * [ProfileStoreState.READY].
 *
 * **A failed read discards everything rather than keeping what was readable.** Every value in an
 * encrypted store is sealed under the same keyset, so a failure is all-or-nothing in practice; and
 * where it is not, a list showing half a profile is worse than an honest empty one.
 */
internal class PreferenceProfileStore(
    private val prefs: LazyPreferences,
    private val secrets: PreferenceSecretVault,
    private val scope: CoroutineScope,
    private val io: CoroutineDispatcher,
    private val log: Log,
    /**
     * A second place a schema-1 install may be hiding: the plaintext file the old code fell back to
     * when the keystore was unavailable. A device whose keystore has since started working again
     * would otherwise open an empty encrypted store and silently lose the user's setup.
     */
    private val legacySource: suspend () -> SharedPreferences? = { null },
) : ProfileStore {

    private val _profiles = MutableStateFlow<List<VpnProfile>>(emptyList())
    private val _activeProfileId = MutableStateFlow<String?>(null)
    private val _state = MutableStateFlow(ProfileStoreState.LOADING)

    /** Optimistic until the store has actually been opened, so no warning flashes during loading. */
    private val _usesEncryptedStorage = MutableStateFlow(true)

    override val profiles: StateFlow<List<VpnProfile>> = _profiles.asStateFlow()
    override val activeProfileId: StateFlow<String?> = _activeProfileId.asStateFlow()
    override val state: StateFlow<ProfileStoreState> = _state.asStateFlow()
    override val usesEncryptedStorage: StateFlow<Boolean> = _usesEncryptedStorage.asStateFlow()

    /** Serialises the load against the mutators, so an early [upsert] cannot be undone by it. */
    private val mutex = Mutex()
    private var loaded = false

    init {
        // Start loading now rather than on first use: by the time the user has looked at the
        // screen it is usually already done.
        scope.launch { withStore { } }
    }

    override suspend fun upsert(profile: VpnProfile) = withStore { store ->
        if (!isUsableProfileId(profile.id)) {
            log.e("Refusing to save a profile with an unusable id; use VpnProfile.newId()")
            return@withStore
        }
        val current = _profiles.value
        val index = current.indexOfFirst { it.id == profile.id }
        val next = if (index >= 0) {
            current.toMutableList().also { it[index] = profile }
        } else {
            current + profile
        }
        // The first profile ever created is the active one; after that an edit changes nothing.
        val active = _activeProfileId.value?.takeIf { id -> next.any { it.id == id } } ?: profile.id
        publish(store, next, active)
    }

    override suspend fun delete(id: String) = withStore { store ->
        val current = _profiles.value
        val index = current.indexOfFirst { it.id == id }
        if (index < 0) {
            log.w("Asked to delete an unknown profile; ignored")
            return@withStore
        }
        // Before the profile row goes, so a store that dies halfway leaves an orphan row rather
        // than an orphan credential.
        secrets.clearAll(id)
        val next = current.filterNot { it.id == id }
        val activeId = if (_activeProfileId.value == id) {
            // The profile that slid into its place, else the new last one, else none left at all.
            (next.getOrNull(index) ?: next.lastOrNull())?.id
        } else {
            _activeProfileId.value
        }
        publish(store, next, activeId)
    }

    override suspend fun setActive(id: String) = withStore { store ->
        if (_profiles.value.none { it.id == id }) {
            log.w("Asked to activate an unknown profile; ignored")
            return@withStore
        }
        publish(store, _profiles.value, id)
    }

    // ------------------------------------------------------------------ internals

    /**
     * Runs [block] on [io] with the store open and the initial load done.
     *
     * The store is opened *outside* [mutex] on purpose: [PreferenceSecretVault] opens it before
     * taking its own lock too, and taking the two in opposite orders would deadlock on the first,
     * slow keystore access.
     */
    private suspend fun withStore(block: suspend (OpenedPreferences?) -> Unit) {
        val store = prefs.await()
        withContext(io) {
            mutex.withLock {
                if (!loaded) {
                    loaded = true
                    load(store)
                }
                block(store)
            }
        }
    }

    private suspend fun load(store: OpenedPreferences?) {
        if (store == null) {
            _usesEncryptedStorage.value = false
            _state.value = ProfileStoreState.UNREADABLE
            return
        }
        _usesEncryptedStorage.value = store.encrypted

        val stored = try {
            val onDisk = readProfiles(store.prefs, log)
            if (onDisk.mayHoldLegacyData) migrateSingleProfile(store) ?: onDisk else onDisk
        } catch (e: Throwable) {
            log.e(
                "The stored profiles could not be read; starting from an empty list. This is what " +
                    "a master key that no longer matches the encrypted store looks like, usually " +
                    "after a restore onto another device or an OS upgrade",
                e,
            )
            _profiles.value = emptyList()
            _activeProfileId.value = null
            _state.value = ProfileStoreState.UNREADABLE
            return
        }

        _profiles.value = stored.profiles
        _activeProfileId.value = stored.activeId
        // Before READY: that is the point at which the UI starts believing SecretVault.isSet, and a
        // form that opens with "no pre-shared key set" on a profile that has one is a bug report.
        secrets.seedPresence(stored.profiles.map { it.id })
        _state.value = ProfileStoreState.READY
        log.i("Loaded ${stored.profiles.size} profile(s), encrypted=${store.encrypted}")
    }

    /**
     * Brings a single-profile (schema 1) install forward, **secrets included**.
     *
     * The order matters and is the whole difficulty: the credentials are made durable first, and
     * only a confirmed write lets the schema-1 keys be dropped. A migration interrupted anywhere
     * before that simply happens again on the next start — [LEGACY_PROFILE_ID] is fixed, so
     * repeating it produces the same profile rather than a second copy.
     *
     * @return the migrated state, or `null` when there was nothing to migrate.
     */
    private suspend fun migrateSingleProfile(store: OpenedPreferences): StoredProfiles? {
        val found = readLegacyProfile(store.prefs)?.let { store.prefs to it } ?: legacyFromFallback()
        if (found == null) {
            // Nothing to bring forward: stamp the schema so we never look again.
            writeProfiles(store.prefs, emptyList(), null, log)
            return null
        }

        val (source, legacy) = found
        val profile = legacy.profile
        try {
            legacy.presharedKey?.let { secrets.store(profile.id, SecretKind.PRESHARED_KEY, it) }
            legacy.password?.let { secrets.store(profile.id, SecretKind.PASSWORD, it) }

            if (!secrets.flushNow()) {
                log.e(
                    "The stored credentials could not be moved into the credential store; the " +
                        "profile is usable for this session and the migration will be retried on " +
                        "the next start",
                )
                return StoredProfiles(listOf(profile), profile.id, version = 0)
            }

            if (writeProfiles(store.prefs, listOf(profile), profile.id, log)) {
                purgeLegacyProfile(source, log)
                log.i("Migrated the single stored profile '${profile.displayName}' to the profile list")
            }
            return StoredProfiles(listOf(profile), profile.id, SCHEMA_VERSION)
        } finally {
            legacy.wipeSecrets()
        }
    }

    private suspend fun legacyFromFallback(): Pair<SharedPreferences, LegacyProfile>? {
        val fallback = try {
            legacySource()
        } catch (e: Throwable) {
            log.w("The plaintext fallback store could not be opened while looking for old data", e)
            null
        } ?: return null

        val legacy = try {
            readLegacyProfile(fallback)
        } catch (e: Throwable) {
            log.w("The plaintext fallback store could not be read while looking for old data", e)
            null
        } ?: return null

        log.i("Found a profile left behind in the plaintext fallback store; bringing it forward")
        return fallback to legacy
    }

    /**
     * Publishes the new list and tries to persist it.
     *
     * The flows are updated whether or not the write lands: a store that will not take the write is
     * no reason to refuse the connection the user is about to ask for with exactly these settings.
     */
    private fun publish(store: OpenedPreferences?, profiles: List<VpnProfile>, activeId: String?) {
        _profiles.value = profiles
        _activeProfileId.value = activeId
        if (store == null) return
        if (writeProfiles(store.prefs, profiles, activeId, log)) {
            // A successful write replaces whatever was unreadable before.
            _state.value = ProfileStoreState.READY
        }
    }
}
