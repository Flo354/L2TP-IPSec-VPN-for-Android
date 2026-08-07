package com.arcansecurity.vpn.l2tpipsec.data

import android.content.Context
import android.content.SharedPreferences
import com.arcansecurity.vpn.l2tpipsec.core.util.Log
import com.arcansecurity.vpn.l2tpipsec.core.util.VpnLogger
import com.arcansecurity.vpn.l2tpipsec.platform.AndroidLogger
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Persists the single VPN profile.
 *
 * The profile holds a pre-shared key and a PPP password, so it is written to the keystore-backed
 * store [openEncryptedPreferences] returns. Two things can go wrong with that, and neither may take
 * the app down, because the only screen that could fix either is the one that would fail to open:
 *
 *  * the store cannot be created at all — a broken or wiped keystore. We fall back to plain
 *    preferences, say so loudly in the log, and [usesEncryptedStorage] lets the UI warn the user;
 *  * the store opens but its contents no longer decrypt. [readProfile] turns that into a blank
 *    profile and raises [profileWasUnreadable].
 */
class ProfileRepository private constructor(
    context: Context,
    logger: VpnLogger,
) {

    private val log = Log(TAG, logger)

    private val prefs: SharedPreferences

    /** `false` when the keystore refused to give us an encrypted store. */
    val usesEncryptedStorage: Boolean

    private val _profile: MutableStateFlow<VpnProfile>
    private val _profileWasUnreadable = MutableStateFlow(false)

    /** The persisted profile; updated on every [save]. */
    val profile: StateFlow<VpnProfile> get() = _profile.asStateFlow()

    /**
     * `true` when what was on disk could not be decrypted and [profile] is a blank one. The user has
     * to be told: their profile is gone and nothing they do on screen will bring it back.
     */
    val profileWasUnreadable: StateFlow<Boolean> get() = _profileWasUnreadable.asStateFlow()

    init {
        var encrypted = true
        val store = try {
            openEncryptedPreferences(context, ENCRYPTED_FILE)
        } catch (e: Throwable) {
            encrypted = false
            log.w(
                "EncryptedSharedPreferences unavailable, falling back to plaintext preferences; " +
                    "the pre-shared key and password will NOT be encrypted at rest",
                e,
            )
            context.applicationContext.getSharedPreferences(PLAIN_FILE, Context.MODE_PRIVATE)
        }
        prefs = store
        usesEncryptedStorage = encrypted

        val stored = readProfile(prefs, log)
        _profile = MutableStateFlow(stored.profile)
        _profileWasUnreadable.value = stored.unreadable
    }

    /** Re-reads the store, discarding anything held in memory. */
    fun reload() {
        val stored = readProfile(prefs, log)
        _profile.value = stored.profile
        _profileWasUnreadable.value = stored.unreadable
    }

    /** Writes [profile] and publishes it to [ProfileRepository.profile]. */
    fun save(profile: VpnProfile) {
        val written = writeProfile(prefs, profile, log)
        // Published either way: a store that will not take the write is no reason to refuse the
        // connection the user is about to ask for with exactly these settings.
        _profile.value = profile
        if (written) {
            // A successful write replaces whatever was unreadable before.
            _profileWasUnreadable.value = false
            log.i("Profile '${profile.name}' saved (encrypted=$usesEncryptedStorage)")
        }
    }

    companion object {
        private const val TAG = "Profiles"
        private const val ENCRYPTED_FILE = "vpn-profile-encrypted"
        private const val PLAIN_FILE = "vpn-profile"

        @Volatile
        private var instance: ProfileRepository? = null

        /** Process-wide singleton; the service and the UI must see the same profile. */
        fun get(context: Context, logger: VpnLogger = AndroidLogger.shared): ProfileRepository =
            instance ?: synchronized(this) {
                instance ?: ProfileRepository(context, logger).also { instance = it }
            }
    }
}
