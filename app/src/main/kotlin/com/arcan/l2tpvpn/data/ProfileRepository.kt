package com.arcan.l2tpvpn.data

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.arcan.l2tpvpn.core.crypto.DhGroup
import com.arcan.l2tpvpn.core.crypto.EspEncryption
import com.arcan.l2tpvpn.core.crypto.EspIntegrity
import com.arcan.l2tpvpn.core.crypto.IkeEncryption
import com.arcan.l2tpvpn.core.crypto.IkeHash
import com.arcan.l2tpvpn.core.tunnel.IkeExchangeMode
import com.arcan.l2tpvpn.core.tunnel.IkeIdentityType
import com.arcan.l2tpvpn.core.tunnel.PppAuthProtocol
import com.arcan.l2tpvpn.core.util.Log
import com.arcan.l2tpvpn.core.util.VpnLogger
import com.arcan.l2tpvpn.platform.AndroidLogger
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Persists the single VPN profile.
 *
 * The profile holds a pre-shared key and a PPP password, so it is written to
 * [EncryptedSharedPreferences] backed by an AES-256-GCM master key in the Android keystore. Some
 * devices — usually ones with a broken or wiped keystore — fail to initialise that; rather than
 * making the app unusable we fall back to plain preferences and say so loudly in the log, and
 * [usesEncryptedStorage] lets the UI warn the user.
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

    /** The persisted profile; updated on every [save]. */
    val profile: StateFlow<VpnProfile> get() = _profile.asStateFlow()

    init {
        var encrypted = true
        val store = try {
            val masterKey = MasterKey.Builder(context.applicationContext)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            EncryptedSharedPreferences.create(
                context.applicationContext,
                ENCRYPTED_FILE,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
            )
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
        _profile = MutableStateFlow(read())
    }

    /** Re-reads the store, discarding anything held in memory. */
    fun reload() {
        _profile.value = read()
    }

    /** Writes [profile] and publishes it to [ProfileRepository.profile]. */
    fun save(profile: VpnProfile) {
        prefs.edit().apply {
            putString(KEY_NAME, profile.name)
            putString(KEY_SERVER, profile.server)
            putString(KEY_PSK, profile.presharedKey)
            putString(KEY_USERNAME, profile.username)
            putString(KEY_PASSWORD, profile.password)
            putString(KEY_EXCHANGE_MODE, profile.exchangeMode.name)
            putString(KEY_IDENTITY_TYPE, profile.identityType.name)
            putString(KEY_IDENTITY_VALUE, profile.identityValue)
            putString(KEY_P1_ENCRYPTION, profile.phase1Encryption.name)
            putString(KEY_P1_HASH, profile.phase1Hash.name)
            putString(KEY_P1_DH, profile.phase1DhGroup.name)
            putString(KEY_P2_ENCRYPTION, profile.phase2Encryption.name)
            putString(KEY_P2_INTEGRITY, profile.phase2Integrity.name)
            putString(KEY_P2_PFS, profile.phase2PfsGroup?.name ?: NONE)
            putString(KEY_PPP_AUTH, profile.allowedPppAuth.joinToString(",") { it.name })
            putInt(KEY_MTU, profile.mtu)
            putString(KEY_DNS, profile.dnsServers)
            putBoolean(KEY_BLOCK_IPV6, profile.blockIpv6)
            putBoolean(KEY_FORCE_UDP, profile.forceUdpEncapsulation)
            putBoolean(KEY_DEBUG_LOG, profile.debugLogging)
        }.apply()
        _profile.value = profile
        log.i("Profile '${profile.name}' saved (encrypted=$usesEncryptedStorage)")
    }

    private fun read(): VpnProfile {
        val defaults = VpnProfile()
        return VpnProfile(
            name = prefs.getString(KEY_NAME, defaults.name) ?: defaults.name,
            server = prefs.getString(KEY_SERVER, defaults.server) ?: defaults.server,
            presharedKey = prefs.getString(KEY_PSK, defaults.presharedKey) ?: defaults.presharedKey,
            username = prefs.getString(KEY_USERNAME, defaults.username) ?: defaults.username,
            password = prefs.getString(KEY_PASSWORD, defaults.password) ?: defaults.password,
            exchangeMode = prefs.enum(KEY_EXCHANGE_MODE, defaults.exchangeMode, IkeExchangeMode::valueOf),
            identityType = prefs.enum(KEY_IDENTITY_TYPE, defaults.identityType, IkeIdentityType::valueOf),
            identityValue = prefs.getString(KEY_IDENTITY_VALUE, defaults.identityValue)
                ?: defaults.identityValue,
            phase1Encryption = prefs.enum(KEY_P1_ENCRYPTION, defaults.phase1Encryption, IkeEncryption::valueOf),
            phase1Hash = prefs.enum(KEY_P1_HASH, defaults.phase1Hash, IkeHash::valueOf),
            phase1DhGroup = prefs.enum(KEY_P1_DH, defaults.phase1DhGroup, DhGroup::valueOf),
            phase2Encryption = prefs.enum(KEY_P2_ENCRYPTION, defaults.phase2Encryption, EspEncryption::valueOf),
            phase2Integrity = prefs.enum(KEY_P2_INTEGRITY, defaults.phase2Integrity, EspIntegrity::valueOf),
            phase2PfsGroup = readPfsGroup(defaults.phase2PfsGroup),
            allowedPppAuth = readPppAuth(defaults.allowedPppAuth),
            mtu = prefs.getInt(KEY_MTU, defaults.mtu),
            dnsServers = prefs.getString(KEY_DNS, defaults.dnsServers) ?: defaults.dnsServers,
            blockIpv6 = prefs.getBoolean(KEY_BLOCK_IPV6, defaults.blockIpv6),
            forceUdpEncapsulation = prefs.getBoolean(KEY_FORCE_UDP, defaults.forceUdpEncapsulation),
            debugLogging = prefs.getBoolean(KEY_DEBUG_LOG, defaults.debugLogging),
        )
    }

    private fun readPfsGroup(default: DhGroup?): DhGroup? {
        val raw = prefs.getString(KEY_P2_PFS, null) ?: return default
        if (raw == NONE) return null
        return runCatching { DhGroup.valueOf(raw) }.getOrDefault(default)
    }

    private fun readPppAuth(default: List<PppAuthProtocol>): List<PppAuthProtocol> {
        val raw = prefs.getString(KEY_PPP_AUTH, null) ?: return default
        val parsed = raw.split(',')
            .mapNotNull { name -> runCatching { PppAuthProtocol.valueOf(name.trim()) }.getOrNull() }
        return parsed.ifEmpty { default }
    }

    private fun <E : Enum<E>> SharedPreferences.enum(key: String, default: E, parse: (String) -> E): E {
        val raw = getString(key, null) ?: return default
        return runCatching { parse(raw) }.getOrElse {
            log.w("Unknown value '$raw' for $key, falling back to $default")
            default
        }
    }

    companion object {
        private const val TAG = "Profiles"
        private const val ENCRYPTED_FILE = "vpn-profile-encrypted"
        private const val PLAIN_FILE = "vpn-profile"
        private const val NONE = "NONE"

        private const val KEY_NAME = "name"
        private const val KEY_SERVER = "server"
        private const val KEY_PSK = "psk"
        private const val KEY_USERNAME = "username"
        private const val KEY_PASSWORD = "password"
        private const val KEY_EXCHANGE_MODE = "exchange_mode"
        private const val KEY_IDENTITY_TYPE = "identity_type"
        private const val KEY_IDENTITY_VALUE = "identity_value"
        private const val KEY_P1_ENCRYPTION = "p1_encryption"
        private const val KEY_P1_HASH = "p1_hash"
        private const val KEY_P1_DH = "p1_dh"
        private const val KEY_P2_ENCRYPTION = "p2_encryption"
        private const val KEY_P2_INTEGRITY = "p2_integrity"
        private const val KEY_P2_PFS = "p2_pfs"
        private const val KEY_PPP_AUTH = "ppp_auth"
        private const val KEY_MTU = "mtu"
        private const val KEY_DNS = "dns"
        private const val KEY_BLOCK_IPV6 = "block_ipv6"
        private const val KEY_FORCE_UDP = "force_udp"
        private const val KEY_DEBUG_LOG = "debug_log"

        @Volatile
        private var instance: ProfileRepository? = null

        /** Process-wide singleton; the service and the UI must see the same profile. */
        fun get(context: Context, logger: VpnLogger = AndroidLogger.shared): ProfileRepository =
            instance ?: synchronized(this) {
                instance ?: ProfileRepository(context, logger).also { instance = it }
            }
    }
}
