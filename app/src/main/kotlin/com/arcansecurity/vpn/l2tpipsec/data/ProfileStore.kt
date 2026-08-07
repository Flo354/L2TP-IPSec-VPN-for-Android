package com.arcansecurity.vpn.l2tpipsec.data

import android.content.SharedPreferences
import androidx.core.content.edit
import com.arcansecurity.vpn.l2tpipsec.core.crypto.DhGroup
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspIntegrity
import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeHash
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeExchangeMode
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeIdentityType
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.PppAuthProtocol
import com.arcansecurity.vpn.l2tpipsec.core.util.Log

/**
 * The [VpnProfile] key/value layout, split out of [ProfileRepository] so that reading and writing
 * can be exercised against a fake [SharedPreferences] on a plain JVM — no Context, no keystore.
 */

/** What came back off disk, and whether it is trustworthy. */
internal data class StoredProfile(
    val profile: VpnProfile,
    /** `true` when the store could not be read and [profile] is therefore the default one. */
    val unreadable: Boolean,
)

/**
 * Reads the stored profile, degrading to a blank one rather than throwing.
 *
 * `EncryptedSharedPreferences` throws `SecurityException` out of *every* getter once its keyset no
 * longer matches the data on disk — a wiped or rotated master key, which is what a restore onto a
 * different handset or some OS upgrades leave behind. Letting that escape took the app down inside
 * `Activity.onCreate`, and the user could never reach the screen that would have let them retype
 * the profile: an unrecoverable crash loop.
 *
 * **A failed read discards everything rather than keeping what was readable.** Every value in an
 * encrypted store is sealed under the same keyset, so in practice a failure is all-or-nothing
 * anyway; and where it is not, a form showing the server and user name but a silently empty
 * pre-shared key is worse than an obviously blank one. The caller pairs this with a visible warning
 * so "your saved profile could not be read" is a thing the user is told, not something they infer.
 *
 * Values that merely fail to *parse* — an enum name written by a newer build — are not a read
 * failure: they fall back to their default individually and leave the rest of the profile alone.
 */
internal fun readProfile(prefs: SharedPreferences, log: Log): StoredProfile = try {
    StoredProfile(prefs.readAllFields(log), unreadable = false)
} catch (e: Throwable) {
    log.e(
        "The stored profile could not be read; starting from a blank one. This is what a master " +
            "key that no longer matches the encrypted store looks like, usually after a restore " +
            "onto another device",
        e,
    )
    StoredProfile(VpnProfile(), unreadable = true)
}

/**
 * Writes [profile].
 *
 * @return `false` when the store refused the write, which is the same keystore failure [readProfile]
 *   guards against seen from the other side. The caller keeps the profile in memory regardless, so
 *   a device that cannot persist can still hold a tunnel up until it is rebooted.
 */
internal fun writeProfile(prefs: SharedPreferences, profile: VpnProfile, log: Log): Boolean = try {
    prefs.edit {
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
    }
    true
} catch (e: Throwable) {
    log.e("The profile could not be written; it is kept in memory only", e)
    false
}

private fun SharedPreferences.readAllFields(log: Log): VpnProfile {
    val defaults = VpnProfile()
    return VpnProfile(
        name = getString(KEY_NAME, defaults.name) ?: defaults.name,
        server = getString(KEY_SERVER, defaults.server) ?: defaults.server,
        presharedKey = getString(KEY_PSK, defaults.presharedKey) ?: defaults.presharedKey,
        username = getString(KEY_USERNAME, defaults.username) ?: defaults.username,
        password = getString(KEY_PASSWORD, defaults.password) ?: defaults.password,
        exchangeMode = enum(KEY_EXCHANGE_MODE, defaults.exchangeMode, log, IkeExchangeMode::valueOf),
        identityType = enum(KEY_IDENTITY_TYPE, defaults.identityType, log, IkeIdentityType::valueOf),
        identityValue = getString(KEY_IDENTITY_VALUE, defaults.identityValue)
            ?: defaults.identityValue,
        phase1Encryption = enum(KEY_P1_ENCRYPTION, defaults.phase1Encryption, log, IkeEncryption::valueOf),
        phase1Hash = enum(KEY_P1_HASH, defaults.phase1Hash, log, IkeHash::valueOf),
        phase1DhGroup = enum(KEY_P1_DH, defaults.phase1DhGroup, log, DhGroup::valueOf),
        phase2Encryption = enum(KEY_P2_ENCRYPTION, defaults.phase2Encryption, log, EspEncryption::valueOf),
        phase2Integrity = enum(KEY_P2_INTEGRITY, defaults.phase2Integrity, log, EspIntegrity::valueOf),
        phase2PfsGroup = readPfsGroup(defaults.phase2PfsGroup),
        allowedPppAuth = readPppAuth(defaults.allowedPppAuth),
        mtu = getInt(KEY_MTU, defaults.mtu),
        dnsServers = getString(KEY_DNS, defaults.dnsServers) ?: defaults.dnsServers,
        blockIpv6 = getBoolean(KEY_BLOCK_IPV6, defaults.blockIpv6),
        forceUdpEncapsulation = getBoolean(KEY_FORCE_UDP, defaults.forceUdpEncapsulation),
        debugLogging = getBoolean(KEY_DEBUG_LOG, defaults.debugLogging),
    )
}

private fun SharedPreferences.readPfsGroup(default: DhGroup?): DhGroup? {
    val raw = getString(KEY_P2_PFS, null) ?: return default
    if (raw == NONE) return null
    return runCatching { DhGroup.valueOf(raw) }.getOrDefault(default)
}

private fun SharedPreferences.readPppAuth(default: List<PppAuthProtocol>): List<PppAuthProtocol> {
    val raw = getString(KEY_PPP_AUTH, null) ?: return default
    val parsed = raw.split(',')
        .mapNotNull { name -> runCatching { PppAuthProtocol.valueOf(name.trim()) }.getOrNull() }
    return parsed.ifEmpty { default }
}

private fun <E : Enum<E>> SharedPreferences.enum(
    key: String,
    default: E,
    log: Log,
    parse: (String) -> E,
): E {
    val raw = getString(key, null) ?: return default
    return runCatching { parse(raw) }.getOrElse {
        log.w("Unknown value '$raw' for $key, falling back to $default")
        default
    }
}

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
