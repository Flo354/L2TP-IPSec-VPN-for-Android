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
 * The key/value layout of the profile list, split out of [PreferenceProfileStore] so that reading,
 * writing and the schema-1 migration can be exercised against a fake [SharedPreferences] on a plain
 * JVM — no Context, no keystore, no Robolectric.
 *
 * ## Layout
 *
 * ```
 * schema.version           2
 * profile.order            id1,id2,id3          <- the list order, verbatim
 * profile.active           id2
 * profile.<id>.name        …                    <- one row per field, non-secret only
 * secret.<id>.psk          …                    <- owned by PreferenceSecretVault
 * secret.<id>.password     …
 * ```
 *
 * The order is an explicit string rather than a `StringSet` because a `StringSet` comes back in
 * hash order, so the list would rearrange itself every time the app was restarted.
 */

/** Bumped when the layout changes; [migrateLegacyProfile] is what a lower number triggers. */
internal const val SCHEMA_VERSION = 2

/** What came back off disk. */
internal data class StoredProfiles(
    val profiles: List<VpnProfile>,
    val activeId: String?,
    /** 0 on a store nothing has ever been written to. */
    val version: Int,
) {
    /**
     * Whether [readLegacyProfile] should be consulted. Both halves matter: the version alone would
     * resurrect a migrated profile the user has since deleted if the schema-1 cleanup had failed,
     * and the emptiness alone would overwrite a schema-2 store that the user has just emptied.
     */
    val mayHoldLegacyData: Boolean get() = version < SCHEMA_VERSION && profiles.isEmpty()
}

/**
 * Reads every stored profile, in order.
 *
 * @throws SecurityException (or whatever else the store raises) when the values cannot be
 *   decrypted. That is deliberate: the caller turns it into
 *   [ProfileStoreState.UNREADABLE] once, for the whole store, rather than each field silently
 *   becoming its default. Values that merely fail to *parse* — an enum name written by a newer
 *   build — are not a read failure and fall back individually.
 */
internal fun readProfiles(prefs: SharedPreferences, log: Log): StoredProfiles {
    val profiles = prefs.storedOrder().map { id -> prefs.readProfile(id, log) }
    val storedActive = prefs.getString(KEY_ACTIVE, null)
    val activeId = storedActive?.takeIf { active -> profiles.any { it.id == active } }
        ?: profiles.firstOrNull()?.id

    return StoredProfiles(profiles, activeId, prefs.getInt(KEY_SCHEMA, 0))
}

/**
 * Replaces the whole profile namespace with [profiles].
 *
 * Rewriting everything rather than patching the rows that changed is what makes a delete leave no
 * orphan behind, and there are a handful of profiles at most — the edit is batched either way.
 * Secrets live under their own prefix and are not touched here; [SecretVault.clearAll] owns them.
 *
 * The rows to drop are derived from the previously stored order rather than from
 * [SharedPreferences.getAll], which on an encrypted store decrypts *every* value — including both
 * credentials of every profile — just to enumerate key names.
 *
 * @return `false` when the store refused the write, which is the same keystore failure
 *   [readProfiles] guards against seen from the other side. The caller keeps the profiles in memory
 *   regardless, so a device that cannot persist can still hold a tunnel up until it is rebooted.
 */
internal fun writeProfiles(
    prefs: SharedPreferences,
    profiles: List<VpnProfile>,
    activeId: String?,
    log: Log,
): Boolean = try {
    val previousIds = prefs.storedOrder()
    prefs.edit {
        previousIds.forEach { removeProfile(it) }
        putInt(KEY_SCHEMA, SCHEMA_VERSION)
        putString(KEY_ORDER, profiles.joinToString(ORDER_SEPARATOR.toString()) { it.id })
        if (activeId != null) putString(KEY_ACTIVE, activeId) else remove(KEY_ACTIVE)
        profiles.forEach { writeProfile(it) }
    }
    true
} catch (e: Throwable) {
    log.e("The profiles could not be written; they are kept in memory only", e)
    false
}

/**
 * Whether [id] can be used as a key component and as an element of [KEY_ORDER].
 *
 * [VpnProfile.newId] always produces one that can; this only exists so that an id invented
 * somewhere else cannot corrupt the order list with a separator.
 */
internal fun isUsableProfileId(id: String): Boolean =
    id.isNotBlank() && ORDER_SEPARATOR !in id && id.none { it.isWhitespace() }

// ---------------------------------------------------------------------- schema 1 → 2

/**
 * The identity given to the profile recovered from a single-profile install.
 *
 * Fixed rather than random so that a migration interrupted before it could be recorded produces
 * the same profile the second time round instead of a duplicate.
 */
internal const val LEGACY_PROFILE_ID = "legacy"

/** The schema-1 profile and its two secrets, as they were found on disk. */
internal class LegacyProfile(
    val profile: VpnProfile,
    val presharedKey: CharArray?,
    val password: CharArray?,
) {
    fun wipeSecrets() {
        presharedKey?.wipe()
        password?.wipe()
    }
}

/**
 * Reads a single-profile (schema 1) install, or returns `null` when [prefs] holds no such thing.
 *
 * Schema 1 stored one profile at the top level with unprefixed keys, its pre-shared key under
 * `psk` and its PPP password under `password`. Users have working setups in that shape; the whole
 * point of this function is that they come back as one profile with **both secrets intact**.
 *
 * @throws SecurityException when the values cannot be decrypted — the caller treats that exactly
 *   like a failed [readProfiles].
 */
internal fun readLegacyProfile(prefs: SharedPreferences): LegacyProfile? {
    if (LEGACY_KEYS.none { prefs.contains(it) }) return null
    val defaults = VpnProfile(id = LEGACY_PROFILE_ID)
    val profile = defaults.copy(
        name = prefs.getString(LEGACY_NAME, defaults.name) ?: defaults.name,
        server = prefs.getString(LEGACY_SERVER, defaults.server) ?: defaults.server,
        username = prefs.getString(LEGACY_USERNAME, defaults.username) ?: defaults.username,
        exchangeMode = prefs.legacyEnum(LEGACY_EXCHANGE_MODE, defaults.exchangeMode, IkeExchangeMode::valueOf),
        identityType = prefs.legacyEnum(LEGACY_IDENTITY_TYPE, defaults.identityType, IkeIdentityType::valueOf),
        identityValue = prefs.getString(LEGACY_IDENTITY_VALUE, defaults.identityValue)
            ?: defaults.identityValue,
        phase1Encryption = prefs.legacyEnum(LEGACY_P1_ENCRYPTION, defaults.phase1Encryption, IkeEncryption::valueOf),
        phase1Hash = prefs.legacyEnum(LEGACY_P1_HASH, defaults.phase1Hash, IkeHash::valueOf),
        phase1DhGroup = prefs.legacyEnum(LEGACY_P1_DH, defaults.phase1DhGroup, DhGroup::valueOf),
        phase2Encryption = prefs.legacyEnum(LEGACY_P2_ENCRYPTION, defaults.phase2Encryption, EspEncryption::valueOf),
        phase2Integrity = prefs.legacyEnum(LEGACY_P2_INTEGRITY, defaults.phase2Integrity, EspIntegrity::valueOf),
        phase2PfsGroup = prefs.readPfsGroup(LEGACY_P2_PFS, defaults.phase2PfsGroup),
        allowedPppAuth = prefs.readPppAuth(LEGACY_PPP_AUTH, defaults.allowedPppAuth),
        mtu = prefs.getInt(LEGACY_MTU, defaults.mtu),
        dnsServers = prefs.getString(LEGACY_DNS, defaults.dnsServers) ?: defaults.dnsServers,
        blockIpv6 = prefs.getBoolean(LEGACY_BLOCK_IPV6, defaults.blockIpv6),
        forceUdpEncapsulation = prefs.getBoolean(LEGACY_FORCE_UDP, defaults.forceUdpEncapsulation),
        debugLogging = prefs.getBoolean(LEGACY_DEBUG_LOG, defaults.debugLogging),
    )
    return LegacyProfile(
        profile = profile,
        presharedKey = prefs.getString(LEGACY_PSK, null)?.takeIf { it.isNotEmpty() }?.toCharArray(),
        password = prefs.getString(LEGACY_PASSWORD, null)?.takeIf { it.isNotEmpty() }?.toCharArray(),
    )
}

/** Drops the schema-1 keys, including the two plaintext secrets that have been moved into the vault. */
internal fun purgeLegacyProfile(prefs: SharedPreferences, log: Log): Boolean = try {
    prefs.edit { LEGACY_KEYS.forEach { remove(it) } }
    true
} catch (e: Throwable) {
    log.w("The migrated single-profile install could not be cleaned up", e)
    false
}

// ---------------------------------------------------------------------- per-profile rows

/** The list order as stored, de-duplicated. Empty when nothing has been written yet. */
private fun SharedPreferences.storedOrder(): List<String> =
    getString(KEY_ORDER, null).orEmpty()
        .split(ORDER_SEPARATOR)
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .distinct()

private fun SharedPreferences.Editor.removeProfile(id: String) {
    val p = "$PROFILE_PREFIX$id."
    FIELDS.forEach { remove(p + it) }
}

private fun SharedPreferences.Editor.writeProfile(profile: VpnProfile) {
    val p = "$PROFILE_PREFIX${profile.id}."
    putString(p + FIELD_NAME, profile.name)
    putString(p + FIELD_SERVER, profile.server)
    putString(p + FIELD_USERNAME, profile.username)
    putString(p + FIELD_EXCHANGE_MODE, profile.exchangeMode.name)
    putString(p + FIELD_IDENTITY_TYPE, profile.identityType.name)
    putString(p + FIELD_IDENTITY_VALUE, profile.identityValue)
    putString(p + FIELD_P1_ENCRYPTION, profile.phase1Encryption.name)
    putString(p + FIELD_P1_HASH, profile.phase1Hash.name)
    putString(p + FIELD_P1_DH, profile.phase1DhGroup.name)
    putString(p + FIELD_P2_ENCRYPTION, profile.phase2Encryption.name)
    putString(p + FIELD_P2_INTEGRITY, profile.phase2Integrity.name)
    putString(p + FIELD_P2_PFS, profile.phase2PfsGroup?.name ?: NONE)
    putString(p + FIELD_PPP_AUTH, profile.allowedPppAuth.joinToString(",") { it.name })
    putInt(p + FIELD_MTU, profile.mtu)
    putString(p + FIELD_DNS, profile.dnsServers)
    putBoolean(p + FIELD_BLOCK_IPV6, profile.blockIpv6)
    putBoolean(p + FIELD_FORCE_UDP, profile.forceUdpEncapsulation)
    putBoolean(p + FIELD_DEBUG_LOG, profile.debugLogging)
}

private fun SharedPreferences.readProfile(id: String, log: Log): VpnProfile {
    val p = "$PROFILE_PREFIX$id."
    val defaults = VpnProfile(id = id)
    return defaults.copy(
        name = getString(p + FIELD_NAME, defaults.name) ?: defaults.name,
        server = getString(p + FIELD_SERVER, defaults.server) ?: defaults.server,
        username = getString(p + FIELD_USERNAME, defaults.username) ?: defaults.username,
        exchangeMode = enum(p + FIELD_EXCHANGE_MODE, defaults.exchangeMode, log, IkeExchangeMode::valueOf),
        identityType = enum(p + FIELD_IDENTITY_TYPE, defaults.identityType, log, IkeIdentityType::valueOf),
        identityValue = getString(p + FIELD_IDENTITY_VALUE, defaults.identityValue)
            ?: defaults.identityValue,
        phase1Encryption = enum(p + FIELD_P1_ENCRYPTION, defaults.phase1Encryption, log, IkeEncryption::valueOf),
        phase1Hash = enum(p + FIELD_P1_HASH, defaults.phase1Hash, log, IkeHash::valueOf),
        phase1DhGroup = enum(p + FIELD_P1_DH, defaults.phase1DhGroup, log, DhGroup::valueOf),
        phase2Encryption = enum(p + FIELD_P2_ENCRYPTION, defaults.phase2Encryption, log, EspEncryption::valueOf),
        phase2Integrity = enum(p + FIELD_P2_INTEGRITY, defaults.phase2Integrity, log, EspIntegrity::valueOf),
        phase2PfsGroup = readPfsGroup(p + FIELD_P2_PFS, defaults.phase2PfsGroup),
        allowedPppAuth = readPppAuth(p + FIELD_PPP_AUTH, defaults.allowedPppAuth),
        mtu = getInt(p + FIELD_MTU, defaults.mtu),
        dnsServers = getString(p + FIELD_DNS, defaults.dnsServers) ?: defaults.dnsServers,
        blockIpv6 = getBoolean(p + FIELD_BLOCK_IPV6, defaults.blockIpv6),
        forceUdpEncapsulation = getBoolean(p + FIELD_FORCE_UDP, defaults.forceUdpEncapsulation),
        debugLogging = getBoolean(p + FIELD_DEBUG_LOG, defaults.debugLogging),
    )
}

/** "No PFS" is a real choice, not the absence of one, so it is stored as an explicit sentinel. */
private fun SharedPreferences.readPfsGroup(key: String, default: DhGroup?): DhGroup? {
    val raw = getString(key, null) ?: return default
    if (raw == NONE) return null
    return runCatching { DhGroup.valueOf(raw) }.getOrDefault(default)
}

private fun SharedPreferences.readPppAuth(
    key: String,
    default: List<PppAuthProtocol>,
): List<PppAuthProtocol> {
    val raw = getString(key, null) ?: return default
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

private fun <E : Enum<E>> SharedPreferences.legacyEnum(key: String, default: E, parse: (String) -> E): E {
    val raw = getString(key, null) ?: return default
    return runCatching { parse(raw) }.getOrDefault(default)
}

private const val NONE = "NONE"
private const val ORDER_SEPARATOR = ','

internal const val PROFILE_PREFIX = "profile."
internal const val KEY_SCHEMA = "schema.version"
internal const val KEY_ORDER = "profile.order"
internal const val KEY_ACTIVE = "profile.active"

private const val FIELD_NAME = "name"
private const val FIELD_SERVER = "server"
private const val FIELD_USERNAME = "username"
private const val FIELD_EXCHANGE_MODE = "exchange_mode"
private const val FIELD_IDENTITY_TYPE = "identity_type"
private const val FIELD_IDENTITY_VALUE = "identity_value"
private const val FIELD_P1_ENCRYPTION = "p1_encryption"
private const val FIELD_P1_HASH = "p1_hash"
private const val FIELD_P1_DH = "p1_dh"
private const val FIELD_P2_ENCRYPTION = "p2_encryption"
private const val FIELD_P2_INTEGRITY = "p2_integrity"
private const val FIELD_P2_PFS = "p2_pfs"
private const val FIELD_PPP_AUTH = "ppp_auth"
private const val FIELD_MTU = "mtu"
private const val FIELD_DNS = "dns"
private const val FIELD_BLOCK_IPV6 = "block_ipv6"
private const val FIELD_FORCE_UDP = "force_udp"
private const val FIELD_DEBUG_LOG = "debug_log"

/** Every row a profile owns, so a delete can drop them all without enumerating the store. */
private val FIELDS = listOf(
    FIELD_NAME,
    FIELD_SERVER,
    FIELD_USERNAME,
    FIELD_EXCHANGE_MODE,
    FIELD_IDENTITY_TYPE,
    FIELD_IDENTITY_VALUE,
    FIELD_P1_ENCRYPTION,
    FIELD_P1_HASH,
    FIELD_P1_DH,
    FIELD_P2_ENCRYPTION,
    FIELD_P2_INTEGRITY,
    FIELD_P2_PFS,
    FIELD_PPP_AUTH,
    FIELD_MTU,
    FIELD_DNS,
    FIELD_BLOCK_IPV6,
    FIELD_FORCE_UDP,
    FIELD_DEBUG_LOG,
)

// Schema 1: one profile, unprefixed keys, both secrets in the clear alongside the settings.
private const val LEGACY_NAME = "name"
private const val LEGACY_SERVER = "server"
private const val LEGACY_PSK = "psk"
private const val LEGACY_USERNAME = "username"
private const val LEGACY_PASSWORD = "password"
private const val LEGACY_EXCHANGE_MODE = "exchange_mode"
private const val LEGACY_IDENTITY_TYPE = "identity_type"
private const val LEGACY_IDENTITY_VALUE = "identity_value"
private const val LEGACY_P1_ENCRYPTION = "p1_encryption"
private const val LEGACY_P1_HASH = "p1_hash"
private const val LEGACY_P1_DH = "p1_dh"
private const val LEGACY_P2_ENCRYPTION = "p2_encryption"
private const val LEGACY_P2_INTEGRITY = "p2_integrity"
private const val LEGACY_P2_PFS = "p2_pfs"
private const val LEGACY_PPP_AUTH = "ppp_auth"
private const val LEGACY_MTU = "mtu"
private const val LEGACY_DNS = "dns"
private const val LEGACY_BLOCK_IPV6 = "block_ipv6"
private const val LEGACY_FORCE_UDP = "force_udp"
private const val LEGACY_DEBUG_LOG = "debug_log"

private val LEGACY_KEYS = listOf(
    LEGACY_NAME,
    LEGACY_SERVER,
    LEGACY_PSK,
    LEGACY_USERNAME,
    LEGACY_PASSWORD,
    LEGACY_EXCHANGE_MODE,
    LEGACY_IDENTITY_TYPE,
    LEGACY_IDENTITY_VALUE,
    LEGACY_P1_ENCRYPTION,
    LEGACY_P1_HASH,
    LEGACY_P1_DH,
    LEGACY_P2_ENCRYPTION,
    LEGACY_P2_INTEGRITY,
    LEGACY_P2_PFS,
    LEGACY_PPP_AUTH,
    LEGACY_MTU,
    LEGACY_DNS,
    LEGACY_BLOCK_IPV6,
    LEGACY_FORCE_UDP,
    LEGACY_DEBUG_LOG,
)
