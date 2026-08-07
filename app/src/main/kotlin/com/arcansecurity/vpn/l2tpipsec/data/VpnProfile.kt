package com.arcansecurity.vpn.l2tpipsec.data

import com.arcansecurity.vpn.l2tpipsec.core.crypto.DhGroup
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspIntegrity
import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeHash
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeExchangeMode
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeIdentity
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeIdentityType
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.Phase1Proposal
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.Phase2Proposal
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.PppAuthProtocol
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.VpnConfig
import java.util.UUID

/**
 * A saved connection: the user-editable, **non-secret** half of a [VpnConfig].
 *
 * [VpnConfig] carries a fair number of protocol timers that nobody should have to think about;
 * this class keeps only what a person configuring a road-warrior tunnel actually needs, in the
 * shape the UI edits it (free text for the DNS list, a nullable PFS group, …), and [toVpnConfig]
 * performs the translation.
 *
 * ## It deliberately holds no secret
 *
 * The pre-shared key and the PPP password used to be two more `String` fields here. That made them
 * reachable from anything holding a profile — a text field, a `copy()`, a crash reporter walking
 * the object graph — and the generated `toString` printed both. They now live in [SecretVault],
 * which has no getter at all, and the only way back to a plaintext secret is [SecretReader.read].
 * Keeping a secret out of this class is what makes that guarantee structural rather than a habit:
 * there is nothing to leak because there is nothing here.
 *
 * Every default is the one that works against the target hardware: IKEv1 main mode,
 * `aes256-sha256-modp2048` for phase 1, `aes256-sha256` with no PFS for phase 2, forced UDP
 * encapsulation (Android cannot open raw ESP sockets) and an MTU of 1400.
 *
 * The class is deliberately free of Android types so that it can be unit-tested on a plain JVM.
 */
data class VpnProfile(
    /**
     * Stable identity, generated once by [newId] and never reused — it keys this profile's rows in
     * the preference store *and* its entries in [SecretVault], so recycling one would hand a new
     * profile the previous tenant's credentials.
     */
    val id: String,
    /** Display name; also used as the `VpnService.Builder` session label. */
    val name: String = DEFAULT_NAME,
    /** Host name or literal IPv4 address of the VPN concentrator. */
    val server: String = "",
    /** PPP user name. Not a secret: it is shown in the list and in the notification. */
    val username: String = "",

    val exchangeMode: IkeExchangeMode = IkeExchangeMode.MAIN,
    /** ISAKMP identity type; [IkeIdentityType.AUTO_IPV4] derives it from the socket. */
    val identityType: IkeIdentityType = IkeIdentityType.AUTO_IPV4,
    /** Identity payload contents; ignored when [identityType] is [IkeIdentityType.AUTO_IPV4]. */
    val identityValue: String = "",

    val phase1Encryption: IkeEncryption = IkeEncryption.AES_CBC_256,
    val phase1Hash: IkeHash = IkeHash.SHA2_256,
    val phase1DhGroup: DhGroup = DhGroup.MODP_2048,

    val phase2Encryption: EspEncryption = EspEncryption.ESP_AES_CBC_256,
    val phase2Integrity: EspIntegrity = EspIntegrity.HMAC_SHA2_256_128,
    /** `null` means "no PFS", which is what most consumer routers expect. */
    val phase2PfsGroup: DhGroup? = null,

    /** PPP authentication protocols offered, in order of preference. */
    val allowedPppAuth: List<PppAuthProtocol> = DEFAULT_PPP_AUTH,

    val mtu: Int = DEFAULT_MTU,

    /**
     * Comma- or space-separated DNS servers pushed to the system instead of the ones IPCP
     * negotiated. Empty means "keep whatever the peer offered".
     */
    val dnsServers: String = "",

    /** Blackhole IPv6 through the tunnel so traffic cannot leak around an IPv4-only VPN. */
    val blockIpv6: Boolean = true,
    /** Advertise a bogus source NAT-D hash so the peer always encapsulates ESP in UDP/4500. */
    val forceUdpEncapsulation: Boolean = true,
    /** Raise the log level of the protocol stack to DEBUG. */
    val debugLogging: Boolean = false,
) {

    /** The [dnsServers] free-text field split into individual addresses. */
    val dnsServerList: List<String>
        get() = dnsServers.split(DNS_SEPARATORS)
            .map { it.trim() }
            .filter { it.isNotEmpty() }

    /** The ISAKMP identity, with the value cleared for the automatic type. */
    val localIdentity: IkeIdentity
        get() = if (identityType == IkeIdentityType.AUTO_IPV4) {
            IkeIdentity(IkeIdentityType.AUTO_IPV4, "")
        } else {
            IkeIdentity(identityType, identityValue.trim())
        }

    /** What the list and the notification show for a profile the user never named. */
    val displayName: String get() = name.ifBlank { server.ifBlank { DEFAULT_NAME } }

    /**
     * Translates this profile plus its two secrets into the protocol stack's configuration.
     *
     * The secrets are passed in rather than looked up: this class cannot reach [SecretVault], and
     * the single place allowed to resolve them is [SecretReader]. Prefer [buildVpnConfig], which
     * pairs the lookup with wiping the plaintext afterwards.
     *
     * Note that [VpnConfig] holds its two secrets as `String`, so from this call onwards they are
     * immutable heap objects that cannot be wiped. Narrowing that is a change to `:core`, out of
     * this layer's reach.
     *
     * @throws IllegalArgumentException if the profile is invalid; call [validate] first to get
     *   per-field diagnostics instead of an exception.
     */
    fun toVpnConfig(presharedKey: CharArray, password: CharArray): VpnConfig = VpnConfig(
        serverHost = server.trim(),
        presharedKey = String(presharedKey),
        username = username.trim(),
        password = String(password),
        exchangeMode = exchangeMode,
        localIdentity = localIdentity,
        phase1 = Phase1Proposal(
            encryption = phase1Encryption,
            hash = phase1Hash,
            dhGroup = phase1DhGroup,
        ),
        phase2 = Phase2Proposal(
            encryption = phase2Encryption,
            integrity = phase2Integrity,
            pfsGroup = phase2PfsGroup,
        ),
        forceUdpEncapsulation = forceUdpEncapsulation,
        allowedPppAuth = allowedPppAuth,
        mtu = mtu,
        dnsOverride = dnsServerList,
        blockIpv6 = blockIpv6,
        debugLogging = debugLogging,
    )

    /**
     * Written out by hand even though there is no secret left to hide.
     *
     * The generated `toString` of the old data class printed the pre-shared key and the password in
     * full, which is how they reached the in-app log buffer. Keeping an explicit one means adding a
     * secret to this class can no longer leak it by default: the field would simply not be printed,
     * and [VpnProfileTest] fails the build if a secret-shaped property ever appears here at all.
     */
    override fun toString(): String =
        "VpnProfile(id=$id, name=$name, server=$server, username=$username, " +
            "exchangeMode=$exchangeMode, identity=$localIdentity, " +
            "phase1=$phase1Encryption/$phase1Hash/$phase1DhGroup, " +
            "phase2=$phase2Encryption/$phase2Integrity/pfs=$phase2PfsGroup, " +
            "ppp=$allowedPppAuth, mtu=$mtu, dns=$dnsServerList, blockIpv6=$blockIpv6, " +
            "forceUdpEncapsulation=$forceUdpEncapsulation, debugLogging=$debugLogging)"

    companion object {
        const val DEFAULT_NAME: String = "L2TP/IPsec"
        const val DEFAULT_MTU: Int = 1400
        const val MIN_MTU: Int = 576
        const val MAX_MTU: Int = 1500

        val DEFAULT_PPP_AUTH: List<PppAuthProtocol> = listOf(
            PppAuthProtocol.MSCHAP_V2,
            PppAuthProtocol.CHAP_MD5,
            PppAuthProtocol.PAP,
        )

        /**
         * A fresh identity for a profile the user is about to create.
         *
         * Random rather than sequential on purpose: an index would be reused the moment a profile
         * in the middle of the list is deleted, and the next profile to take that index would
         * inherit the deleted one's stored secrets.
         */
        fun newId(): String = UUID.randomUUID().toString()

        /** An empty profile with a fresh [newId], for the "add a connection" flow. */
        fun blank(name: String = DEFAULT_NAME): VpnProfile = VpnProfile(id = newId(), name = name)

        private val DNS_SEPARATORS = Regex("[,;\\s]+")
    }
}

/**
 * Resolves [profile]'s secrets and builds the protocol configuration, wiping the plaintext arrays
 * before returning.
 *
 * This is the whole reason [SecretReader] exists as a separate type: the service is handed one, the
 * UI never is, and this function is the only caller in the app that turns a stored secret back into
 * something readable.
 *
 * @throws IllegalArgumentException if the profile is incomplete — `VpnConfig` rejects an empty
 *   server or pre-shared key. Call [validate] first for per-field diagnostics.
 */
fun buildVpnConfig(profile: VpnProfile, secrets: SecretReader): VpnConfig {
    val psk = secrets.read(profile.id, SecretKind.PRESHARED_KEY) ?: CharArray(0)
    val password = secrets.read(profile.id, SecretKind.PASSWORD) ?: CharArray(0)
    try {
        return profile.toVpnConfig(psk, password)
    } finally {
        psk.wipe()
        password.wipe()
    }
}
