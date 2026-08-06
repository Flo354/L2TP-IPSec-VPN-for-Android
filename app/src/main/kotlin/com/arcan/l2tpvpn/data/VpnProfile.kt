package com.arcan.l2tpvpn.data

import com.arcan.l2tpvpn.core.crypto.DhGroup
import com.arcan.l2tpvpn.core.crypto.EspEncryption
import com.arcan.l2tpvpn.core.crypto.EspIntegrity
import com.arcan.l2tpvpn.core.crypto.IkeEncryption
import com.arcan.l2tpvpn.core.crypto.IkeHash
import com.arcan.l2tpvpn.core.tunnel.IkeExchangeMode
import com.arcan.l2tpvpn.core.tunnel.IkeIdentity
import com.arcan.l2tpvpn.core.tunnel.IkeIdentityType
import com.arcan.l2tpvpn.core.tunnel.Phase1Proposal
import com.arcan.l2tpvpn.core.tunnel.Phase2Proposal
import com.arcan.l2tpvpn.core.tunnel.PppAuthProtocol
import com.arcan.l2tpvpn.core.tunnel.VpnConfig

/**
 * The user-editable half of a [VpnConfig].
 *
 * [VpnConfig] carries a fair number of protocol timers that nobody should have to think about;
 * this class keeps only what a person configuring a road-warrior tunnel actually needs, in the
 * shape the UI edits it (free text for the DNS list, a nullable PFS group, …), and [toVpnConfig]
 * performs the translation.
 *
 * Every default here is the one that works against the target hardware: IKEv1 main mode,
 * `aes256-sha256-modp2048` for phase 1, `aes256-sha256` with no PFS for phase 2, forced UDP
 * encapsulation (Android cannot open raw ESP sockets) and an MTU of 1400.
 *
 * The class is deliberately free of Android types so that it can be unit-tested on a plain JVM.
 */
data class VpnProfile(
    /** Display name; also used as the `VpnService.Builder` session label. */
    val name: String = DEFAULT_NAME,
    /** Host name or literal IPv4 address of the VPN concentrator. */
    val server: String = "",
    /** IKE pre-shared key. Stored encrypted, never logged. */
    val presharedKey: String = "",
    /** PPP user name. */
    val username: String = "",
    /** PPP password. Stored encrypted, never logged. */
    val password: String = "",

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

    /**
     * Translates this profile into the protocol stack's configuration.
     *
     * @throws IllegalArgumentException if the profile is invalid; call [validate] first to get
     *   per-field diagnostics instead of an exception.
     */
    fun toVpnConfig(): VpnConfig = VpnConfig(
        serverHost = server.trim(),
        presharedKey = presharedKey,
        username = username.trim(),
        password = password,
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

    /** Never let a PSK or a password reach the log buffer. */
    override fun toString(): String =
        "VpnProfile(name=$name, server=$server, username=$username, psk=***, password=***, " +
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

        private val DNS_SEPARATORS = Regex("[,;\\s]+")
    }
}
