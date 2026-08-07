package com.arcansecurity.vpn.l2tpipsec

import com.arcansecurity.vpn.l2tpipsec.core.crypto.DhGroup
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspIntegrity
import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeHash
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeExchangeMode
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeIdentityType
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.PppAuthProtocol
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelErrorKind
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelState

/**
 * Human-readable names for the protocol stack's enums, in the vocabulary a network engineer
 * expects to read on a router's configuration page (`aes256`, `modp2048`, …) rather than the
 * Kotlin identifiers.
 *
 * Kept out of `strings.xml`: these are protocol terms, they are not translated, and the
 * notification, the status card and the dropdowns must all spell them the same way.
 */

val TunnelState.label: String
    get() = when (this) {
        TunnelState.IDLE -> "Disconnected"
        TunnelState.RESOLVING -> "Resolving server"
        TunnelState.IKE_PHASE1 -> "IKE phase 1"
        TunnelState.IKE_PHASE2 -> "IKE phase 2"
        TunnelState.L2TP_TUNNEL -> "L2TP tunnel"
        TunnelState.L2TP_SESSION -> "L2TP session"
        TunnelState.PPP_NEGOTIATION -> "PPP negotiation"
        TunnelState.CONNECTED -> "Connected"
        TunnelState.RECONNECTING -> "Reconnecting"
        TunnelState.DISCONNECTING -> "Disconnecting"
        TunnelState.FAILED -> "Failed"
    }

/** True while the tunnel is going through the handshake. */
val TunnelState.isTransient: Boolean
    get() = this !in setOf(TunnelState.IDLE, TunnelState.CONNECTED, TunnelState.FAILED)

val TunnelErrorKind.label: String
    get() = when (this) {
        TunnelErrorKind.DNS_FAILURE -> "Server name could not be resolved"
        TunnelErrorKind.NETWORK_UNREACHABLE -> "Network unreachable"
        TunnelErrorKind.IKE_NO_RESPONSE -> "No response from the server"
        TunnelErrorKind.IKE_PROPOSAL_REJECTED -> "The server rejected the phase 1 proposal"
        TunnelErrorKind.IKE_AUTH_FAILED -> "Wrong pre-shared key"
        TunnelErrorKind.IPSEC_SA_FAILED -> "IPsec SA could not be established"
        TunnelErrorKind.L2TP_FAILED -> "L2TP negotiation failed"
        TunnelErrorKind.PPP_AUTH_FAILED -> "Wrong user name or password"
        TunnelErrorKind.PPP_FAILED -> "PPP negotiation failed"
        TunnelErrorKind.TUN_UNAVAILABLE -> "The VPN interface could not be created"
        TunnelErrorKind.PEER_DISCONNECTED -> "The server closed the tunnel"
        TunnelErrorKind.INTERNAL -> "Internal error"
    }

val IkeExchangeMode.label: String
    get() = when (this) {
        IkeExchangeMode.MAIN -> "Main mode"
        IkeExchangeMode.AGGRESSIVE -> "Aggressive mode"
    }

val IkeIdentityType.label: String
    get() = when (this) {
        IkeIdentityType.AUTO_IPV4 -> "Automatic (local IPv4)"
        IkeIdentityType.IPV4_ADDR -> "IPv4 address"
        IkeIdentityType.FQDN -> "FQDN"
        IkeIdentityType.USER_FQDN -> "User FQDN (e-mail)"
        IkeIdentityType.KEY_ID -> "Key ID"
    }

val IkeEncryption.label: String
    get() = when (this) {
        IkeEncryption.TRIPLE_DES_CBC -> "3des"
        IkeEncryption.AES_CBC_128 -> "aes128"
        IkeEncryption.AES_CBC_192 -> "aes192"
        IkeEncryption.AES_CBC_256 -> "aes256"
    }

val IkeHash.label: String
    get() = when (this) {
        IkeHash.MD5 -> "md5"
        IkeHash.SHA1 -> "sha1"
        IkeHash.SHA2_256 -> "sha256"
        IkeHash.SHA2_384 -> "sha384"
        IkeHash.SHA2_512 -> "sha512"
    }

val DhGroup.label: String
    get() = when (this) {
        DhGroup.MODP_1024 -> "modp1024 (group 2)"
        DhGroup.MODP_1536 -> "modp1536 (group 5)"
        DhGroup.MODP_2048 -> "modp2048 (group 14)"
    }

val EspEncryption.label: String
    get() = when (this) {
        EspEncryption.ESP_3DES -> "3des"
        EspEncryption.ESP_AES_CBC_128 -> "aes128"
        EspEncryption.ESP_AES_CBC_192 -> "aes192"
        EspEncryption.ESP_AES_CBC_256 -> "aes256"
    }

val EspIntegrity.label: String
    get() = when (this) {
        EspIntegrity.HMAC_MD5_96 -> "md5-96"
        EspIntegrity.HMAC_SHA1_96 -> "sha1-96"
        EspIntegrity.HMAC_SHA2_256_128 -> "sha256-128"
        EspIntegrity.HMAC_SHA2_384_192 -> "sha384-192"
        EspIntegrity.HMAC_SHA2_512_256 -> "sha512-256"
    }

val PppAuthProtocol.label: String
    get() = when (this) {
        PppAuthProtocol.PAP -> "PAP"
        PppAuthProtocol.CHAP_MD5 -> "CHAP-MD5"
        PppAuthProtocol.MSCHAP_V2 -> "MS-CHAPv2"
    }
