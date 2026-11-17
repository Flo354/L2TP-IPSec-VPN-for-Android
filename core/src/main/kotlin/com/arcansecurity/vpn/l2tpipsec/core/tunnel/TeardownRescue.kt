package com.arcansecurity.vpn.l2tpipsec.core.tunnel

import java.net.InetAddress

/**
 * The part of a tunnel's teardown the server never acknowledged, kept so the next connection
 * attempt to the same server can deliver it.
 *
 * The case it exists for is a network handover. By the time the platform reports that Wi-Fi has
 * gone, the old tunnel's PPP Terminate, L2TP CDN/StopCCN and ISAKMP Deletes have nowhere left to
 * go: sent from the old socket, they either die with the interface or leave through the new one
 * from an address the server has no SA for. The server keeps the session until its own keepalives
 * time out, and a Livebox in that state has been seen to accept the next attempt's L2TP session
 * and then never start PPP on it.
 *
 * None of these messages is tied to the address it was first sent from. An L2TP control message
 * names its tunnel by id, and ISAKMP names its SA by cookies, so the next attempt can carry them —
 * the L2TP ones inside its own fresh IPsec SA, the ISAKMP ones as they are — before it opens a
 * tunnel of its own.
 *
 * Opaque outside the stack: [L2tpIpsecTunnel.leftover] produces one and the next tunnel's
 * constructor consumes it.
 */
class TeardownRescue internal constructor(
    /** The server the messages belong to; a rescue is only ever delivered back to it. */
    val serverAddress: InetAddress,
    /** Encoded L2TP control messages, oldest first, to be sent through a new IPsec SA. */
    internal val l2tpMessages: List<ByteArray>,
    /** Encrypted ISAKMP Informational messages, without the RFC 3948 non-ESP marker. */
    internal val isakmpMessages: List<ByteArray>,
    /** [Clock] time at which the teardown was given up on. */
    val capturedAtMs: Long,
) {
    override fun toString(): String =
        "TeardownRescue(server=${serverAddress.hostAddress}, l2tp=${l2tpMessages.size}, " +
            "isakmp=${isakmpMessages.size}, capturedAtMs=$capturedAtMs)"
}
