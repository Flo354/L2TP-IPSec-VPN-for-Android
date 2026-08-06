package com.arcan.l2tpvpn.core.ike

import com.arcan.l2tpvpn.core.tunnel.IkeExchangeMode
import com.arcan.l2tpvpn.core.tunnel.Phase2Proposal
import com.arcan.l2tpvpn.core.tunnel.VpnConfig
import java.net.InetAddress

/** Endpoints and credentials shared by the IKE tests. */
object IkeTestFixtures {
    const val PRESHARED_KEY = "correct horse battery staple"
    const val LOCAL_PORT = 34567

    val localAddress: InetAddress = InetAddress.getByName("192.168.1.5")
    val remoteAddress: InetAddress = InetAddress.getByName("203.0.113.7")

    fun config(
        exchangeMode: IkeExchangeMode = IkeExchangeMode.MAIN,
        forceUdpEncapsulation: Boolean = true,
        presharedKey: String = PRESHARED_KEY,
        phase2: Phase2Proposal = Phase2Proposal(),
    ) = VpnConfig(
        serverHost = "vpn.example.com",
        presharedKey = presharedKey,
        username = "user",
        password = "secret",
        exchangeMode = exchangeMode,
        phase2 = phase2,
        forceUdpEncapsulation = forceUdpEncapsulation,
        // The fake responder answers synchronously, so these only bound the failure paths.
        ikeRetransmitTimeoutMs = 50,
        ikeMaxRetransmits = 1,
    )
}

/**
 * An in-memory [IkeTransport]: every datagram the negotiator sends is handed straight to a
 * [FakeIkeResponder] and its reply, if any, is queued for the next receive.
 */
class FakeIkeTransport(
    override val localAddress: InetAddress,
    override val localPort: Int,
    override val remoteAddress: InetAddress,
    private val responder: FakeIkeResponder,
) : IkeTransport {

    override var natTraversalActive = false
        private set

    /** Every datagram the negotiator has sent, in order. */
    val sent = mutableListOf<ByteArray>()

    private val inbox = ArrayDeque<ByteArray>()

    override fun enableNatTraversal() {
        natTraversalActive = true
    }

    override fun sendIsakmp(message: ByteArray) {
        sent += message
        responder.onMessage(message)?.let { inbox.addLast(it) }
    }

    override fun receiveIsakmp(timeoutMs: Int): ByteArray? = inbox.removeFirstOrNull()

    /** The first cleartext message whose header announces [payloadType] as its first payload. */
    fun firstCleartextMessageStartingWith(payloadType: Int): PayloadChain? = sent
        .map { it to IsakmpHeader.decode(it) }
        .firstOrNull { (_, header) -> !header.isEncrypted && header.nextPayload == payloadType }
        ?.let { (raw, header) -> IsakmpCodec.decodeMessage(raw, header) }
}
