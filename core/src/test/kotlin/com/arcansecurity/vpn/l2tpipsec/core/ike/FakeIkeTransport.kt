package com.arcansecurity.vpn.l2tpipsec.core.ike

import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeExchangeMode
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.Phase2Proposal
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.VpnConfig
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

    /**
     * Datagrams the negotiator handed back because they belong to another ISAKMP SA. A tunnel
     * parks these until the rekey that is running finishes; here they are only recorded, so a test
     * can tell "given back" from "silently dropped".
     */
    val deferred = mutableListOf<ByteArray>()

    /** Records outbound datagrams but never shows them to the responder, modelling a dead path. */
    var dropOutbound = false

    private val inbox = ArrayDeque<ByteArray>()
    private val injected = ArrayDeque<ByteArray>()

    override fun enableNatTraversal() {
        natTraversalActive = true
    }

    /**
     * Queues [message] so it is delivered *before* whatever the responder answers next with. Real
     * peers reorder: an informational the peer had already sent routinely overtakes the reply we
     * are waiting for.
     */
    fun deliverBeforeNextReply(message: ByteArray) {
        injected.addLast(message)
    }

    override fun sendIsakmp(message: ByteArray) {
        sent += message
        while (injected.isNotEmpty()) inbox.addLast(injected.removeFirst())
        if (dropOutbound) return
        responder.onMessage(message)?.let { inbox.addLast(it) }
    }

    override fun receiveIsakmp(timeoutMs: Int): ByteArray? = inbox.removeFirstOrNull()

    override fun deferForeignMessage(message: ByteArray) {
        deferred += message
    }

    /** The first cleartext message whose header announces [payloadType] as its first payload. */
    fun firstCleartextMessageStartingWith(payloadType: Int): PayloadChain? = sent
        .map { it to IsakmpHeader.decode(it) }
        .firstOrNull { (_, header) -> !header.isEncrypted && header.nextPayload == payloadType }
        ?.let { (raw, header) -> IsakmpCodec.decodeMessage(raw, header) }
}
