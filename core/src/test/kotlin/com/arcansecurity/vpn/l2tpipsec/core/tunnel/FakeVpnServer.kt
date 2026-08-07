package com.arcansecurity.vpn.l2tpipsec.core.tunnel

import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspIntegrity
import com.arcansecurity.vpn.l2tpipsec.core.esp.EspException
import com.arcansecurity.vpn.l2tpipsec.core.esp.EspInboundSa
import com.arcansecurity.vpn.l2tpipsec.core.esp.EspOutboundSa
import com.arcansecurity.vpn.l2tpipsec.core.esp.UdpEncapsulation
import com.arcansecurity.vpn.l2tpipsec.core.ike.FakeIkeResponder
import com.arcansecurity.vpn.l2tpipsec.core.ike.IsakmpHeader
import com.arcansecurity.vpn.l2tpipsec.core.ike.PayloadType
import com.arcansecurity.vpn.l2tpipsec.core.l2tp.L2tpAvp
import com.arcansecurity.vpn.l2tpipsec.core.l2tp.L2tpAvpType
import com.arcansecurity.vpn.l2tpipsec.core.l2tp.L2tpCodec
import com.arcansecurity.vpn.l2tpipsec.core.l2tp.L2tpMessageType
import com.arcansecurity.vpn.l2tpipsec.core.l2tp.find
import com.arcansecurity.vpn.l2tpipsec.core.net.UdpDatagram
import com.arcansecurity.vpn.l2tpipsec.core.ppp.PppFrame
import com.arcansecurity.vpn.l2tpipsec.core.ppp.PppProtocol
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketException
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import com.arcansecurity.vpn.l2tpipsec.core.ppp.FakeLns as PppPeer

/**
 * The whole server side of the stack behind a single [UdpSocketChannel], so [L2tpIpsecTunnel] can
 * be driven all the way to [TunnelState.CONNECTED] inside a plain unit test.
 *
 * It reuses the fakes the layer tests already rely on — [FakeIkeResponder] for IKEv1 and
 * [PppPeer] for LCP/authentication/IPCP — and adds the two pieces that only exist once the layers
 * are stacked: RFC 3948 demultiplexing on UDP/4500 and a minimal LNS.
 *
 * Every datagram the client sends is decrypted here with a mirror of the SA it negotiated, so a
 * client that corrupts an ESP packet — for instance by driving one [EspOutboundSa] from two
 * threads — shows up as [espFailures] rather than as a packet that quietly disappears.
 *
 * All of it runs under one lock: a server is a different machine, and its own state machines are
 * no more thread-safe than the client's.
 */
class FakeVpnServer(
    private val presharedKey: String,
    private val clientAddress: InetAddress = InetAddress.getByName("192.168.1.5"),
    private val serverAddress: InetAddress = InetAddress.getByName("203.0.113.7"),
    /** Answers the client's PPP negotiation; the defaults mirror the strongSwan lab. */
    val ppp: PppPeer = PppPeer(username = "u", password = "p", mru = 1350),
    private val espEncryption: EspEncryption = EspEncryption.ESP_AES_CBC_256,
    private val espIntegrity: EspIntegrity = EspIntegrity.HMAC_SHA2_256_128,
) : UdpSocketChannel {

    override val localAddress: InetAddress get() = clientAddress
    override val localPort: Int = 34567

    /** The ISAKMP SA the client is talking on now. A phase-1 rekey replaces it with a fresh one. */
    @Volatile
    var responder = newResponder()
        private set

    /**
     * The ISAKMP SA a phase-1 rekey superseded, kept live exactly as a real router keeps it until
     * it sends its own Delete. One [FakeIkeResponder] cannot stand in for both: the second Main
     * Mode overwrites the cookies and the whole key schedule of the first, so a server built on a
     * single responder simply cannot be talked to on the SA that is being replaced — which is the
     * one every message that matters during a rekey belongs to.
     */
    @Volatile
    var supersededResponder: FakeIkeResponder? = null
        private set

    /**
     * Datagrams to deliver on the SA being replaced the instant the client starts renegotiating
     * phase 1. They are queued ahead of the Main Mode answer, which puts them inside the rekey
     * window by construction rather than by sleeping and hoping.
     */
    @Volatile
    var duringPhase1Rekey: ((FakeIkeResponder) -> List<ByteArray>)? = null

    /** ESP packets the client sent that this server could not authenticate. */
    val espFailures = AtomicInteger()

    /** IP packets that came out of the tunnel, i.e. traffic the client's uplink thread forwarded. */
    val ipPacketsReceived = AtomicInteger()

    val natKeepalives = AtomicInteger()

    /** Control messages received, in order, so a test can assert on the polite teardown. */
    val controlMessages: MutableList<L2tpMessageType> = java.util.Collections.synchronizedList(mutableListOf())

    @Volatile var lastEspFailure: String? = null
        private set

    @Volatile private var closed = false

    /**
     * Answers every inbound data packet with an L2TP HELLO. A HELLO must be acknowledged, and the
     * client emits that ZLB from its downlink pump, which is how a test gets the pump and the
     * uplink thread sending through the same outbound SA at the same time.
     */
    @Volatile var helloAfterEveryDataPacket = false

    /**
     * Fails every ISAKMP send with an I/O error, the way a phone that has just lost its network
     * would, while leaving the data path alone. Lets a test make a rekey fail at once instead of
     * waiting out a retransmission budget.
     */
    @Volatile var isakmpUnreachable = false

    private val inbox = LinkedBlockingQueue<ByteArray>()
    private val lock = Any()

    // ESP, installed once quick mode completes. `inbound` is the SA whose SPI this server chose,
    // i.e. the one the client sends on.
    private var espIn: EspInboundSa? = null
    private var espOut: EspOutboundSa? = null

    // LNS state.
    private val serverTunnelId = 0x4321
    private val serverSessionId = 0x8765
    private var ns = 0
    private var nr = 0
    private var clientTunnelId = 0
    private var clientSessionId = 0

    init {
        ppp.send = { protocol, payload -> sendPpp(protocol, payload) }
    }

    // ------------------------------------------------------------------------ socket surface

    override fun send(data: ByteArray, offset: Int, length: Int, destination: InetSocketAddress) {
        if (closed) throw SocketException("Socket closed")
        val packet = data.copyOfRange(offset, offset + length)
        synchronized(lock) {
            // Port 500 carries bare ISAKMP; only 4500 multiplexes the three RFC 3948 kinds.
            if (destination.port != UdpEncapsulation.PORT) {
                if (isakmpUnreachable) throw SocketException("Network is unreachable")
                onIsakmp(packet, encapsulated = false)
                return@synchronized
            }
            when (UdpEncapsulation.classify(packet, 0, packet.size)) {
                UdpEncapsulation.Kind.KEEPALIVE -> natKeepalives.incrementAndGet()
                UdpEncapsulation.Kind.IKE -> {
                    if (isakmpUnreachable) throw SocketException("Network is unreachable")
                    onIsakmp(packet.copyOfRange(UdpEncapsulation.NON_ESP_MARKER.size, packet.size), true)
                }
                UdpEncapsulation.Kind.ESP -> onEsp(packet)
                UdpEncapsulation.Kind.UNKNOWN -> Unit
            }
        }
    }

    override fun receive(buffer: ByteArray, timeoutMs: Int): Datagram? {
        if (closed) throw SocketException("Socket closed")
        val packet = inbox.poll(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
        if (closed) throw SocketException("Socket closed")
        if (packet == null || packet.size > buffer.size) return null
        System.arraycopy(packet, 0, buffer, 0, packet.size)
        return Datagram(packet.size, InetSocketAddress(serverAddress, UdpEncapsulation.PORT))
    }

    override fun close() {
        closed = true
    }

    // ------------------------------------------------------------------------ test controls

    /** Puts arbitrary bytes where a PPP frame belongs, for the malformed-input paths. */
    fun sendRawPppBytes(bytes: ByteArray) = synchronized(lock) {
        sendEsp(L2tpCodec.encodeData(clientTunnelId, clientSessionId, bytes))
    }

    /** Deletes the ISAKMP SA, which is what makes the client renegotiate phase 1 straight away. */
    fun sendIsakmpDelete() = synchronized(lock) {
        inbox.put(UdpEncapsulation.NON_ESP_MARKER + responder.buildIsakmpDelete())
    }

    /** Tears the control connection down from the server side, as a router rebooting would. */
    fun sendStopCcn() = synchronized(lock) {
        emit(
            L2tpMessageType.StopCCN,
            listOf(
                L2tpAvp.u16(L2tpAvpType.AssignedTunnelId, serverTunnelId),
                L2tpAvp.raw(L2tpAvpType.ResultCode, byteArrayOf(0, 1, 0, 0)),
            ),
        )
    }

    // ------------------------------------------------------------------------ IKE

    private fun onIsakmp(message: ByteArray, encapsulated: Boolean) {
        val header = IsakmpHeader.decode(message)
        // The cookies decide which SA a message belongs to, exactly as they do on the client: for
        // the length of a rekey the two SAs are both live and both being written to.
        val target = supersededResponder?.takeIf { it.owns(header) } ?: currentResponder(header, encapsulated)
        val reply = target.onMessage(message) ?: return
        inbox.put(if (encapsulated) UdpEncapsulation.NON_ESP_MARKER + reply else reply)
    }

    /**
     * The responder that owns the SA [header] belongs to, rotating a fresh one in when the client
     * starts a second Main Mode and handing the SA it is replacing to [duringPhase1Rekey].
     */
    private fun currentResponder(header: IsakmpHeader, encapsulated: Boolean): FakeIkeResponder {
        if (!startsNewPhase1(header)) return responder
        val superseded = responder
        supersededResponder = superseded
        responder = newResponder()
        duringPhase1Rekey?.invoke(superseded)?.forEach {
            inbox.put(if (encapsulated) UdpEncapsulation.NON_ESP_MARKER + it else it)
        }
        return responder
    }

    /**
     * A first phase-1 message carrying cookies we have never keyed. The initiator cookie is what
     * rules out a retransmission of the rekey's own message 1, which would otherwise throw away the
     * half-built SA every time the client repeated itself.
     */
    private fun startsNewPhase1(header: IsakmpHeader): Boolean =
        responder.hasEstablishedSa && !responder.matchesInitiator(header) &&
            !header.isEncrypted && header.nextPayload == PayloadType.SA

    private fun newResponder(): FakeIkeResponder =
        FakeIkeResponder(presharedKey, clientAddress, serverAddress, localPort).also { fresh ->
            fresh.onEspKeysDerived = { installEsp(fresh) }
        }

    /**
     * Switches both ESP directions to the pair [from] has just derived. It is driven by the
     * responder rather than by "the quick mode had nothing to answer", because a Quick Mode this
     * server started ends on a message it *does* answer, and an SA negotiated over the superseded
     * ISAKMP SA is keyed by that responder rather than by the current one.
     */
    private fun installEsp(from: FakeIkeResponder) {
        espIn = EspInboundSa(
            spi = from.inboundSpi,
            encryption = espEncryption,
            integrity = espIntegrity,
            encryptionKey = from.inboundEncryptionKey,
            integrityKey = from.inboundIntegrityKey,
        )
        espOut = EspOutboundSa(
            spi = from.outboundSpi,
            encryption = espEncryption,
            integrity = espIntegrity,
            encryptionKey = from.outboundEncryptionKey,
            integrityKey = from.outboundIntegrityKey,
        )
    }

    // ------------------------------------------------------------------------ ESP

    private fun onEsp(packet: ByteArray) {
        val sa = espIn ?: return
        val decapsulated = try {
            sa.decapsulate(packet)
        } catch (e: EspException) {
            espFailures.incrementAndGet()
            lastEspFailure = e.message
            return
        }
        val udp = try {
            UdpDatagram.parse(decapsulated.payload)
        } catch (e: Exception) {
            espFailures.incrementAndGet()
            lastEspFailure = "inner datagram: ${e.message}"
            return
        }
        onL2tp(decapsulated.payload, udp.payloadOffset, udp.payloadLength)
    }

    private fun sendEsp(l2tpPacket: ByteArray) {
        val sa = espOut ?: return
        inbox.put(sa.encapsulate(UdpDatagram.encode(1701, 1701, l2tpPacket), nextHeader = 17))
    }

    // ------------------------------------------------------------------------ LNS

    private fun onL2tp(buffer: ByteArray, offset: Int, length: Int) {
        val (header, payloadOffset) = L2tpCodec.parseHeader(buffer, offset, length)
        if (!header.isControl) {
            onPppFrame(buffer, payloadOffset, header.payloadLength)
            return
        }
        val avps = L2tpCodec.parseAvps(buffer, payloadOffset, header.payloadLength)
        if (avps.isEmpty()) return // ZLB: acknowledgement only, consumes no sequence number.
        if (header.ns != nr) {
            emitZlb()
            return
        }
        nr = (nr + 1) and 0xFFFF
        val type = avps.find(L2tpAvpType.MessageType)?.let { L2tpMessageType.of(it.asU16()) }
        type?.let { controlMessages += it }
        when (type) {
            L2tpMessageType.SCCRQ -> {
                clientTunnelId = avps.find(L2tpAvpType.AssignedTunnelId)!!.asU16()
                emit(L2tpMessageType.SCCRP, sccrpAvps())
            }

            L2tpMessageType.ICRQ -> {
                clientSessionId = avps.find(L2tpAvpType.AssignedSessionId)!!.asU16()
                emit(
                    L2tpMessageType.ICRP,
                    listOf(L2tpAvp.u16(L2tpAvpType.AssignedSessionId, serverSessionId)),
                    sessionId = clientSessionId,
                )
            }

            else -> emitZlb()
        }
    }

    private fun sccrpAvps(): List<L2tpAvp> = listOf(
        L2tpAvp.u16(L2tpAvpType.ProtocolVersion, 0x0100),
        L2tpAvp.u32(L2tpAvpType.FramingCapabilities, 3),
        L2tpAvp.u32(L2tpAvpType.BearerCapabilities, 3),
        L2tpAvp.text(L2tpAvpType.HostName, "fake-lns"),
        L2tpAvp.u16(L2tpAvpType.AssignedTunnelId, serverTunnelId),
        L2tpAvp.u16(L2tpAvpType.ReceiveWindowSize, 8),
    )

    private fun emit(type: L2tpMessageType, avps: List<L2tpAvp>, sessionId: Int = 0) {
        val packet = L2tpCodec.encodeControl(
            clientTunnelId,
            sessionId,
            ns,
            nr,
            listOf(L2tpAvp.u16(L2tpAvpType.MessageType, type.code)) + avps,
        )
        ns = (ns + 1) and 0xFFFF
        sendEsp(packet)
    }

    private fun emitZlb() = sendEsp(L2tpCodec.encodeControl(clientTunnelId, 0, ns, nr, emptyList()))

    // ------------------------------------------------------------------------ PPP

    private fun onPppFrame(buffer: ByteArray, offset: Int, length: Int) {
        val frame = PppFrame.parse(buffer, offset, length)
        val payload = buffer.copyOfRange(frame.payloadOffset, frame.payloadOffset + frame.payloadLength)
        if (frame.protocol != PppProtocol.IPV4) {
            ppp.onFrame(frame.protocol, payload)
            return
        }
        ipPacketsReceived.incrementAndGet()
        // Reflect the packet so the client's downlink pump has something to do, which is what
        // keeps both of its senders busy at once.
        sendPpp(PppProtocol.IPV4, payload)
        if (helloAfterEveryDataPacket) emit(L2tpMessageType.HELLO, emptyList())
    }

    private fun sendPpp(protocol: Int, payload: ByteArray) {
        sendEsp(
            L2tpCodec.encodeData(
                clientTunnelId,
                clientSessionId,
                PppFrame.encode(protocol, payload),
            ),
        )
    }
}
