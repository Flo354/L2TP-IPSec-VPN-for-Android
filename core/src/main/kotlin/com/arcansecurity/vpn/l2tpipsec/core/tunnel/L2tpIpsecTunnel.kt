package com.arcansecurity.vpn.l2tpipsec.core.tunnel

import com.arcansecurity.vpn.l2tpipsec.core.esp.EspException
import com.arcansecurity.vpn.l2tpipsec.core.esp.EspInboundSa
import com.arcansecurity.vpn.l2tpipsec.core.esp.EspOutboundSa
import com.arcansecurity.vpn.l2tpipsec.core.esp.UdpEncapsulation
import com.arcansecurity.vpn.l2tpipsec.core.ike.IkeTransport
import com.arcansecurity.vpn.l2tpipsec.core.ike.IkeV1Negotiator
import com.arcansecurity.vpn.l2tpipsec.core.ike.NatTraversalFlavor
import com.arcansecurity.vpn.l2tpipsec.core.ike.Phase1Result
import com.arcansecurity.vpn.l2tpipsec.core.ike.Phase2Result
import com.arcansecurity.vpn.l2tpipsec.core.l2tp.L2tpTransport
import com.arcansecurity.vpn.l2tpipsec.core.l2tp.L2tpTunnel
import com.arcansecurity.vpn.l2tpipsec.core.net.UdpDatagram
import com.arcansecurity.vpn.l2tpipsec.core.ppp.PppFrame
import com.arcansecurity.vpn.l2tpipsec.core.ppp.PppProtocol
import com.arcansecurity.vpn.l2tpipsec.core.ppp.PppSession
import com.arcansecurity.vpn.l2tpipsec.core.util.Log
import com.arcansecurity.vpn.l2tpipsec.core.util.VpnLogger
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.UnknownHostException
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Drives one complete L2TP/IPsec connection and then pumps packets through it.
 *
 * The layering, outermost first, is:
 * ```
 * UDP/4500 datagram  <- the only socket we own, protected from the VPN we are building
 *   ESP transport mode (RFC 4303 + RFC 3948 encapsulation)
 *     UDP 1701 -> 1701          <- inner transport-layer datagram; there is NO inner IP header
 *       L2TPv2 data message
 *         PPP frame
 *           the user's IP packet, read from / written to the TUN interface
 * ```
 * [run] blocks on the calling thread until the tunnel terminates; [stop] unblocks it.
 */
class L2tpIpsecTunnel(
    private val config: VpnConfig,
    private val socketFactory: UdpSocketFactory,
    private val tunProvider: TunProvider,
    private val listener: TunnelListener = TunnelListener.NONE,
    private val logger: VpnLogger = VpnLogger.NONE,
    private val clock: Clock = Clock.SYSTEM,
) {
    private val log = Log("Tunnel", logger)
    private val stopRequested = AtomicBoolean(false)

    private val bytesIn = AtomicLong()
    private val bytesOut = AtomicLong()
    private val packetsIn = AtomicLong()
    private val packetsOut = AtomicLong()
    private val lastInboundMs = AtomicLong()

    @Volatile private var connectedSinceMs = 0L
    @Volatile private var socket: UdpSocketChannel? = null
    @Volatile private var tun: TunInterface? = null
    @Volatile private var readerThread: Thread? = null
    @Volatile private var uplinkThread: Thread? = null

    @Volatile
    var state: TunnelState = TunnelState.IDLE
        private set

    val stats: TunnelStats
        get() = TunnelStats(
            bytesIn = bytesIn.get(),
            bytesOut = bytesOut.get(),
            packetsIn = packetsIn.get(),
            packetsOut = packetsOut.get(),
            connectedSinceMs = connectedSinceMs,
        )

    // Datagrams demultiplexed off the single UDP socket by the reader thread.
    private val ikeQueue = ArrayBlockingQueue<ByteArray>(32)
    private val l2tpQueue = ArrayBlockingQueue<ByteArray>(256)

    /** Set by the connect watchdog so the failure can be attributed to the phase that stalled. */
    @Volatile private var stalledIn: TunnelState? = null

    @Volatile private var natTraversal = false
    @Volatile private var espIn: EspInboundSa? = null
    @Volatile private var espOut: EspOutboundSa? = null
    private lateinit var serverAddress: InetAddress
    private lateinit var ikeEndpoint: InetSocketAddress
    private lateinit var natTEndpoint: InetSocketAddress

    fun run() {
        try {
            connectAndPump()
        } catch (e: TunnelException) {
            log.e("tunnel failed: ${e.message}", e)
            setState(TunnelState.FAILED, e.message)
            listener.onFailed(e.kind, e.message ?: e.kind.name, e)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            log.i("tunnel interrupted")
        } catch (e: Exception) {
            // A stalled connect surfaces here as whatever I/O error the watchdog's socket close
            // produced, which says nothing useful. Report the phase that actually stopped making
            // progress instead — that is the difference between "check your PSK" and "check your
            // password".
            val stalled = stalledIn
            if (stalled != null) {
                val message = stallMessage(stalled)
                log.e(message)
                setState(TunnelState.FAILED, message)
                listener.onFailed(kindForStall(stalled), message, e)
            } else {
                log.e("unexpected tunnel error", e)
                setState(TunnelState.FAILED, e.message)
                listener.onFailed(TunnelErrorKind.INTERNAL, e.message ?: e.javaClass.simpleName, e)
            }
        } finally {
            shutdown()
            listener.onDisconnected()
        }
    }

    /** Idempotent and safe to call from any thread. */
    fun stop() {
        if (!stopRequested.compareAndSet(false, true)) return
        log.i("stop requested")
        // Closing the TUN is what unblocks the uplink thread, which is parked in a read that no
        // timeout will ever interrupt. The socket is deliberately left open: the control thread
        // still has to push PPP Terminate, L2TP CDN/StopCCN and the ISAKMP deletes out of it, and
        // without them the server keeps the session alive until its own DPD notices. It closes the
        // socket itself once that is done; the reaper below is only the backstop for a control
        // thread that is wedged somewhere it cannot see the stop flag.
        runCatching { tun?.close() }
        uplinkThread?.interrupt()
        Thread({
            runCatching { Thread.sleep(SHUTDOWN_GRACE_MS) }
            runCatching { socket?.close() }
            readerThread?.interrupt()
        }, "l2tp-vpn-reaper").apply { isDaemon = true }.start()
    }

    // ------------------------------------------------------------------ connection sequence

    private fun connectAndPump() {
        setState(TunnelState.RESOLVING)
        serverAddress = try {
            InetAddress.getByName(config.serverHost)
        } catch (e: UnknownHostException) {
            throw TunnelException(TunnelErrorKind.DNS_FAILURE, "cannot resolve ${config.serverHost}", e)
        }
        ikeEndpoint = InetSocketAddress(serverAddress, config.ikePort)
        natTEndpoint = InetSocketAddress(serverAddress, config.natTraversalPort)

        val sock = socketFactory.open()
        socket = sock
        log.i("socket bound to ${sock.localAddress.hostAddress}:${sock.localPort}, server ${serverAddress.hostAddress}")

        startReaderThread(sock)
        startConnectWatchdog()

        setState(TunnelState.IKE_PHASE1)
        val ikeTransport = SocketIkeTransport(sock)
        val negotiator = IkeV1Negotiator(config, ikeTransport, clock, logger)
        val phase1 = negotiator.establishPhase1()
        log.i(
            "IKE phase 1 up: ${config.phase1.encryption}/${config.phase1.hash}/${config.phase1.dhGroup}, " +
                "nat local=${phase1.localBehindNat} remote=${phase1.remoteBehindNat} flavor=${phase1.natTraversalFlavor}",
        )
        if (phase1.natTraversalFlavor == NatTraversalFlavor.NONE) {
            throw TunnelException(
                TunnelErrorKind.IPSEC_SA_FAILED,
                "the server did not negotiate NAT traversal; an unrooted Android client can only " +
                    "carry ESP inside UDP/4500",
            )
        }
        checkStop()

        setState(TunnelState.IKE_PHASE2)
        val phase2 = negotiator.establishPhase2(phase1)
        if (!phase2.udpEncapsulated) {
            throw TunnelException(
                TunnelErrorKind.IPSEC_SA_FAILED,
                "the server selected plain ESP instead of UDP-encapsulated ESP",
            )
        }
        espOut = EspOutboundSa(
            spi = phase2.outboundSpi,
            encryption = phase2.encryption,
            integrity = phase2.integrity,
            encryptionKey = phase2.outboundEncryptionKey,
            integrityKey = phase2.outboundIntegrityKey,
        )
        espIn = EspInboundSa(
            spi = phase2.inboundSpi,
            encryption = phase2.encryption,
            integrity = phase2.integrity,
            encryptionKey = phase2.inboundEncryptionKey,
            integrityKey = phase2.inboundIntegrityKey,
        )
        log.i(
            "IPsec SA up: in=0x%08x out=0x%08x %s/%s".format(
                phase2.inboundSpi, phase2.outboundSpi, phase2.encryption, phase2.integrity,
            ),
        )
        checkStop()

        val tunnelMtu = Mtu.tunnelMtu(Mtu.DEFAULT_PATH_MTU, phase2.encryption, phase2.integrity, config.mtu)
        log.i("negotiated tunnel MTU: $tunnelMtu")

        setState(TunnelState.L2TP_TUNNEL)
        val l2tp = L2tpTunnel(
            transport = SocketL2tpTransport(),
            hostName = config.l2tpHostName,
            clock = clock,
            logger = logger,
            helloIntervalMs = config.l2tpHelloIntervalMs,
        )
        val sessionInfo = l2tp.connect(config.connectTimeoutMs)
        setState(TunnelState.L2TP_SESSION)
        log.i(
            "L2TP session up: tunnel ${sessionInfo.localTunnelId}->${sessionInfo.remoteTunnelId} " +
                "session ${sessionInfo.localSessionId}->${sessionInfo.remoteSessionId} peer=${sessionInfo.peerHostName}",
        )
        checkStop()

        setState(TunnelState.PPP_NEGOTIATION)
        val ppp = PppSession(
            username = config.username,
            password = config.password,
            allowedAuth = config.allowedPppAuth,
            requestedMru = tunnelMtu,
            send = { protocol, payload -> sendPppFrame(l2tp, protocol, payload, 0, payload.size) },
            clock = clock,
            logger = logger,
        )
        val pppResult = negotiatePpp(l2tp, ppp)
        log.i("PPP up: ${pppResult.localAddress} peer ${pppResult.remoteAddress} dns=${pppResult.dnsServers}")

        val dns = config.dnsOverride.ifEmpty { pppResult.dnsServers }
        val device = tunProvider.establish(
            TunParameters(
                address = pppResult.localAddress,
                prefixLength = 32,
                mtu = tunnelMtu,
                dnsServers = dns,
                blockIpv6 = config.blockIpv6,
            ),
        ) ?: throw TunnelException(TunnelErrorKind.TUN_UNAVAILABLE, "the system refused to create the VPN interface")
        tun = device

        connectedSinceMs = clock.nowMs()
        setState(TunnelState.CONNECTED)
        listener.onConnected(
            TunnelInfo(
                serverAddress = serverAddress.hostAddress ?: config.serverHost,
                assignedAddress = pppResult.localAddress,
                peerAddress = pppResult.remoteAddress,
                dnsServers = dns,
                mtu = tunnelMtu,
                natDetected = phase1.localBehindNat || phase1.remoteBehindNat,
                udpEncapsulated = phase2.udpEncapsulated,
                phase1Description = "${config.phase1.encryption}/${config.phase1.hash}/${config.phase1.dhGroup}",
                phase2Description = "${phase2.encryption}/${phase2.integrity}" +
                    (config.phase2.pfsGroup?.let { "/$it" } ?: "/no-pfs"),
                pppAuthDescription = pppResult.authProtocolUsed?.name ?: "none",
            ),
        )

        startUplinkThread(l2tp, device, tunnelMtu)
        pumpDownlink(l2tp, ppp, device, negotiator, phase1, phase2)
    }

    /** Runs LCP / authentication / IPCP until the session opens, fails, or the deadline expires. */
    private fun negotiatePpp(l2tp: L2tpTunnel, ppp: PppSession): com.arcansecurity.vpn.l2tpipsec.core.ppp.PppResult {
        ppp.start()
        val deadline = clock.nowMs() + config.connectTimeoutMs
        while (!stopRequested.get() && clock.nowMs() < deadline) {
            checkSendAborted()
            val packet = l2tpQueue.poll(100, TimeUnit.MILLISECONDS)
            if (packet != null) {
                when (val received = l2tp.onPacket(packet, 0, packet.size)) {
                    is L2tpTunnel.Received.Data -> {
                        val frame = PppFrame.parse(packet, received.offset, received.length)
                        ppp.onFrame(frame.protocol, packet, frame.payloadOffset, frame.payloadLength)
                    }
                    is L2tpTunnel.Received.Closed ->
                        throw TunnelException(TunnelErrorKind.L2TP_FAILED, "peer closed the session: ${received.reason}")
                    else -> Unit
                }
            }
            ppp.tick()
            l2tp.tick()
            ppp.failure?.let { throw it }
            ppp.result?.let { return it }
        }
        checkStop()
        throw TunnelException(TunnelErrorKind.PPP_FAILED, "PPP negotiation timed out in phase ${ppp.phase}")
    }

    // ------------------------------------------------------------------ packet pumps

    /**
     * Bounds the whole establishment, not just the individual layers. Each layer has its own
     * retransmission budget, and a peer that answers phase 1 and then goes quiet would otherwise
     * keep the user on a spinner for the sum of all of them — a wrong pre-shared key, which
     * strongSwan answers with silence rather than a notify, takes over a minute that way.
     */
    private fun startConnectWatchdog() {
        val deadline = clock.nowMs() + config.connectTimeoutMs
        Thread({
            while (!stopRequested.get() && state != TunnelState.CONNECTED) {
                if (clock.nowMs() >= deadline) {
                    stalledIn = state
                    log.w("connect deadline expired in state $state; aborting")
                    runCatching { socket?.close() }
                    return@Thread
                }
                runCatching { Thread.sleep(200) }
            }
        }, "l2tp-vpn-connect-watchdog").apply { isDaemon = true }.start()
    }

    private fun startReaderThread(sock: UdpSocketChannel) {
        val thread = Thread({
            val buffer = ByteArray(4096)
            var consecutiveFailures = 0
            while (!stopRequested.get()) {
                val datagram = try {
                    sock.receive(buffer, 500).also { consecutiveFailures = 0 }
                } catch (e: Exception) {
                    // Both stop() and the connect watchdog close this socket underneath us. A
                    // closed descriptor fails instantly and forever, so retrying it is a hot spin
                    // that buries the log and pins a core; there is nothing left to read either
                    // way, so leave.
                    if (stopRequested.get() || stalledIn != null) break
                    if (++consecutiveFailures >= MAX_CONSECUTIVE_READ_FAILURES) {
                        log.e("abandoning the socket after $consecutiveFailures failed reads", e)
                        break
                    }
                    log.w("socket read failed", e)
                    continue
                } ?: continue
                try {
                    dispatchInbound(buffer, datagram.length)
                } catch (e: Exception) {
                    log.w("dropping malformed inbound datagram", e)
                }
            }
            log.d { "reader thread finished" }
        }, "l2tp-vpn-reader")
        thread.isDaemon = true
        readerThread = thread
        thread.start()
    }

    private fun dispatchInbound(buffer: ByteArray, length: Int) {
        if (length <= 0) return
        lastInboundMs.set(clock.nowMs())
        if (!natTraversal) {
            // Before the float to UDP/4500 everything arriving is a bare ISAKMP message.
            ikeQueue.offer(buffer.copyOf(length))
            return
        }
        when (UdpEncapsulation.classify(buffer, 0, length)) {
            UdpEncapsulation.Kind.KEEPALIVE -> Unit
            UdpEncapsulation.Kind.IKE -> {
                val marker = UdpEncapsulation.NON_ESP_MARKER.size
                ikeQueue.offer(buffer.copyOfRange(marker, length))
            }
            UdpEncapsulation.Kind.ESP -> {
                val sa = espIn ?: return
                val decapsulated = try {
                    sa.decapsulate(buffer, 0, length)
                } catch (e: EspException) {
                    log.d { "dropping ESP packet: ${e.message}" }
                    return
                }
                val udp = UdpDatagram.parse(decapsulated.payload)
                if (udp.destinationPort != config.l2tpPort) {
                    log.d { "dropping inner datagram for port ${udp.destinationPort}" }
                    return
                }
                bytesIn.addAndGet(length.toLong())
                packetsIn.incrementAndGet()
                val l2tpPacket = decapsulated.payload.copyOfRange(udp.payloadOffset, udp.payloadOffset + udp.payloadLength)
                if (!l2tpQueue.offer(l2tpPacket)) log.w("inbound L2TP queue overflow, dropping packet")
            }
            UdpEncapsulation.Kind.UNKNOWN -> log.d { "dropping unrecognised datagram of $length bytes" }
        }
    }

    private fun startUplinkThread(l2tp: L2tpTunnel, device: TunInterface, mtu: Int) {
        val thread = Thread({
            val ipPacket = ByteArray(mtu + 128)
            val pppScratch = ByteArray(mtu + 256)
            while (!stopRequested.get()) {
                val length = try {
                    device.readPacket(ipPacket)
                } catch (e: Exception) {
                    if (stopRequested.get()) break
                    log.w("TUN read failed", e)
                    break
                }
                if (length <= 0) break
                try {
                    val pppLength = PppFrame.encodeInto(pppScratch, 0, PppProtocol.IPV4, ipPacket, 0, length)
                    sendL2tpPayload(l2tp.encodePppFrame(pppScratch, 0, pppLength))
                } catch (e: Exception) {
                    if (stopRequested.get()) break
                    log.w("failed to forward an outbound packet", e)
                }
            }
            log.d { "uplink thread finished" }
        }, "l2tp-vpn-uplink")
        thread.isDaemon = true
        uplinkThread = thread
        thread.start()
    }

    private fun pumpDownlink(
        l2tp: L2tpTunnel,
        ppp: PppSession,
        device: TunInterface,
        negotiator: IkeV1Negotiator,
        phase1: Phase1Result,
        phase2: Phase2Result,
    ) {
        var lastKeepalive = clock.nowMs()
        var lastStats = clock.nowMs()
        while (!stopRequested.get()) {
            val packet = l2tpQueue.poll(200, TimeUnit.MILLISECONDS)
            if (packet != null) {
                when (val received = l2tp.onPacket(packet, 0, packet.size)) {
                    is L2tpTunnel.Received.Data -> handlePppPacket(packet, received, ppp, device)
                    is L2tpTunnel.Received.Closed -> {
                        log.i("peer closed the L2TP session: ${received.reason}")
                        listener.onFailed(TunnelErrorKind.PEER_DISCONNECTED, received.reason, null)
                        return
                    }
                    else -> Unit
                }
            }

            drainIkeQueue(negotiator, phase1)
            ppp.tick()
            l2tp.tick()
            ppp.failure?.let { throw it }
            if (!ppp.isOpen) throw TunnelException(TunnelErrorKind.PPP_FAILED, "PPP went down (phase ${ppp.phase})")

            val now = clock.nowMs()
            if (now - lastKeepalive >= config.natKeepaliveIntervalMs) {
                sendNatKeepalive()
                lastKeepalive = now
            }
            if (now - lastStats >= 1_000) {
                listener.onStats(stats)
                lastStats = now
            }
        }
        // A clean stop: unwind the stack politely so the server frees its resources immediately.
        runCatching { ppp.terminate("client shutdown") }
        runCatching { l2tp.close() }
        runCatching { negotiator.sendDeleteNotifications(phase1, phase2) }
    }

    private fun handlePppPacket(
        packet: ByteArray,
        received: L2tpTunnel.Received.Data,
        ppp: PppSession,
        device: TunInterface,
    ) {
        val frame = PppFrame.parse(packet, received.offset, received.length)
        if (frame.protocol == PppProtocol.IPV4) {
            device.writePacket(packet, frame.payloadOffset, frame.payloadLength)
        } else {
            ppp.onFrame(frame.protocol, packet, frame.payloadOffset, frame.payloadLength)
        }
    }

    private fun drainIkeQueue(negotiator: IkeV1Negotiator, phase1: Phase1Result) {
        while (true) {
            val message = ikeQueue.poll() ?: return
            try {
                if (!negotiator.handleInformational(phase1, message)) {
                    throw TunnelException(TunnelErrorKind.PEER_DISCONNECTED, "the peer deleted the IPsec SA")
                }
            } catch (e: TunnelException) {
                throw e
            } catch (e: Exception) {
                log.w("ignoring unparsable informational exchange", e)
            }
        }
    }

    // ------------------------------------------------------------------ send helpers

    /** Wraps an L2TP packet in UDP/1701 and ESP and puts it on the wire. */
    private fun sendL2tpPayload(l2tpPacket: ByteArray) {
        val sa = espOut ?: return
        val sock = socket ?: return
        val inner = UdpDatagram.encode(config.l2tpPort, config.l2tpPort, l2tpPacket)
        val esp = sa.encapsulate(inner, nextHeader = 17)
        sock.send(esp, 0, esp.size, natTEndpoint)
        bytesOut.addAndGet(esp.size.toLong())
        packetsOut.incrementAndGet()
    }

    private fun sendPppFrame(l2tp: L2tpTunnel, protocol: Int, payload: ByteArray, offset: Int, length: Int) {
        val frame = PppFrame.encode(protocol, payload, offset, length)
        sendL2tpPayload(l2tp.encodePppFrame(frame))
    }

    /** RFC 3948 section 4: a single 0xFF byte keeps the NAT mapping for UDP/4500 alive. */
    private fun sendNatKeepalive() {
        val sock = socket ?: return
        if (!natTraversal) return
        val payload = UdpEncapsulation.NAT_KEEPALIVE
        runCatching { sock.send(payload, 0, payload.size, natTEndpoint) }
    }

    // ------------------------------------------------------------------ plumbing

    /**
     * The abort signal for the negotiating layers. They each sit in their own retransmission loop
     * and have no idea the tunnel is going away, so the transports they were handed are where a
     * stop request or an expired connect deadline has to become an exception. Relying on the
     * socket close alone is not enough: a socket that merely times out never reports anything, and
     * the layer above would keep retransmitting into the void.
     *
     * Sending stays allowed once a stop is requested, because the polite teardown — PPP Terminate,
     * L2TP CDN/StopCCN, ISAKMP Delete — still has to get out.
     */
    private fun checkReceiveAborted() {
        if (stopRequested.get()) throw InterruptedException("stopped")
        checkSendAborted()
    }

    private fun checkSendAborted() {
        val stalled = stalledIn ?: return
        throw TunnelException(kindForStall(stalled), stallMessage(stalled))
    }

    private fun kindForStall(stalled: TunnelState) = when (stalled) {
        TunnelState.RESOLVING, TunnelState.IKE_PHASE1, TunnelState.IKE_PHASE2 -> TunnelErrorKind.IKE_NO_RESPONSE
        TunnelState.L2TP_TUNNEL, TunnelState.L2TP_SESSION -> TunnelErrorKind.L2TP_FAILED
        TunnelState.PPP_NEGOTIATION -> TunnelErrorKind.PPP_FAILED
        else -> TunnelErrorKind.INTERNAL
    }

    private fun stallMessage(stalled: TunnelState) =
        "the server stopped responding during $stalled (no answer within ${config.connectTimeoutMs / 1000}s)"

    private inner class SocketIkeTransport(private val sock: UdpSocketChannel) : IkeTransport {
        override val localAddress: InetAddress get() = sock.localAddress
        override val localPort: Int get() = sock.localPort
        override val remoteAddress: InetAddress get() = serverAddress
        override val natTraversalActive: Boolean get() = natTraversal

        override fun enableNatTraversal() {
            if (!natTraversal) {
                log.i("floating IKE to UDP/${config.natTraversalPort}")
                natTraversal = true
            }
        }

        override fun sendIsakmp(message: ByteArray) {
            checkSendAborted()
            if (natTraversal) {
                val marker = UdpEncapsulation.NON_ESP_MARKER
                val framed = ByteArray(marker.size + message.size)
                System.arraycopy(marker, 0, framed, 0, marker.size)
                System.arraycopy(message, 0, framed, marker.size, message.size)
                sock.send(framed, 0, framed.size, natTEndpoint)
            } else {
                sock.send(message, 0, message.size, ikeEndpoint)
            }
        }

        override fun receiveIsakmp(timeoutMs: Int): ByteArray? {
            checkReceiveAborted()
            return ikeQueue.poll(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
        }
    }

    private inner class SocketL2tpTransport : L2tpTransport {
        override fun send(packet: ByteArray, offset: Int, length: Int) {
            checkSendAborted()
            sendL2tpPayload(if (offset == 0 && length == packet.size) packet else packet.copyOfRange(offset, offset + length))
        }

        override fun receive(timeoutMs: Int): ByteArray? {
            checkReceiveAborted()
            return l2tpQueue.poll(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
        }
    }

    private fun setState(next: TunnelState, detail: String? = null) {
        state = next
        listener.onStateChanged(next, detail)
    }

    private fun checkStop() {
        if (stopRequested.get()) throw InterruptedException("stopped")
    }

    private fun shutdown() {
        setState(TunnelState.DISCONNECTING)
        runCatching { tun?.close() }
        runCatching { socket?.close() }
        tun = null
        socket = null
        readerThread?.interrupt()
        uplinkThread?.interrupt()
        state = TunnelState.IDLE
    }

    private companion object {
        /** How long the socket outlives a stop request so the teardown messages can leave. */
        const val SHUTDOWN_GRACE_MS = 2_000L

        /** A healthy socket does not fail repeatedly; past this the reader gives up rather than spin. */
        const val MAX_CONSECUTIVE_READ_FAILURES = 16
    }
}
