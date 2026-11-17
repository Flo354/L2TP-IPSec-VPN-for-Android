package com.arcansecurity.vpn.l2tpipsec.core.tunnel

import com.arcansecurity.vpn.l2tpipsec.core.e2e.FakeTun
import com.arcansecurity.vpn.l2tpipsec.core.e2e.FakeTunProvider
import com.arcansecurity.vpn.l2tpipsec.core.ike.FakeIkeResponder
import com.arcansecurity.vpn.l2tpipsec.core.ike.NotifyType
import com.arcansecurity.vpn.l2tpipsec.core.ike.ProtocolId
import com.arcansecurity.vpn.l2tpipsec.core.l2tp.L2tpMessageType
import com.arcansecurity.vpn.l2tpipsec.core.util.ByteReader
import com.arcansecurity.vpn.l2tpipsec.core.util.VpnLogger
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.After
import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import com.arcansecurity.vpn.l2tpipsec.core.ppp.FakeLns as PppPeer

/**
 * Drives the orchestrator all the way to [TunnelState.CONNECTED] against [FakeVpnServer], which is
 * the only way to reach the code that only exists once every layer is stacked: the two send paths
 * that share one outbound SA, the thread set the tunnel owns while it is up, and the teardown.
 */
class L2tpIpsecTunnelLoopbackTest {

    private val started = mutableListOf<L2tpIpsecTunnel>()

    @After
    fun stopEverything() {
        started.forEach { runCatching { it.stop() } }
    }

    private class Recorder : TunnelListener {
        val connected = CountDownLatch(1)
        val finished = CountDownLatch(1)
        @Volatile var info: TunnelInfo? = null
        @Volatile var kind: TunnelErrorKind? = null
        @Volatile var message: String? = null

        override fun onConnected(info: TunnelInfo) {
            this.info = info
            connected.countDown()
        }

        override fun onFailed(kind: TunnelErrorKind, message: String, cause: Throwable?) {
            this.kind = kind
            this.message = message
        }

        override fun onDisconnected() = finished.countDown()
    }

    private fun config(helloIntervalMs: Int = 60_000) = VpnConfig(
        serverHost = SERVER,
        presharedKey = PSK,
        username = "u",
        password = "p",
        connectTimeoutMs = 20_000,
        ikeRetransmitTimeoutMs = 1_000,
        ikeMaxRetransmits = 3,
        l2tpHelloIntervalMs = helloIntervalMs,
    )

    private fun start(
        server: FakeVpnServer,
        config: VpnConfig = config(),
    ): Triple<L2tpIpsecTunnel, Recorder, FakeTunProvider> {
        val recorder = Recorder()
        val provider = FakeTunProvider()
        val tunnel = L2tpIpsecTunnel(
            config = config,
            socketFactory = { server },
            tunProvider = provider,
            listener = recorder,
            logger = VpnLogger.NONE,
        )
        started += tunnel
        Thread({ tunnel.run() }, "loopback-tunnel").apply { isDaemon = true }.start()
        assertTrue(
            "tunnel did not connect: ${recorder.kind} ${recorder.message}",
            recorder.connected.await(30, TimeUnit.SECONDS),
        )
        return Triple(tunnel, recorder, provider)
    }

    @Test
    fun `connects through the whole stack and carries traffic both ways`() {
        val server = FakeVpnServer(PSK, ppp = peer(primaryDns = "10.10.10.1", secondaryDns = "10.10.10.1"))
        val (tunnel, _, provider) = start(server)

        val tun = provider.established!!
        assertEquals("10.10.10.100", tun.params.address)
        // The header budget alone would allow 1400; the peer asked for 1350 and must win.
        assertEquals(1350, tun.params.mtu)
        assertEquals("a resolver pushed twice must be installed once", listOf("10.10.10.1"), tun.params.dnsServers)

        val packet = ipPacket(7)
        tun.inject(packet)
        val echoed = tun.awaitInbound(10_000)
        assertNotNull("the packet never came back through the tunnel", echoed)
        assertTrue(packet.contentEquals(echoed!!))
        assertEquals(0, server.espFailures.get())
        assertTrue(tunnel.stats.bytesOut > 0)
        assertTrue(tunnel.stats.bytesIn > 0)
    }

    /**
     * The uplink thread and the downlink pump both encrypt with the same [EspOutboundSa]. That SA
     * holds one `Mac`, so if the tunnel lets both threads into it the ICV comes out computed over
     * an interleaving of two packets and the server drops them.
     */
    @Test
    fun `the uplink thread and the downlink pump never corrupt the outbound sa`() {
        val server = FakeVpnServer(PSK, ppp = peer())
        // A HELLO per data packet makes the pump answer every uplink packet with a ZLB, so both
        // senders are inside the outbound SA at the same time for the whole test.
        server.helloAfterEveryDataPacket = true
        val (_, _, provider) = start(server, config(helloIntervalMs = 0))

        val tun = provider.established!!
        repeat(PACKETS) { tun.inject(ipPacket(it)) }

        val deadline = System.currentTimeMillis() + 30_000
        while (System.currentTimeMillis() < deadline && server.ipPacketsReceived.get() < PACKETS) {
            Thread.sleep(20)
        }
        assertEquals(
            "the server could not authenticate ESP the client sent (${server.lastEspFailure})",
            0,
            server.espFailures.get(),
        )
        assertEquals(
            "packets went missing between the TUN and the server",
            PACKETS,
            server.ipPacketsReceived.get(),
        )
    }

    /** Every thread the tunnel creates must be gone once [L2tpIpsecTunnel.run] returns. */
    @Test
    fun `a stopped tunnel leaves no threads behind and says goodbye first`() {
        val server = FakeVpnServer(PSK, ppp = peer())
        val before = vpnThreads()
        val (tunnel, recorder, _) = start(server)

        tunnel.stop()
        assertTrue("stop() must unblock run()", recorder.finished.await(20, TimeUnit.SECONDS))
        assertTrue(
            "the LNS never saw the session torn down: ${server.controlMessages}",
            server.controlMessages.contains(L2tpMessageType.CDN) &&
                server.controlMessages.contains(L2tpMessageType.StopCCN),
        )
        awaitNoNewVpnThreads(before)
    }

    /**
     * A tunnel that dies on its own never goes through [L2tpIpsecTunnel.stop], so nothing else can
     * be relied on to wind its threads down.
     */
    @Test
    fun `a peer-initiated disconnect also leaves no threads behind`() {
        val server = FakeVpnServer(PSK, ppp = peer())
        val before = vpnThreads()
        val (tunnel, recorder, _) = start(server)

        server.sendStopCcn()
        assertTrue("the tunnel ignored the StopCCN", recorder.finished.await(20, TimeUnit.SECONDS))
        assertEquals(TunnelErrorKind.PEER_DISCONNECTED, recorder.kind)
        // A caller that polls `state` must see the same thing the listener was told, not a clean
        // IDLE that erases the reason the tunnel went away.
        assertEquals(TunnelState.FAILED, tunnel.state)
        awaitNoNewVpnThreads(before)
    }

    /**
     * The pump parses inbound PPP itself, so a runt frame used to throw straight out of it and
     * take a working tunnel down with it.
     */
    @Test
    fun `a malformed ppp frame is dropped instead of killing the tunnel`() {
        val server = FakeVpnServer(PSK, ppp = peer())
        val (tunnel, recorder, provider) = start(server)
        val tun = provider.established!!

        // Empty, no protocol field, an odd byte that claims protocol compression and then nothing,
        // and a two-byte protocol field cut in half.
        server.sendRawPppBytes(ByteArray(0))
        server.sendRawPppBytes(byteArrayOf(0xFF.toByte(), 0x03))
        server.sendRawPppBytes(byteArrayOf(0xFF.toByte(), 0x03, 0x00))
        server.sendRawPppBytes(byteArrayOf(0x00))

        val packet = ipPacket(11)
        tun.inject(packet)
        val echoed = tun.awaitInbound(10_000)
        assertNotNull("the tunnel stopped carrying traffic after a malformed frame", echoed)
        assertTrue(packet.contentEquals(echoed!!))
        assertEquals(null, recorder.kind)
        assertEquals(TunnelState.CONNECTED, tunnel.state)
    }

    /**
     * A connect that fails on its own is not a stop, so nothing raises the stop flag for it. The
     * watchdog in particular used to keep polling for the rest of the connect timeout and then
     * condemn a tunnel that had been dead for half a minute.
     */
    @Test
    fun `a connect that fails before it completes takes its watchdog with it`() {
        val server = FakeVpnServer(PSK, ppp = PppPeer(username = "u", password = "p", refuseCredentials = true))
        val before = vpnThreads()
        val recorder = Recorder()
        val tunnel = L2tpIpsecTunnel(
            config = config().copy(connectTimeoutMs = 60_000),
            socketFactory = { server },
            tunProvider = FakeTunProvider(),
            listener = recorder,
            logger = VpnLogger.NONE,
        )
        started += tunnel
        Thread({ tunnel.run() }, "loopback-auth-failure").apply { isDaemon = true }.start()

        assertTrue("the tunnel never gave up", recorder.finished.await(30, TimeUnit.SECONDS))
        assertEquals(TunnelErrorKind.PPP_AUTH_FAILED, recorder.kind)
        assertEquals(TunnelState.FAILED, tunnel.state)
        awaitNoNewVpnThreads(before)
    }

    /**
     * A failed ISAKMP rekey must back off the ISAKMP schedule. Sending it to the IPsec deadline
     * instead leaves the ISAKMP attempt due — so it is retried every maintenance pass — and
     * replaces a healthy IPsec SA fifteen seconds later for no reason at all.
     */
    @Test
    fun `a failed isakmp rekey backs off the isakmp schedule and not the ipsec one`() {
        val server = FakeVpnServer(PSK, ppp = peer())
        val (tunnel, recorder, _) = start(server)

        // Fail the renegotiation the peer's Delete triggers, then let the network come back.
        server.isakmpUnreachable = true
        server.sendIsakmpDelete()
        Thread.sleep(1_500)
        server.isakmpUnreachable = false

        val deadline = System.currentTimeMillis() + 25_000
        while (System.currentTimeMillis() < deadline && tunnel.stats.ikeRekeys < 1) {
            assertEquals("the tunnel died instead of retrying: ${recorder.message}", null, recorder.kind)
            Thread.sleep(200)
        }
        assertEquals("the ISAKMP rekey was never retried", 1L, tunnel.stats.ikeRekeys)
        assertEquals(
            "a failed ISAKMP rekey must not drag the IPsec SA down with it",
            0L,
            tunnel.stats.ipsecRekeys,
        )
    }

    /**
     * A phase-1 rekey runs a whole Main Mode on the maintenance thread, and that thread is the only
     * consumer of the inbound ISAKMP queue — so for the length of the rekey the *new* negotiator is
     * the one draining it, and a DPD probe for the still-live old SA is addressed to cookies it does
     * not have and encrypted under keys it cannot derive. A peer that hears nothing back for the few
     * round trips a Main Mode takes concludes the tunnel is dead and tears it down.
     */
    @Test
    fun `a dpd probe for the old sa sent during a phase 1 rekey is still answered`() {
        val server = FakeVpnServer(PSK, ppp = peer())
        val (tunnel, recorder, _) = start(server)

        server.duringPhase1Rekey = { old -> listOf(old.buildDpdRequest(DPD_SEQUENCE)) }
        server.sendIsakmpDelete()

        val old = awaitSupersededSa(server)
        // Reaching the old responder at all is the proof the answer was authenticated with the old
        // SA's keys: it is keyed for that SA alone and would not decode anything else.
        await("the DPD probe sent during the rekey was never acknowledged") {
            old.receivedNotifyTypes.contains(NotifyType.DPD_R_U_THERE_ACK)
        }
        val ack = old.receivedNotifies.first { it.notifyType == NotifyType.DPD_R_U_THERE_ACK }
        assertEquals(
            "the acknowledgement must echo the sequence of the probe it answers",
            DPD_SEQUENCE.toLong(),
            ByteReader(ack.data).u32(),
        )
        assertEquals("the tunnel died during the rekey: ${recorder.message}", null, recorder.kind)
        assertEquals(1L, tunnel.stats.ikeRekeys)
    }

    /**
     * The same window, with a Delete in it. Losing it leaves the client encrypting into an IPsec SA
     * the peer has already thrown away, which looks exactly like a tunnel that is up and carrying
     * nothing.
     */
    @Test
    fun `an ipsec delete that arrives during a phase 1 rekey is not lost`() {
        val server = FakeVpnServer(PSK, ppp = peer())
        val (tunnel, recorder, _) = start(server)

        // A Delete names the sender's own inbound SPIs, which are the ones we send on.
        server.duringPhase1Rekey = { old -> listOf(old.buildEspDelete(old.inboundSpi)) }
        server.sendIsakmpDelete()

        await("the delete was dropped: the IPsec SA the peer retired was never replaced") {
            tunnel.stats.ipsecRekeys >= 1
        }
        assertEquals("the tunnel died during the rekey: ${recorder.message}", null, recorder.kind)
        assertEquals(1L, tunnel.stats.ikeRekeys)
    }

    /**
     * And with a Quick Mode in it. It arrives on the superseded ISAKMP SA, so only that SA's
     * negotiator can answer it — and both ends have to end up on the same ESP pair, or the tunnel
     * goes quiet without ever reporting a failure.
     */
    @Test
    fun `a peer initiated quick mode that arrives during a phase 1 rekey is answered`() {
        val server = FakeVpnServer(PSK, ppp = peer())
        val (tunnel, recorder, provider) = start(server)

        server.duringPhase1Rekey = { old -> listOf(old.startQuickMode()) }
        server.sendIsakmpDelete()

        await("the quick mode the peer started during the rekey went unanswered") {
            tunnel.stats.ipsecRekeys >= 1
        }
        assertEquals("the tunnel died during the rekey: ${recorder.message}", null, recorder.kind)
        assertEquals(1L, tunnel.stats.ikeRekeys)

        val tun = provider.established!!
        val packet = ipPacket(23)
        tun.inject(packet)
        val echoed = tun.awaitInbound(10_000)
        assertNotNull("the two ends did not agree on the SA the peer negotiated", echoed)
        assertTrue(packet.contentEquals(echoed!!))
    }

    // ------------------------------------------------------------------------------- teardown

    /**
     * A connect that fails after the L2TP session is up used to leave everything it had built on
     * the server: the IPsec SA, the tunnel, the session. Every automatic retry added another set.
     */
    @Test
    fun `a connect refused at ppp still tears down everything it built`() {
        val server = FakeVpnServer(PSK, ppp = PppPeer(username = "u", password = "p", refuseCredentials = true))
        val (tunnel, recorder) = launch(server, rescue = null)

        assertTrue("the tunnel never gave up", recorder.finished.await(30, TimeUnit.SECONDS))
        assertEquals(TunnelErrorKind.PPP_AUTH_FAILED, recorder.kind)
        assertTrue(
            "the LNS never saw the failed session torn down: ${server.controlMessages}",
            server.controlMessages.containsAll(listOf(L2tpMessageType.CDN, L2tpMessageType.StopCCN)),
        )
        assertTrue(
            "the IPsec and ISAKMP SAs were left on the server",
            server.responder.receivedDeleteProtocols.containsAll(listOf(ProtocolId.ESP, ProtocolId.ISAKMP)),
        )
        assertNull("an acknowledged teardown leaves nothing for the next attempt", tunnel.leftover)
    }

    /**
     * Disconnect pressed while PPP is still negotiating — what a user does with a reconnect that
     * hangs. checkStop() reports that as an InterruptedException, and the teardown has to survive
     * the interrupt run() re-asserts for it.
     */
    @Test
    fun `a stop while ppp is still negotiating tears down what was built`() {
        val server = FakeVpnServer(PSK, ppp = peer())
        server.pppSilent = true
        val (tunnel, recorder) = launch(server, rescue = null)
        await("the tunnel never reached PPP") { tunnel.state == TunnelState.PPP_NEGOTIATION }

        tunnel.stop()

        assertTrue("stop() must unblock run()", recorder.finished.await(20, TimeUnit.SECONDS))
        assertTrue(
            "the LNS never saw the abandoned session torn down: ${server.controlMessages}",
            server.controlMessages.containsAll(listOf(L2tpMessageType.CDN, L2tpMessageType.StopCCN)),
        )
        assertTrue(server.responder.receivedDeleteProtocols.contains(ProtocolId.ISAKMP))
        assertNull(tunnel.leftover)
    }

    /**
     * The handover. The old tunnel's teardown goes out of a socket whose network has gone, so the
     * server never hears it and keeps the session; the next attempt, from a new socket, has to
     * deliver it — the L2TP part inside its own new SA, ahead of its own SCCRQ.
     */
    @Test
    fun `a teardown lost with the network is delivered by the next attempt through its own sa`() {
        val server = FakeVpnServer(PSK, ppp = peer())
        val (first, firstRecorder, _) = start(server)
        val oldIke = server.responder

        server.primaryEndpoint.unreachable = true
        first.stop()
        assertTrue(firstRecorder.finished.await(20, TimeUnit.SECONDS))
        assertFalse("nothing should have reached the server", server.controlMessages.contains(L2tpMessageType.StopCCN))
        val leftover = first.leftover
        assertNotNull("a teardown nobody acknowledged must be kept for the next attempt", leftover)

        val endpoint = server.newEndpoint()
        val (second, recorder) = launch(server, rescue = leftover, socket = endpoint)
        assertTrue(
            "the next attempt did not connect: ${recorder.kind} ${recorder.message}",
            recorder.connected.await(30, TimeUnit.SECONDS),
        )

        val log = server.controlLog.toList()
        val oldTunnel = log.first().first
        val newTunnel = log.last { it.second == L2tpMessageType.SCCRQ }.first
        assertNotEquals("the second attempt must have opened a tunnel of its own", oldTunnel, newTunnel)
        val cdn = log.indexOf(oldTunnel to L2tpMessageType.CDN)
        val stopCcn = log.indexOf(oldTunnel to L2tpMessageType.StopCCN)
        val sccrq = log.indexOf(newTunnel to L2tpMessageType.SCCRQ)
        assertTrue("the old tunnel was never closed: $log", cdn >= 0 && stopCcn > cdn)
        assertTrue("the old tunnel must be closed before the new one is opened: $log", stopCcn < sccrq)
        assertTrue(
            "the old SAs were never deleted",
            oldIke.receivedDeleteProtocols.containsAll(listOf(ProtocolId.ESP, ProtocolId.ISAKMP)),
        )

        val tun = provider(second)
        val packet = ipPacket(31)
        tun.inject(packet)
        assertNotNull("the new tunnel does not carry traffic", tun.awaitInbound(10_000))

        second.stop()
        assertTrue(recorder.finished.await(20, TimeUnit.SECONDS))
        assertNull("a delivered rescue must not be handed on again", second.leftover)
    }

    @Test
    fun `a rescue meant for another server is not delivered`() {
        val server = FakeVpnServer(PSK, ppp = peer())
        val foreign = TeardownRescue(
            serverAddress = InetAddress.getByName("198.51.100.1"),
            l2tpMessages = listOf(ByteArray(12)),
            isakmpMessages = emptyList(),
            capturedAtMs = System.currentTimeMillis(),
        )
        val (tunnel, recorder) = launch(server, rescue = foreign)

        assertTrue(recorder.connected.await(30, TimeUnit.SECONDS))
        assertEquals("the LNS received something that was not this attempt's", L2tpMessageType.SCCRQ, server.controlLog.first().second)
        tunnel.stop()
        assertTrue(recorder.finished.await(20, TimeUnit.SECONDS))
        assertNull(tunnel.leftover)
    }

    @Test
    fun `a rescue the attempt never got far enough to deliver is handed on`() {
        val server = FakeVpnServer(PSK, ppp = peer())
        server.isakmpUnreachable = true
        val pending = TeardownRescue(
            serverAddress = InetAddress.getByName(SERVER),
            l2tpMessages = listOf(ByteArray(12)),
            isakmpMessages = emptyList(),
            capturedAtMs = System.currentTimeMillis(),
        )
        val (tunnel, recorder) = launch(server, rescue = pending)

        assertTrue("the tunnel never gave up", recorder.finished.await(30, TimeUnit.SECONDS))
        assertSame(pending, tunnel.leftover)
    }

    // ------------------------------------------------------------------------------- helpers

    private fun await(message: String, timeoutMs: Long = 25_000, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return
            Thread.sleep(50)
        }
        throw AssertionError(message)
    }

    /** The server's view of the ISAKMP SA the client has started replacing. */
    /** Starts a tunnel without waiting for it to connect, for the tests that expect it not to. */
    private fun launch(
        server: FakeVpnServer,
        rescue: TeardownRescue?,
        socket: UdpSocketChannel = server,
    ): Pair<L2tpIpsecTunnel, Recorder> {
        val recorder = Recorder()
        val provider = FakeTunProvider()
        val tunnel = L2tpIpsecTunnel(
            config = config(),
            socketFactory = { socket },
            tunProvider = provider,
            listener = recorder,
            logger = VpnLogger.NONE,
            rescue = rescue,
        )
        providers[tunnel] = provider
        started += tunnel
        Thread({ tunnel.run() }, "loopback-launch").apply { isDaemon = true }.start()
        return tunnel to recorder
    }

    private val providers = HashMap<L2tpIpsecTunnel, FakeTunProvider>()

    private fun provider(tunnel: L2tpIpsecTunnel): FakeTun = providers.getValue(tunnel).established!!

    private fun awaitSupersededSa(server: FakeVpnServer): FakeIkeResponder {
        await("the client never started renegotiating phase 1") { server.supersededResponder != null }
        return server.supersededResponder!!
    }

    private fun peer(primaryDns: String = "10.10.10.1", secondaryDns: String = "8.8.8.8") =
        PppPeer(
            username = "u",
            password = "p",
            mru = 1350,
            primaryDns = primaryDns,
            secondaryDns = secondaryDns,
        )

    /** A minimal well-formed IPv4 packet; the server reflects it verbatim. */
    private fun ipPacket(seed: Int): ByteArray {
        val payload = ByteArray(200) { ((seed + it) and 0xFF).toByte() }
        val packet = ByteArray(20 + payload.size)
        packet[0] = 0x45
        packet[2] = (packet.size ushr 8).toByte()
        packet[3] = packet.size.toByte()
        packet[8] = 64
        packet[9] = 17
        payload.copyInto(packet, 20)
        return packet
    }

    private fun vpnThreads(): Set<Thread> =
        Thread.getAllStackTraces().keys.filterTo(HashSet()) { it.name.startsWith(THREAD_PREFIX) }

    private fun awaitNoNewVpnThreads(before: Set<Thread>) {
        // The reaper deliberately outlives the stop request; give it more than its grace period.
        val deadline = System.currentTimeMillis() + 15_000
        var leaked: List<Thread>
        do {
            leaked = (vpnThreads() - before).filter { it.isAlive }
            if (leaked.isEmpty()) return
            Thread.sleep(100)
        } while (System.currentTimeMillis() < deadline)
        throw AssertionError("threads left running: ${leaked.map { it.name }}")
    }

    private companion object {
        const val SERVER = "203.0.113.7"
        const val PSK = "correct horse battery staple"
        const val THREAD_PREFIX = "l2tp-vpn-"
        const val PACKETS = 2_000
        const val DPD_SEQUENCE = 0x00ABCDEF
    }
}
