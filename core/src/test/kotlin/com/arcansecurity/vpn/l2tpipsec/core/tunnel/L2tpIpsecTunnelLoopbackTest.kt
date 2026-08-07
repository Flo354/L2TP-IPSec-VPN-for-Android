package com.arcansecurity.vpn.l2tpipsec.core.tunnel

import com.arcansecurity.vpn.l2tpipsec.core.e2e.FakeTun
import com.arcansecurity.vpn.l2tpipsec.core.e2e.FakeTunProvider
import com.arcansecurity.vpn.l2tpipsec.core.l2tp.L2tpMessageType
import com.arcansecurity.vpn.l2tpipsec.core.util.VpnLogger
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
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

    // ------------------------------------------------------------------------------- helpers

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
    }
}
