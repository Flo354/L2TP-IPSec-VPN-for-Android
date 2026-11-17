package com.arcansecurity.vpn.l2tpipsec.core.e2e

import com.arcansecurity.vpn.l2tpipsec.core.l2tp.L2tpCodec
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.Datagram
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.L2tpIpsecTunnel
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TeardownRescue
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelErrorKind
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelInfo
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelListener
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelState
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.UdpSocketChannel
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.VpnConfig
import com.arcansecurity.vpn.l2tpipsec.core.util.VpnLogger
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The teardown against a real strongSwan + xl2tpd + pppd server: that a failed attempt cleans up
 * after itself, and that a teardown lost with the network is delivered by the next attempt.
 *
 * Skipped unless `-Dl2tp.test.server=<ip>` is passed. The handover test comes from a second source
 * address when `-Dl2tp.test.altLocal=<ip>` names one this host owns and the server can answer —
 * which is the case that matters, since a phone that has left Wi-Fi is somewhere else entirely —
 * and checks the server's own logs when `-Dl2tp.test.container=<name>` names the lab container.
 * Docker masquerades a second bridge's address on its way into the first, so the second attempt
 * only really arrives from somewhere else when it also goes to the server's address on that
 * bridge, `-Dl2tp.test.altServer`; it is the same charon and the same xl2tpd either way:
 * ```
 * docker network create --subnet 172.29.0.0/16 --gateway 172.29.0.1 l2tplab2
 * docker network connect --ip 172.29.0.10 l2tplab2 l2tp-server
 * ./gradlew :core:test -Dl2tp.test.server=172.28.0.10 -Dl2tp.test.altLocal=172.29.0.1 \
 *     -Dl2tp.test.altServer=172.29.0.10 -Dl2tp.test.container=l2tp-server --tests '*LiveTeardownTest'
 * ```
 *
 * Nothing here needs PPP to come up. The network is pulled as soon as the L2TP session exists, so
 * the tests hold on a Docker host that cannot give the container `/dev/ppp` — where pppd dies at
 * once and the LNS answers every session with a CDN — as well as on one that can.
 */
class LiveTeardownTest {

    private val server: String? = System.getProperty("l2tp.test.server").takeUnless { it.isNullOrBlank() }
    private val altLocal: InetAddress? =
        System.getProperty("l2tp.test.altLocal").takeUnless { it.isNullOrBlank() }?.let(InetAddress::getByName)
    private val altServer: String? = System.getProperty("l2tp.test.altServer").takeUnless { it.isNullOrBlank() }
    private val container: String? = System.getProperty("l2tp.test.container").takeUnless { it.isNullOrBlank() }

    private fun config(
        password: String = System.getProperty("l2tp.test.password", "VpnPass123"),
        serverHost: String = server!!,
    ) = VpnConfig(
        serverHost = serverHost,
        presharedKey = System.getProperty("l2tp.test.psk", "TestPreSharedKey2024!"),
        username = System.getProperty("l2tp.test.user", "vpnuser"),
        password = password,
        connectTimeoutMs = 30_000,
        debugLogging = true,
    )

    private class Recorder(private val onSession: () -> Unit = {}) : TunnelListener {
        val connected = CountDownLatch(1)
        val sessionUp = CountDownLatch(1)
        val finished = CountDownLatch(1)
        @Volatile var info: TunnelInfo? = null
        @Volatile var errorKind: TunnelErrorKind? = null
        @Volatile var errorMessage: String? = null

        override fun onStateChanged(state: TunnelState, detail: String?) {
            // Runs on the tunnel thread before it moves on, so whatever onSession does happens
            // before the first PPP frame is sent.
            if (state == TunnelState.L2TP_SESSION) {
                onSession()
                sessionUp.countDown()
            }
        }

        override fun onConnected(info: TunnelInfo) {
            this.info = info
            connected.countDown()
        }

        override fun onFailed(kind: TunnelErrorKind, message: String, cause: Throwable?) {
            errorKind = kind
            errorMessage = message
        }

        override fun onDisconnected() = finished.countDown()
    }

    /**
     * A UDP socket whose network can be pulled out from under it: once [unplugged], sends still
     * succeed and nothing leaves, which is what a phone that has just lost Wi-Fi does with a
     * socket that was never bound to a network.
     */
    private class UnpluggableSocket(serverAddress: InetAddress, bindTo: InetAddress?) : UdpSocketChannel {
        private val socket = if (bindTo != null) DatagramSocket(InetSocketAddress(bindTo, 0)) else DatagramSocket()

        @Volatile var unplugged = false

        override val localAddress: InetAddress = bindTo ?: DatagramSocket().use { probe ->
            probe.connect(serverAddress, 4500)
            probe.localAddress
        }
        override val localPort: Int get() = socket.localPort

        override fun send(data: ByteArray, offset: Int, length: Int, destination: InetSocketAddress) {
            if (unplugged) return
            socket.send(DatagramPacket(data, offset, length, destination))
        }

        override fun receive(buffer: ByteArray, timeoutMs: Int): Datagram? {
            socket.soTimeout = timeoutMs
            val packet = DatagramPacket(buffer, buffer.size)
            return try {
                socket.receive(packet)
                Datagram(packet.length, InetSocketAddress(packet.address, packet.port))
            } catch (e: SocketTimeoutException) {
                null
            }
        }

        override fun close() = socket.close()
    }

    private fun launch(
        config: VpnConfig,
        socket: UdpSocketChannel,
        rescue: TeardownRescue? = null,
        recorder: Recorder = Recorder(),
    ): Triple<L2tpIpsecTunnel, Recorder, FakeTunProvider> {
        val provider = FakeTunProvider()
        val tunnel = L2tpIpsecTunnel(
            config = config,
            socketFactory = { socket },
            tunProvider = provider,
            listener = recorder,
            logger = VpnLogger.STDOUT,
            rescue = rescue,
        )
        Thread({ tunnel.run() }, "e2e-teardown").apply { isDaemon = true }.start()
        return Triple(tunnel, recorder, provider)
    }

    @Test
    fun `a failed attempt has its teardown acknowledged by the real lns`() {
        assumeTrue("set -Dl2tp.test.server to run the live tests", server != null)
        val socket = UnpluggableSocket(InetAddress.getByName(server), bindTo = null)
        val (tunnel, recorder, _) = launch(config(password = "wrong-password"), socket)

        assertTrue("tunnel never finished", recorder.finished.await(60, TimeUnit.SECONDS))
        assertEquals("the attempt must have got as far as an L2TP session", 0L, recorder.sessionUp.count)
        assertTrue("the attempt was expected to fail: ${recorder.errorKind}", recorder.errorKind != null)
        assertNull(
            "xl2tpd must have acknowledged the StopCCN of a failed attempt, leaving nothing to rescue",
            tunnel.leftover,
        )
    }

    @Test
    fun `a teardown lost with the network is delivered by the next attempt`() {
        assumeTrue("set -Dl2tp.test.server to run the live tests", server != null)
        val serverAddress = InetAddress.getByName(server)

        val wifi = UnpluggableSocket(serverAddress, bindTo = null)
        val firstRecorder = Recorder(onSession = { wifi.unplugged = true })
        val (first, _, _) = launch(config(), wifi, recorder = firstRecorder)
        assertTrue(
            "the first tunnel never got an L2TP session: ${firstRecorder.errorKind} ${firstRecorder.errorMessage}",
            firstRecorder.sessionUp.await(60, TimeUnit.SECONDS),
        )
        println("first tunnel's network pulled at L2TP_SESSION, from ${wifi.localAddress.hostAddress}:${wifi.localPort}")
        first.stop()
        assertTrue(firstRecorder.finished.await(15, TimeUnit.SECONDS))
        val leftover = first.leftover
        assertNotNull("nothing acknowledged the teardown, so it must have been kept", leftover)
        val staleTunnel = L2tpCodec.parseHeader(leftover!!.l2tpMessages.last()).first.tunnelId
        println("leftover: $leftover, for the LNS's tunnel $staleTunnel")
        if (container != null) {
            assertTrue("the LNS saw the first teardown after all", lnsLogLines(staleTunnel).isEmpty())
        }

        // The rescue is pinned to the address the server was reached on; reaching the same server
        // on its second address needs it re-pinned, which is all this copy does.
        val secondServer = altServer ?: server!!
        val rescue = if (altServer == null) leftover else TeardownRescue(
            InetAddress.getByName(altServer),
            leftover.l2tpMessages,
            leftover.isakmpMessages,
            leftover.capturedAtMs,
        )
        val mobile = UnpluggableSocket(InetAddress.getByName(secondServer), bindTo = altLocal)
        val (second, recorder, provider) = launch(config(serverHost = secondServer), mobile, rescue = rescue)
        try {
            assertTrue(
                "the next attempt never got an L2TP session: ${recorder.errorKind} ${recorder.errorMessage}",
                recorder.sessionUp.await(60, TimeUnit.SECONDS),
            )
            println("second tunnel's session up from ${mobile.localAddress.hostAddress}:${mobile.localPort}")
            if (container != null) {
                val closed = lnsLogLines(staleTunnel)
                lnsLog().filter { it.contains("recv packet from") && it.contains("tunnel = $staleTunnel,") }
                    .forEach { println("LNS: $it") }
                println("LNS: $closed")
                assertTrue(
                    "xl2tpd never closed the tunnel the first attempt left behind",
                    closed.isNotEmpty(),
                )
            }
            // On a lab that can run pppd the new tunnel must also carry traffic.
            if (recorder.connected.await(20, TimeUnit.SECONDS)) {
                val info = recorder.info!!
                val tun = provider.established!!
                var replied = false
                for (sequence in 1..5) {
                    tun.inject(IcmpEcho.request(info.assignedAddress, info.peerAddress, 0xFACE, sequence, byteArrayOf(1, 2, 3)))
                    val deadline = System.currentTimeMillis() + 2_000
                    while (!replied && System.currentTimeMillis() < deadline) {
                        val reply = tun.awaitInbound(500)?.let(IcmpEcho::parseReply) ?: continue
                        replied = reply.identifier == 0xFACE
                    }
                    if (replied) break
                }
                assertTrue("the second tunnel does not carry traffic", replied)
            } else {
                println("the second tunnel did not reach CONNECTED (${recorder.errorMessage}); is pppd able to run in the lab?")
            }
        } finally {
            second.stop()
            recorder.finished.await(15, TimeUnit.SECONDS)
        }
        assertNull("a delivered rescue must not be handed on again", second.leftover)
    }

    /** xl2tpd's own record of closing the control connection it numbered [lnsTunnelId]. */
    private fun lnsLogLines(lnsTunnelId: Int): List<String> =
        lnsLog().filter { it.contains("Connection closed to") && it.contains("Local: $lnsTunnelId,") }

    private fun lnsLog(): List<String> {
        val process = ProcessBuilder("docker", "exec", container!!, "cat", "/var/log/xl2tpd.log")
            .redirectErrorStream(true)
            .start()
        val lines = process.inputStream.bufferedReader().readLines()
        process.waitFor()
        return lines
    }
}
