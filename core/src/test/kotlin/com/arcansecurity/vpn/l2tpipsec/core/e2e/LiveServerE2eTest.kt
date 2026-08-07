package com.arcansecurity.vpn.l2tpipsec.core.e2e

import com.arcansecurity.vpn.l2tpipsec.core.tunnel.L2tpIpsecTunnel
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.PppAuthProtocol
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelErrorKind
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelInfo
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelListener
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelState
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.VpnConfig
import com.arcansecurity.vpn.l2tpipsec.core.util.VpnLogger
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Drives the complete client against a real strongSwan + xl2tpd + pppd server (see `testserver/`).
 *
 * These tests are skipped unless `-Dl2tp.test.server=<ip>` is passed, so the ordinary unit-test
 * run stays hermetic. Run them with:
 * ```
 * ./gradlew :core:test -Dl2tp.test.server=172.28.0.10 --tests '*LiveServerE2eTest'
 * ```
 */
class LiveServerE2eTest {

    private val server: String? = System.getProperty("l2tp.test.server").takeUnless { it.isNullOrBlank() }
    private val psk = System.getProperty("l2tp.test.psk", "TestPreSharedKey2024!")
    private val user = System.getProperty("l2tp.test.user", "vpnuser")
    private val password = System.getProperty("l2tp.test.password", "VpnPass123")

    private fun config(
        psk: String = this.psk,
        password: String = this.password,
        auth: List<PppAuthProtocol> = listOf(PppAuthProtocol.MSCHAP_V2, PppAuthProtocol.CHAP_MD5, PppAuthProtocol.PAP),
    ) = VpnConfig(
        serverHost = server!!,
        presharedKey = psk,
        username = user,
        password = password,
        allowedPppAuth = auth,
        connectTimeoutMs = 30_000,
        debugLogging = true,
    )

    private class Recorder : TunnelListener {
        val connected = CountDownLatch(1)
        val finished = CountDownLatch(1)
        @Volatile var info: TunnelInfo? = null
        @Volatile var errorKind: TunnelErrorKind? = null
        @Volatile var errorMessage: String? = null
        val states = mutableListOf<TunnelState>()

        override fun onStateChanged(state: TunnelState, detail: String?) {
            synchronized(states) { states += state }
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

    private fun runTunnel(config: VpnConfig): Triple<L2tpIpsecTunnel, Recorder, FakeTunProvider> {
        val recorder = Recorder()
        val provider = FakeTunProvider()
        val tunnel = L2tpIpsecTunnel(
            config = config,
            socketFactory = TestUdpSocketFactory(InetAddress.getByName(config.serverHost)),
            tunProvider = provider,
            listener = recorder,
            logger = VpnLogger.STDOUT,
        )
        Thread({ tunnel.run() }, "e2e-tunnel").apply { isDaemon = true }.start()
        return Triple(tunnel, recorder, provider)
    }

    @Test
    fun `establishes the tunnel and carries an icmp echo end to end`() {
        assumeTrue("set -Dl2tp.test.server to run the live tests", server != null)
        val (tunnel, recorder, provider) = runTunnel(config())
        try {
            assertTrue(
                "tunnel did not connect: ${recorder.errorKind} ${recorder.errorMessage}",
                recorder.connected.await(60, TimeUnit.SECONDS),
            )
            val info = recorder.info!!
            println("connected: $info")
            assertTrue("unexpected address ${info.assignedAddress}", info.assignedAddress.startsWith("10.10.10."))
            assertTrue("NAT-T must be in use", info.udpEncapsulated)
            assertEquals("10.10.10.1", info.peerAddress)

            val tun = provider.established!!
            assertEquals(info.assignedAddress, tun.params.address)
            assertTrue("DNS should have been pushed", tun.params.dnsServers.isNotEmpty())

            // Ping the LNS through the whole stack: TUN -> PPP -> L2TP -> UDP -> ESP -> UDP/4500.
            val payload = "arcan-l2tp-probe".toByteArray()
            var reply: IcmpEcho.Reply? = null
            for (sequence in 1..5) {
                tun.inject(IcmpEcho.request(info.assignedAddress, info.peerAddress, 0xBEEF, sequence, payload))
                val deadline = System.currentTimeMillis() + 3_000
                while (System.currentTimeMillis() < deadline) {
                    val packet = tun.awaitInbound(500) ?: continue
                    val parsed = IcmpEcho.parseReply(packet) ?: continue
                    if (parsed.identifier == 0xBEEF && parsed.sequence == sequence) {
                        reply = parsed
                        break
                    }
                }
                if (reply != null) break
            }
            assertNotNull("no ICMP echo reply came back through the tunnel", reply)
            assertEquals(info.peerAddress, reply!!.sourceIp)
            assertEquals(info.assignedAddress, reply.destinationIp)
            assertTrue(reply.payload.copyOf(payload.size).contentEquals(payload))

            val stats = tunnel.stats
            assertTrue("no bytes were counted outbound", stats.bytesOut > 0)
            assertTrue("no bytes were counted inbound", stats.bytesIn > 0)
        } finally {
            tunnel.stop()
            recorder.finished.await(15, TimeUnit.SECONDS)
        }
    }

    @Test
    fun `a wrong pre-shared key fails phase 1 authentication`() {
        assumeTrue("set -Dl2tp.test.server to run the live tests", server != null)
        val (tunnel, recorder, _) = runTunnel(config(psk = "definitely-not-the-right-key"))
        try {
            assertTrue("tunnel never finished", recorder.finished.await(60, TimeUnit.SECONDS))
            assertTrue(
                "expected an IKE failure, got ${recorder.errorKind}: ${recorder.errorMessage}",
                recorder.errorKind in setOf(
                    TunnelErrorKind.IKE_AUTH_FAILED,
                    TunnelErrorKind.IKE_NO_RESPONSE,
                    TunnelErrorKind.IKE_PROPOSAL_REJECTED,
                ),
            )
        } finally {
            tunnel.stop()
        }
    }

    @Test
    fun `a wrong ppp password fails authentication after the ipsec sa is up`() {
        assumeTrue("set -Dl2tp.test.server to run the live tests", server != null)
        val (tunnel, recorder, _) = runTunnel(config(password = "wrong-password"))
        try {
            assertTrue("tunnel never finished", recorder.finished.await(60, TimeUnit.SECONDS))
            assertEquals(TunnelErrorKind.PPP_AUTH_FAILED, recorder.errorKind)
            // Everything below PPP must have worked for us to get this far.
            synchronized(recorder.states) {
                assertTrue("IPsec should have come up", recorder.states.contains(TunnelState.L2TP_SESSION))
            }
        } finally {
            tunnel.stop()
        }
    }

    @Test
    fun `authenticates over pap and over chap md5 as well as mschapv2`() {
        assumeTrue("set -Dl2tp.test.server to run the live tests", server != null)
        for (protocol in listOf(PppAuthProtocol.PAP, PppAuthProtocol.CHAP_MD5, PppAuthProtocol.MSCHAP_V2)) {
            val (tunnel, recorder, _) = runTunnel(config(auth = listOf(protocol)))
            try {
                assertTrue(
                    "$protocol did not connect: ${recorder.errorKind} ${recorder.errorMessage}",
                    recorder.connected.await(60, TimeUnit.SECONDS),
                )
                assertEquals(protocol.name, recorder.info!!.pppAuthDescription)
            } finally {
                tunnel.stop()
                recorder.finished.await(15, TimeUnit.SECONDS)
            }
        }
    }
}
