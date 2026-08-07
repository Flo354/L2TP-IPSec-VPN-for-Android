package com.arcansecurity.vpn.l2tpipsec.core.e2e

import com.arcansecurity.vpn.l2tpipsec.core.tunnel.L2tpIpsecTunnel
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.Phase1Proposal
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.Phase2Proposal
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelErrorKind
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelInfo
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelListener
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.VpnConfig
import com.arcansecurity.vpn.l2tpipsec.core.util.VpnLogger
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Proves rekeying against the real strongSwan lab rather than against a fake.
 *
 * The lab has to be started with short SA lifetimes for any of this to be observable inside a
 * test, which is what `IKE_LIFETIME=3m ESP_LIFETIME=2m testserver/run.sh` does. Run with:
 * ```
 * ./gradlew :core:test -Dl2tp.test.server=172.28.0.10 -Dl2tp.test.rekey=true --tests '*LiveRekeyTest'
 * ```
 */
class LiveRekeyTest {

    private val server: String? = System.getProperty("l2tp.test.server").takeUnless { it.isNullOrBlank() }
    private val rekeyLab: Boolean = System.getProperty("l2tp.test.rekey").toBoolean()

    private class Recorder : TunnelListener {
        val connected = CountDownLatch(1)
        val finished = CountDownLatch(1)
        @Volatile var info: TunnelInfo? = null
        @Volatile var errorKind: TunnelErrorKind? = null
        @Volatile var errorMessage: String? = null

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

    @Test
    fun `the tunnel rekeys both security associations and keeps carrying traffic`() {
        assumeTrue("set -Dl2tp.test.server to run the live tests", server != null)
        assumeTrue(
            "start the lab with IKE_LIFETIME=3m ESP_LIFETIME=2m and set -Dl2tp.test.rekey=true",
            rekeyLab,
        )

        val recorder = Recorder()
        val provider = FakeTunProvider()
        val tunnel = L2tpIpsecTunnel(
            config = VpnConfig(
                serverHost = server!!,
                presharedKey = System.getProperty("l2tp.test.psk", "TestPreSharedKey2024!"),
                username = System.getProperty("l2tp.test.user", "vpnuser"),
                password = System.getProperty("l2tp.test.password", "VpnPass123"),
                // strongSwan echoes back the lifetime the initiator proposes rather than imposing
                // its own, so the schedule under test is set from here. The lab is configured with
                // matching 2 m / 3 m expiries, which is what makes the test meaningful: if the
                // rekey did not work the server would tear the SAs down and the ping would fail.
                phase1 = Phase1Proposal(lifetimeSeconds = 180),
                phase2 = Phase2Proposal(lifetimeSeconds = 120),
                connectTimeoutMs = 30_000,
            ),
            socketFactory = TestUdpSocketFactory(InetAddress.getByName(server)),
            tunProvider = provider,
            listener = recorder,
            logger = VpnLogger.STDOUT,
        )
        Thread({ tunnel.run() }, "e2e-rekey").apply { isDaemon = true }.start()

        try {
            assertTrue(
                "tunnel did not connect: ${recorder.errorKind} ${recorder.errorMessage}",
                recorder.connected.await(60, TimeUnit.SECONDS),
            )
            val info = recorder.info!!
            val tun = provider.established!!
            assertTrue(ping(tun, info, sequence = 1))

            // The lab's IPsec SA lives 2 minutes and its ISAKMP SA 3, and the client starts
            // replacing each at 75-85% of that, so both must have happened well before 200 s.
            val deadline = System.currentTimeMillis() + 200_000
            while (System.currentTimeMillis() < deadline) {
                val stats = tunnel.stats
                if (stats.ipsecRekeys >= 1 && stats.ikeRekeys >= 1) break
                assertNull("the tunnel died instead of rekeying: ${recorder.errorMessage}", recorder.errorKind)
                Thread.sleep(1_000)
            }
            val stats = tunnel.stats
            assertTrue("no IPsec SA rekey happened (stats=$stats)", stats.ipsecRekeys >= 1)
            assertTrue("no ISAKMP SA rekey happened (stats=$stats)", stats.ikeRekeys >= 1)
            println("rekeys observed: ipsec=${stats.ipsecRekeys} ike=${stats.ikeRekeys}")

            // The point of the whole exercise: traffic still flows on the replaced SAs.
            assertTrue("traffic stopped after the rekey", ping(tun, info, sequence = 2))

            // And it still flows once the superseded SAs have actually been deleted. This is the
            // part worth proving on a real server: the ESP SAs were negotiated under the previous
            // ISAKMP SA, and an implementation that treats them as its children would drop them
            // when that SA is deleted at the end of the overlap window.
            Thread.sleep(40_000)
            assertTrue(
                "traffic stopped once the superseded SAs were deleted",
                ping(tun, info, sequence = 3),
            )
            assertNull("the tunnel reported a failure: ${recorder.errorMessage}", recorder.errorKind)
            assertEquals(
                "the tunnel must not have reconnected underneath us",
                info.assignedAddress,
                provider.established!!.params.address,
            )
        } finally {
            tunnel.stop()
            recorder.finished.await(15, TimeUnit.SECONDS)
        }
    }

    /**
     * The other half of rekeying: the router decides to replace the SA and we have to answer its
     * Quick Mode. Needs a lab that rekeys on its own:
     * ```
     * ESP_LIFETIME=2m REKEY=yes MARGINTIME=60s testserver/run.sh
     * ./gradlew :core:test -Dl2tp.test.server=172.28.0.10 -Dl2tp.test.rekey.responder=true \
     *     --tests '*LiveRekeyTest'
     * ```
     */
    @Test
    fun `a rekey started by the server is answered and traffic keeps flowing`() {
        assumeTrue("set -Dl2tp.test.server to run the live tests", server != null)
        assumeTrue(
            "start the lab with ESP_LIFETIME=2m REKEY=yes MARGINTIME=60s and set " +
                "-Dl2tp.test.rekey.responder=true",
            System.getProperty("l2tp.test.rekey.responder").toBoolean(),
        )

        val recorder = Recorder()
        val provider = FakeTunProvider()
        val tunnel = L2tpIpsecTunnel(
            // Default lifetimes on our side, so our own rekey timer is three quarters of an hour
            // away: anything that happens in the next two minutes can only have come from the peer.
            config = VpnConfig(
                serverHost = server!!,
                presharedKey = System.getProperty("l2tp.test.psk", "TestPreSharedKey2024!"),
                username = System.getProperty("l2tp.test.user", "vpnuser"),
                password = System.getProperty("l2tp.test.password", "VpnPass123"),
                connectTimeoutMs = 30_000,
            ),
            socketFactory = TestUdpSocketFactory(InetAddress.getByName(server)),
            tunProvider = provider,
            listener = recorder,
            logger = VpnLogger.STDOUT,
        )
        Thread({ tunnel.run() }, "e2e-rekey-responder").apply { isDaemon = true }.start()

        try {
            assertTrue(
                "tunnel did not connect: ${recorder.errorKind} ${recorder.errorMessage}",
                recorder.connected.await(60, TimeUnit.SECONDS),
            )
            val info = recorder.info!!
            val tun = provider.established!!
            assertTrue(ping(tun, info, sequence = 1))

            val deadline = System.currentTimeMillis() + 150_000
            while (System.currentTimeMillis() < deadline && tunnel.stats.ipsecRekeys < 1) {
                assertNull("the tunnel died instead of rekeying: ${recorder.errorMessage}", recorder.errorKind)
                Thread.sleep(1_000)
            }
            assertTrue(
                "the server never rekeyed, or we failed to answer it (stats=${tunnel.stats})",
                tunnel.stats.ipsecRekeys >= 1,
            )
            println("peer-initiated rekeys observed: ${tunnel.stats.ipsecRekeys}")
            assertTrue("traffic stopped after the peer's rekey", ping(tun, info, sequence = 2))
            assertNull("the tunnel reported a failure: ${recorder.errorMessage}", recorder.errorKind)
        } finally {
            tunnel.stop()
            recorder.finished.await(15, TimeUnit.SECONDS)
        }
    }

    /** One ICMP echo through the whole stack; true when the reply comes back. */
    private fun ping(tun: FakeTun, info: TunnelInfo, sequence: Int): Boolean {
        val payload = "rekey-probe".toByteArray()
        repeat(5) { attempt ->
            tun.inject(
                IcmpEcho.request(info.assignedAddress, info.peerAddress, 0xCAFE, sequence * 10 + attempt, payload),
            )
            val deadline = System.currentTimeMillis() + 2_000
            while (System.currentTimeMillis() < deadline) {
                val packet = tun.awaitInbound(500) ?: continue
                val reply = IcmpEcho.parseReply(packet) ?: continue
                if (reply.identifier == 0xCAFE) {
                    assertNotNull(reply)
                    return true
                }
            }
        }
        return false
    }
}
