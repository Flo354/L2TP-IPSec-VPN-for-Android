package com.arcan.l2tpvpn.core.tunnel

import com.arcan.l2tpvpn.core.util.VpnLogger
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Hermetic coverage of the orchestrator's failure handling. The happy path needs a real server
 * and lives in `e2e/LiveServerE2eTest`; what is checked here is that a server which never answers,
 * or a socket that dies underneath us, is turned into a bounded, correctly attributed failure
 * rather than a hang or a spin.
 */
class L2tpIpsecTunnelTest {

    private class Recorder : TunnelListener {
        val finished = CountDownLatch(1)
        @Volatile var kind: TunnelErrorKind? = null
        @Volatile var message: String? = null
        val states = mutableListOf<TunnelState>()

        override fun onStateChanged(state: TunnelState, detail: String?) {
            synchronized(states) { states += state }
        }

        override fun onFailed(kind: TunnelErrorKind, message: String, cause: Throwable?) {
            this.kind = kind
            this.message = message
        }

        override fun onDisconnected() = finished.countDown()
    }

    /** A peer that is reachable but silent — the shape of a wrong pre-shared key on strongSwan. */
    private class SilentChannel : UdpSocketChannel {
        val sends = AtomicInteger()
        val receives = AtomicInteger()
        override val localAddress: InetAddress = InetAddress.getByName("192.0.2.10")
        override val localPort = 41234

        override fun send(data: ByteArray, offset: Int, length: Int, destination: InetSocketAddress) {
            sends.incrementAndGet()
        }

        override fun receive(buffer: ByteArray, timeoutMs: Int): Datagram? {
            receives.incrementAndGet()
            Thread.sleep(minOf(timeoutMs, 50).toLong())
            return null
        }

        override fun close() = Unit
    }

    /** A socket that has already been torn down: every read fails instantly and forever. */
    private class DeadChannel : UdpSocketChannel {
        val receives = AtomicInteger()
        override val localAddress: InetAddress = InetAddress.getByName("192.0.2.10")
        override val localPort = 41234

        override fun send(data: ByteArray, offset: Int, length: Int, destination: InetSocketAddress) = Unit

        override fun receive(buffer: ByteArray, timeoutMs: Int): Datagram? {
            receives.incrementAndGet()
            throw SocketException("Socket closed")
        }

        override fun close() = Unit
    }

    private fun config(connectTimeoutMs: Int) = VpnConfig(
        serverHost = "127.0.0.1",
        presharedKey = "secret",
        username = "u",
        password = "p",
        connectTimeoutMs = connectTimeoutMs,
        ikeRetransmitTimeoutMs = 200,
        ikeMaxRetransmits = 20,
    )

    private fun run(config: VpnConfig, channel: UdpSocketChannel): Pair<L2tpIpsecTunnel, Recorder> {
        val recorder = Recorder()
        val tunnel = L2tpIpsecTunnel(
            config = config,
            socketFactory = { channel },
            tunProvider = { null },
            listener = recorder,
            logger = VpnLogger.NONE,
        )
        Thread({ tunnel.run() }, "tunnel-under-test").apply { isDaemon = true }.start()
        return tunnel to recorder
    }

    @Test
    fun `a silent peer fails within the connect timeout and blames the ike phase`() {
        val channel = SilentChannel()
        val (tunnel, recorder) = run(config(connectTimeoutMs = 1_500), channel)
        try {
            assertTrue(
                "the tunnel should have given up on its own",
                recorder.finished.await(15, TimeUnit.SECONDS),
            )
            assertEquals(TunnelErrorKind.IKE_NO_RESPONSE, recorder.kind)
            assertTrue("message should name the phase: ${recorder.message}", recorder.message!!.contains("IKE_PHASE1"))
            assertTrue("we should have retransmitted at least once", channel.sends.get() >= 2)
            synchronized(recorder.states) {
                assertTrue(recorder.states.contains(TunnelState.IKE_PHASE1))
                assertTrue(recorder.states.contains(TunnelState.FAILED))
            }
        } finally {
            tunnel.stop()
        }
    }

    @Test
    fun `a dead socket ends the reader instead of spinning on it`() {
        val channel = DeadChannel()
        val (tunnel, recorder) = run(config(connectTimeoutMs = 2_000), channel)
        try {
            assertTrue(recorder.finished.await(15, TimeUnit.SECONDS))
            // Before the bounded retry the reader burned a core and produced millions of reads in
            // the time this test takes; a couple of dozen is the honest number.
            assertTrue(
                "reader spun on the dead socket: ${channel.receives.get()} reads",
                channel.receives.get() < 100,
            )
        } finally {
            tunnel.stop()
        }
    }

    @Test
    fun `stop unblocks a connect that is still waiting`() {
        val channel = SilentChannel()
        val (tunnel, recorder) = run(config(connectTimeoutMs = 60_000), channel)
        Thread.sleep(300)
        tunnel.stop()
        assertTrue("stop() must unblock run()", recorder.finished.await(15, TimeUnit.SECONDS))
    }

    @Test
    fun `an unresolvable host fails fast as a dns error`() {
        val recorder = Recorder()
        val tunnel = L2tpIpsecTunnel(
            config = VpnConfig(
                serverHost = "no-such-host.invalid",
                presharedKey = "secret",
                username = "u",
                password = "p",
            ),
            socketFactory = { throw IllegalStateException("must not open a socket") },
            tunProvider = { null },
            listener = recorder,
        )
        Thread({ tunnel.run() }, "tunnel-dns-test").apply { isDaemon = true }.start()
        assertTrue(recorder.finished.await(30, TimeUnit.SECONDS))
        assertEquals(TunnelErrorKind.DNS_FAILURE, recorder.kind)
    }
}
