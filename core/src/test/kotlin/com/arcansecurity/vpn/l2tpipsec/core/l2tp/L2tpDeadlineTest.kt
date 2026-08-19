package com.arcansecurity.vpn.l2tpipsec.core.l2tp

import com.arcansecurity.vpn.l2tpipsec.core.util.VpnLogger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [L2tpTunnel.nextDeadlineMs] is what lets the packet pump sleep instead of ticking on a fixed
 * period, so it has to agree with [L2tpTunnel.tick] exactly.
 *
 * Two failures matter and each has its own test. A deadline *later* than the moment `tick` would
 * act delays a retransmission — caught by stepping the clock and asserting that nothing is ever
 * sent before the deadline last advertised. And an implementation that simply always answered
 * `Long.MAX_VALUE` would satisfy that invariant while doing nothing at all — caught by asserting
 * the deadline genuinely comes due and work happens.
 */
class L2tpDeadlineTest {

    private val clock = FakeClock()
    private val helloIntervalMs = 5_000
    private val retransmitTimeoutMs = 100

    private fun connected(lns: FakeLns): L2tpTunnel {
        val tunnel = L2tpTunnel(
            transport = lns,
            hostName = "android",
            clock = clock,
            logger = VpnLogger.NONE,
            retransmitTimeoutMs = retransmitTimeoutMs,
            maxRetransmits = 20,
            helloIntervalMs = helloIntervalMs,
        )
        tunnel.connect(timeoutMs = 10_000)
        tunnel.onPacket(lns.zlb())
        return tunnel
    }

    @Test
    fun `an idle tunnel is due at its next hello and not before`() {
        val lns = FakeLns(clock)
        val tunnel = connected(lns)
        tunnel.tick()

        assertEquals(clock.nowMs() + helloIntervalMs, tunnel.nextDeadlineMs())
    }

    @Test
    fun `an unacknowledged control message is due at its retransmission`() {
        val lns = FakeLns(clock)
        val tunnel = connected(lns)

        clock.advance(helloIntervalMs.toLong())
        tunnel.tick()
        assertEquals(1, lns.count(L2tpMessageType.HELLO))

        // The HELLO is now outstanding, and its retransmission is sooner than the next HELLO.
        assertEquals(clock.nowMs() + retransmitTimeoutMs, tunnel.nextDeadlineMs())
    }

    @Test
    fun `an unsolicited message is acknowledged at once and leaves nothing due`() {
        val lns = FakeLns(clock)
        val tunnel = connected(lns)
        tunnel.tick()
        val before = lns.received.size

        // SLI is a message a peer may send at any time and that onPacket does not hand upstream.
        // It acknowledges it itself rather than leaving the ZLB for the next tick, which is why
        // the tunnel is not left due — the pump can go back to sleep with nothing owed.
        tunnel.onPacket(lns.sli())

        assertTrue("the ZLB goes out immediately", lns.received.size > before)
        assertTrue(
            "nothing is owed, so the next deadline is still the hello",
            tunnel.nextDeadlineMs() > clock.nowMs(),
        )
    }

    @Test
    fun `a terminated tunnel has nothing due`() {
        val lns = FakeLns(clock)
        val tunnel = connected(lns)
        tunnel.close("test")

        assertEquals(Long.MAX_VALUE, tunnel.nextDeadlineMs())
    }

    @Test
    fun `tick never acts before the deadline it advertised, and the deadline does come due`() {
        val lns = FakeLns(clock)
        val tunnel = connected(lns)
        var sent = lns.received.size
        var elapsed = 0L

        while (elapsed < 30_000) {
            val advertised = tunnel.nextDeadlineMs()
            clock.advance(STEP_MS)
            elapsed += STEP_MS
            tunnel.tick()
            if (lns.received.size != sent) {
                assertTrue(
                    "tick() sent at ${clock.nowMs()} after advertising $advertised",
                    advertised <= clock.nowMs(),
                )
                sent = lns.received.size
                // Acknowledge, so the tunnel stays healthy instead of drowning in retransmissions.
                tunnel.onPacket(lns.zlb())
            }
        }

        // Not vacuous: over thirty seconds of a five-second hello, the deadline really did fire.
        assertTrue(
            "the advertised deadline never came due (${lns.count(L2tpMessageType.HELLO)} hellos)",
            lns.count(L2tpMessageType.HELLO) >= 4,
        )
    }

    private companion object {
        const val STEP_MS = 10L
    }
}
