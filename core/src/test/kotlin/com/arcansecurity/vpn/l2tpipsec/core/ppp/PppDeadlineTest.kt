package com.arcansecurity.vpn.l2tpipsec.core.ppp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [PppSession.nextDeadlineMs] is what lets the packet pump sleep instead of ticking on a fixed
 * period, so it has to agree with [PppSession.tick] exactly.
 *
 * Two failures matter and each has its own test. A deadline *later* than the moment `tick` would
 * act delays a retransmission or a keepalive — caught by stepping the clock and asserting nothing
 * is ever sent before the deadline last advertised. And an implementation that simply always
 * answered `Long.MAX_VALUE` would satisfy that invariant while doing nothing — caught by asserting
 * the deadline genuinely comes due and echoes go out.
 */
class PppDeadlineTest {

    /** `PppSession.ECHO_INTERVAL_MS`, which is private. */
    private val echoIntervalMs = 20_000L

    /** `PppSession.RESTART_TIMER_MS`, which is private. */
    private val restartTimerMs = 3_000L

    @Test
    fun `an open session is due at its next echo and not before`() {
        val h = PppHarness()
        h.runToCompletion()
        assertTrue(h.session.isOpen)

        // The first echo is due as soon as LCP opens; this ticks it out so the interval is running.
        h.session.tick()
        h.pump()

        assertEquals(h.clock.now + echoIntervalMs, h.session.nextDeadlineMs())
    }

    @Test
    fun `a pending configure-request is due at its retransmission`() {
        val h = PppHarness()
        h.session.start()

        // Nothing delivered to the peer, so the LCP Configure-Request is still outstanding and is
        // sooner than the overall negotiation deadline.
        assertEquals(h.clock.now + restartTimerMs, h.session.nextDeadlineMs())
    }

    @Test
    fun `a terminating session is due at its retransmission`() {
        val h = PppHarness()
        h.runToCompletion()
        h.session.terminate("test")

        assertEquals(h.clock.now + restartTimerMs, h.session.nextDeadlineMs())
    }

    @Test
    fun `a session that never started has nothing due`() {
        val h = PppHarness()
        assertEquals(Long.MAX_VALUE, h.session.nextDeadlineMs())
    }

    @Test
    fun `tick never acts before the deadline it advertised, and the deadline does come due`() {
        val h = PppHarness()
        h.runToCompletion()
        assertTrue(h.session.isOpen)

        var elapsed = 0L
        while (elapsed < 90_000) {
            val advertised = h.session.nextDeadlineMs()
            h.clock.advance(STEP_MS)
            elapsed += STEP_MS
            h.session.tick()
            if (h.fromClient.isNotEmpty()) {
                assertTrue(
                    "tick() sent at ${h.clock.now} after advertising $advertised",
                    advertised <= h.clock.now,
                )
            }
            h.pump()
        }

        // Not vacuous: over ninety seconds of a twenty-second echo, the deadline really did fire.
        assertTrue(
            "the advertised deadline never came due (${h.peer.echoRepliesSent} echo replies)",
            h.peer.echoRepliesSent >= 3,
        )
        assertTrue("and the session survived", h.session.isOpen)
    }

    @Test
    fun `the invariant holds through negotiation, not only once open`() {
        // The peer answers nothing, so every Configure-Request has to be retransmitted and the
        // session eventually gives up — the busiest the timers ever are.
        val h = PppHarness(peer = FakeLns(answerIpcp = false))
        h.session.start()
        h.fromClient.clear()

        var elapsed = 0L
        while (elapsed < 70_000 && h.session.failure == null) {
            val advertised = h.session.nextDeadlineMs()
            h.clock.advance(STEP_MS)
            elapsed += STEP_MS
            h.session.tick()
            if (h.fromClient.isNotEmpty()) {
                assertTrue(
                    "tick() sent at ${h.clock.now} after advertising $advertised",
                    advertised <= h.clock.now,
                )
                h.fromClient.clear()
            }
        }

        assertTrue("the negotiation should have given up", h.session.failure != null)
    }

    private companion object {
        const val STEP_MS = 10L
    }
}
