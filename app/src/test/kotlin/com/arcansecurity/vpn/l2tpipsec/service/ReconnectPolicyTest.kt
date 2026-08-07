package com.arcansecurity.vpn.l2tpipsec.service

import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelErrorKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ReconnectPolicyTest {

    @Test
    fun `the backoff doubles and saturates at one minute`() {
        val policy = ReconnectPolicy()
        val delays = (1..8).map { policy.nextDelayMs() }

        assertEquals(
            listOf(2_000L, 4_000L, 8_000L, 16_000L, 32_000L, 60_000L, 60_000L, 60_000L),
            delays,
        )
    }

    @Test
    fun `delayForAttempt is the same sequence without consuming attempts`() {
        val policy = ReconnectPolicy()
        assertEquals(2_000L, policy.delayForAttempt(1))
        assertEquals(32_000L, policy.delayForAttempt(5))
        assertEquals(60_000L, policy.delayForAttempt(6))
        assertEquals(60_000L, policy.delayForAttempt(1_000))
        assertEquals(0, policy.attempts)
    }

    @Test
    fun `reset restarts the sequence`() {
        val policy = ReconnectPolicy()
        repeat(4) { policy.nextDelayMs() }
        assertEquals(4, policy.attempts)

        policy.reset()

        assertEquals(0, policy.attempts)
        assertEquals(2_000L, policy.nextDelayMs())
    }

    @Test
    fun `authentication failures are never retried`() {
        val policy = ReconnectPolicy()
        assertFalse(policy.shouldRetry(TunnelErrorKind.IKE_AUTH_FAILED))
        assertFalse(policy.shouldRetry(TunnelErrorKind.PPP_AUTH_FAILED))
    }

    @Test
    fun `every other failure is retried`() {
        val policy = ReconnectPolicy()
        val retryable = TunnelErrorKind.entries -
            setOf(TunnelErrorKind.IKE_AUTH_FAILED, TunnelErrorKind.PPP_AUTH_FAILED)

        retryable.forEach { kind ->
            assertTrue("$kind should be retried", policy.shouldRetry(kind))
        }
    }

    @Test
    fun `a custom sequence is honoured`() {
        val policy = ReconnectPolicy(initialDelayMs = 500, maxDelayMs = 2_000)
        assertEquals(
            listOf(500L, 1_000L, 2_000L, 2_000L),
            (1..4).map { policy.nextDelayMs() },
        )
    }
}
