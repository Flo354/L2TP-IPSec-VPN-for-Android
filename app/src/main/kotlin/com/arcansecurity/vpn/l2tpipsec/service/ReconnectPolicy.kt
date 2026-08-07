package com.arcansecurity.vpn.l2tpipsec.service

import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelErrorKind

/**
 * Decides whether a dropped tunnel should be retried, and how long to wait first.
 *
 * The delay doubles from [initialDelayMs] and saturates at [maxDelayMs]: 2s, 4s, 8s, 16s, 32s,
 * then 60s forever. That is aggressive enough to ride out a two-second cell handover and polite
 * enough not to hammer a router that is simply switched off.
 *
 * Authentication failures are never retried. A wrong pre-shared key or a wrong PPP password will
 * not fix itself, and retrying is how accounts get locked out.
 *
 * Deliberately free of Android types so the policy can be unit-tested on a plain JVM.
 */
class ReconnectPolicy(
    private val initialDelayMs: Long = DEFAULT_INITIAL_DELAY_MS,
    private val maxDelayMs: Long = DEFAULT_MAX_DELAY_MS,
) {

    init {
        require(initialDelayMs > 0) { "initialDelayMs must be positive" }
        require(maxDelayMs >= initialDelayMs) { "maxDelayMs must not be below initialDelayMs" }
    }

    /** How many retries have been handed out since the last [reset]. */
    var attempts: Int = 0
        private set

    /** `false` for failures the user has to fix themselves. */
    fun shouldRetry(kind: TunnelErrorKind): Boolean = kind !in FATAL

    /** The delay before the [attempt]-th retry, counting from 1. */
    fun delayForAttempt(attempt: Int): Long {
        require(attempt >= 1) { "attempts are numbered from 1" }
        if (attempt > MAX_DOUBLINGS) return maxDelayMs
        val doubled = initialDelayMs shl (attempt - 1)
        return if (doubled <= 0L || doubled > maxDelayMs) maxDelayMs else doubled
    }

    /** Consumes one retry and returns how long to wait before it. */
    fun nextDelayMs(): Long {
        attempts += 1
        return delayForAttempt(attempts)
    }

    /** Called once a connection succeeds, or when a network change restarts the sequence. */
    fun reset() {
        attempts = 0
    }

    companion object {
        const val DEFAULT_INITIAL_DELAY_MS: Long = 2_000
        const val DEFAULT_MAX_DELAY_MS: Long = 60_000

        /** Beyond this the shift would overflow; the delay is pinned to the cap long before. */
        private const val MAX_DOUBLINGS = 32

        private val FATAL = setOf(
            TunnelErrorKind.IKE_AUTH_FAILED,
            TunnelErrorKind.PPP_AUTH_FAILED,
        )
    }
}
