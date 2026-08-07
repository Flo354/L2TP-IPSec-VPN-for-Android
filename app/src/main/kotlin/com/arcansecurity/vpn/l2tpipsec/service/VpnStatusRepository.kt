package com.arcansecurity.vpn.l2tpipsec.service

import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelErrorKind
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelInfo
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelState
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelStats
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** A failure the user should see, with the moment it happened so the UI can age it out. */
data class VpnFailure(
    val kind: TunnelErrorKind,
    val message: String,
    val atMs: Long = System.currentTimeMillis(),
)

/** A pending automatic retry, so the status card can count down to it. */
data class RetrySchedule(
    val attempt: Int,
    val delayMs: Long,
    val scheduledAtMs: Long = System.currentTimeMillis(),
) {
    val dueAtMs: Long get() = scheduledAtMs + delayMs
}

/**
 * Process-wide mirror of the tunnel's state.
 *
 * The UI never binds to [L2tpVpnService]: the service pushes everything worth showing here and
 * the screens collect the flows. That keeps the Activity out of the service's lifecycle entirely
 * — it can be destroyed and recreated while the tunnel keeps running, and the status card is
 * correct the instant it recomposes.
 */
object VpnStatusRepository {

    private val _state = MutableStateFlow(TunnelState.IDLE)
    private val _detail = MutableStateFlow<String?>(null)
    private val _info = MutableStateFlow<TunnelInfo?>(null)
    private val _stats = MutableStateFlow(TunnelStats())
    private val _failure = MutableStateFlow<VpnFailure?>(null)
    private val _retry = MutableStateFlow<RetrySchedule?>(null)
    private val _connectedSinceMs = MutableStateFlow(0L)

    /** Where the tunnel currently is in its lifecycle. */
    val state: StateFlow<TunnelState> get() = _state.asStateFlow()

    /** Free-text elaboration of [state], e.g. "retrying in 8 s". */
    val detail: StateFlow<String?> get() = _detail.asStateFlow()

    /** Negotiated parameters; `null` until the tunnel comes up. */
    val info: StateFlow<TunnelInfo?> get() = _info.asStateFlow()

    val stats: StateFlow<TunnelStats> get() = _stats.asStateFlow()

    /** Last failure, kept after the state leaves [TunnelState.FAILED] so the UI can explain it. */
    val failure: StateFlow<VpnFailure?> get() = _failure.asStateFlow()

    /** Set while an automatic reconnect is pending. */
    val retry: StateFlow<RetrySchedule?> get() = _retry.asStateFlow()

    /** Wall clock of the last successful connection, or 0. */
    val connectedSinceMs: StateFlow<Long> get() = _connectedSinceMs.asStateFlow()

    /** True from the moment the user asks to connect until the service is gone. */
    val isBusy: Boolean
        get() = _state.value !in setOf(TunnelState.IDLE, TunnelState.FAILED)

    internal fun onState(state: TunnelState, detail: String? = null) {
        _state.value = state
        _detail.value = detail
        if (state != TunnelState.CONNECTED) {
            _connectedSinceMs.value = 0L
        }
        if (state == TunnelState.CONNECTED || state == TunnelState.IDLE) {
            _retry.value = null
        }
    }

    internal fun onConnected(info: TunnelInfo) {
        _info.value = info
        _failure.value = null
        _retry.value = null
        _connectedSinceMs.value = System.currentTimeMillis()
        _state.value = TunnelState.CONNECTED
        _detail.value = null
    }

    internal fun onStats(stats: TunnelStats) {
        _stats.value = stats
    }

    internal fun onFailure(kind: TunnelErrorKind, message: String) {
        _failure.value = VpnFailure(kind, message)
        _info.value = null
    }

    internal fun onRetryScheduled(attempt: Int, delayMs: Long) {
        _retry.value = RetrySchedule(attempt, delayMs)
    }

    /** Called when the service stops for good; keeps [failure] so the user can read it. */
    internal fun onStopped() {
        _state.value = if (_failure.value != null) TunnelState.FAILED else TunnelState.IDLE
        _detail.value = null
        _info.value = null
        _retry.value = null
        _connectedSinceMs.value = 0L
        _stats.value = TunnelStats()
    }

    /** Clears everything, including the last failure. Used when a new attempt starts. */
    internal fun onStarting() {
        _failure.value = null
        _retry.value = null
        _info.value = null
        _stats.value = TunnelStats()
        _connectedSinceMs.value = 0L
        _state.value = TunnelState.RESOLVING
        _detail.value = null
    }
}
