package com.arcan.l2tpvpn.core.tunnel

import com.arcan.l2tpvpn.core.util.VpnLogger
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Drives one complete L2TP/IPsec connection: IKEv1 phase 1 and 2, ESP transport-mode
 * encapsulation inside UDP/4500, the L2TP control channel and session, PPP negotiation, and
 * finally the packet pump between the TUN interface and the tunnel.
 *
 * [run] blocks on the calling thread until the tunnel terminates; [stop] unblocks it.
 */
class L2tpIpsecTunnel(
    private val config: VpnConfig,
    private val socketFactory: UdpSocketFactory,
    private val tunProvider: TunProvider,
    private val listener: TunnelListener = TunnelListener.NONE,
    private val logger: VpnLogger = VpnLogger.NONE,
    private val clock: Clock = Clock.SYSTEM,
) {
    private val stopRequested = AtomicBoolean(false)

    @Volatile
    var stats: TunnelStats = TunnelStats()
        private set

    @Volatile
    var state: TunnelState = TunnelState.IDLE
        private set

    fun run() {
        throw NotImplementedError("wired up during integration")
    }

    /** Idempotent and safe to call from any thread. */
    fun stop() {
        stopRequested.set(true)
    }
}
