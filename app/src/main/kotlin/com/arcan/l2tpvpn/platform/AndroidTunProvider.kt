package com.arcan.l2tpvpn.platform

import android.app.PendingIntent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import com.arcan.l2tpvpn.core.tunnel.TunInterface
import com.arcan.l2tpvpn.core.tunnel.TunParameters
import com.arcan.l2tpvpn.core.tunnel.TunProvider
import com.arcan.l2tpvpn.core.util.Log
import com.arcan.l2tpvpn.core.util.VpnLogger
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Creates the system TUN interface once PPP has handed us an address.
 *
 * The interesting decisions:
 *
 *  * A default route (`0.0.0.0/0`) captures all IPv4 traffic — this is a full-tunnel client.
 *  * When `blockIpv6` is set we add a `::/0` route **without** an IPv6 address. Android then has
 *    nowhere to send v6 packets and drops them, which is what we want: an IPv4-only tunnel with a
 *    live IPv6 uplink would quietly leak every dual-stack connection around the VPN.
 *  * `setBlocking(true)` because the packet pump reads the descriptor from a dedicated thread.
 *  * `setUnderlyingNetworks(null)` tells the connectivity stack to attribute our traffic to the
 *    system default network, so the VPN follows Wi-Fi/mobile handovers instead of pinning itself.
 *
 * @param onEstablished receives the raw descriptor so the service can close it to unblock a
 *   blocking read when the tunnel is torn down.
 */
class AndroidTunProvider @JvmOverloads constructor(
    private val service: VpnService,
    private val onEstablished: (ParcelFileDescriptor) -> Unit,
    private val sessionName: String = DEFAULT_SESSION,
    /** Opened when the user taps the VPN entry in system settings. */
    private val configureIntent: PendingIntent? = null,
    private val logger: VpnLogger = VpnLogger.NONE,
) : TunProvider {

    private val log = Log(TAG, logger)

    override fun establish(params: TunParameters): TunInterface? {
        val builder = service.Builder()
            .setSession(sessionName)
            .setMtu(params.mtu)
            .addAddress(params.address, params.prefixLength)
            .addRoute(DEFAULT_ROUTE_V4, 0)

        params.dnsServers.forEach { dns ->
            runCatching { builder.addDnsServer(dns) }
                .onFailure { log.w("Rejecting unusable DNS server '$dns'", it) }
        }
        params.searchDomain?.takeIf { it.isNotBlank() }?.let { domain ->
            runCatching { builder.addSearchDomain(domain) }
                .onFailure { log.w("Rejecting unusable search domain '$domain'", it) }
        }

        if (params.blockIpv6) {
            // No IPv6 address is added, so this route is a blackhole rather than a path.
            runCatching { builder.addRoute(DEFAULT_ROUTE_V6, 0) }
                .onFailure { log.w("Could not install the IPv6 blackhole route", it) }
        }

        builder.setBlocking(true)
        configureIntent?.let { builder.setConfigureIntent(it) }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
            builder.setUnderlyingNetworks(null)
        }

        val descriptor = builder.establish()
        if (descriptor == null) {
            log.w("VpnService.Builder.establish() returned null: consent was revoked")
            return null
        }

        log.i(
            "TUN up: ${params.address}/${params.prefixLength} mtu=${params.mtu} " +
                "dns=${params.dnsServers.joinToString(",").ifEmpty { "(none)" }} " +
                "ipv6=${if (params.blockIpv6) "blocked" else "untouched"}",
        )
        onEstablished(descriptor)
        return ParcelFileDescriptorTun(descriptor)
    }

    private companion object {
        const val TAG = "Tun"
        const val DEFAULT_SESSION = "L2TP/IPsec"
        const val DEFAULT_ROUTE_V4 = "0.0.0.0"
        const val DEFAULT_ROUTE_V6 = "::"
    }
}

/** [TunInterface] over the descriptor `VpnService.Builder.establish()` produced. */
private class ParcelFileDescriptorTun(
    private val descriptor: ParcelFileDescriptor,
) : TunInterface {

    private val input = FileInputStream(descriptor.fileDescriptor)
    private val output = FileOutputStream(descriptor.fileDescriptor)
    private val closed = AtomicBoolean(false)

    override fun readPacket(buffer: ByteArray): Int {
        if (closed.get()) return -1
        return try {
            input.read(buffer)
        } catch (e: IOException) {
            // Closing the descriptor from another thread is how a blocking read is cancelled.
            if (closed.get()) -1 else throw e
        }
    }

    override fun writePacket(buffer: ByteArray, offset: Int, length: Int) {
        if (closed.get()) return
        output.write(buffer, offset, length)
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        runCatching { input.close() }
        runCatching { output.close() }
        runCatching { descriptor.close() }
    }
}
