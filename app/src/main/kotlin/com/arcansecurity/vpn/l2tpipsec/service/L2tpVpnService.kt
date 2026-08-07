package com.arcansecurity.vpn.l2tpipsec.service

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.core.content.ContextCompat
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.L2tpIpsecTunnel
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelErrorKind
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelException
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelInfo
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelListener
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelState
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelStats
import com.arcansecurity.vpn.l2tpipsec.core.util.Log
import com.arcansecurity.vpn.l2tpipsec.core.util.LogLevel
import com.arcansecurity.vpn.l2tpipsec.data.ProfileRepository
import com.arcansecurity.vpn.l2tpipsec.data.VpnProfile
import com.arcansecurity.vpn.l2tpipsec.data.validate
import com.arcansecurity.vpn.l2tpipsec.label
import com.arcansecurity.vpn.l2tpipsec.platform.AndroidLogger
import com.arcansecurity.vpn.l2tpipsec.platform.AndroidTunProvider
import com.arcansecurity.vpn.l2tpipsec.platform.AndroidUdpSocketFactory
import com.arcansecurity.vpn.l2tpipsec.ui.MainActivity
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The foreground [VpnService] that owns one L2TP/IPsec tunnel.
 *
 * Responsibilities, in the order they matter:
 *
 *  1. Keep a `specialUse` foreground notification up for as long as the tunnel exists, because
 *     Android will otherwise kill the process the moment the screen goes off.
 *  2. Run [L2tpIpsecTunnel.run] — which blocks — on a dedicated thread, never on the main looper.
 *  3. Reconnect automatically with exponential backoff after any failure that is not the user's
 *     credentials being wrong (see [ReconnectPolicy]).
 *  4. Notice that the default network changed (Wi-Fi to mobile and back) and restart immediately,
 *     because the source address the IKE SA was negotiated on no longer exists.
 *  5. Publish everything worth showing to [VpnStatusRepository] so the UI needs no service binding.
 */
class L2tpVpnService : VpnService() {

    private val logger = AndroidLogger.shared
    private val log = Log(TAG, logger)

    private lateinit var notifications: VpnNotifications
    private val reconnectPolicy = ReconnectPolicy()
    private val running = AtomicBoolean(false)

    /** Woken to cut a backoff sleep short. */
    private val wakeUp = Object()

    @Volatile private var worker: Thread? = null
    @Volatile private var tunnel: L2tpIpsecTunnel? = null
    @Volatile private var socketFactory: AndroidUdpSocketFactory? = null
    @Volatile private var tunDescriptor: ParcelFileDescriptor? = null
    @Volatile private var profile: VpnProfile = VpnProfile()
    @Volatile private var stopRequested = false
    @Volatile private var networkChangePending = false
    @Volatile private var foregroundStarted = false

    private var connectivityManager: ConnectivityManager? = null
    private var registeredCallback: ConnectivityManager.NetworkCallback? = null
    private var currentNetwork: Network? = null

    override fun onCreate() {
        super.onCreate()
        notifications = VpnNotifications(this)
        notifications.ensureChannel()
        connectivityManager = getSystemService(ConnectivityManager::class.java)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Whatever the action is, we were possibly launched with startForegroundService and owe
        // the system a startForeground() call within a few seconds.
        pushNotification()

        when (intent?.action) {
            ACTION_DISCONNECT -> {
                log.i("Disconnect requested by the user")
                stopTunnel(TunnelState.DISCONNECTING)
            }

            ACTION_CONNECT -> startTunnel()

            else -> {
                log.w("Unexpected start command (${intent?.action}); stopping")
                stopTunnel(TunnelState.DISCONNECTING)
            }
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        log.w("VPN permission revoked by the system or another VPN app")
        stopTunnel(TunnelState.DISCONNECTING)
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel(TunnelState.DISCONNECTING)
        worker?.let { thread ->
            runCatching { thread.join(THREAD_JOIN_TIMEOUT_MS) }
        }
        unregisterNetworkCallback()
        super.onDestroy()
    }

    // ---------------------------------------------------------------- lifecycle

    private fun startTunnel() {
        if (!running.compareAndSet(false, true)) {
            log.i("Connect requested while already running; ignored")
            return
        }

        val loaded = ProfileRepository.get(this, logger).profile.value
        val validation = loaded.validate()
        if (!validation.isValid) {
            val message = validation.errors.joinToString("; ") { it.message }
            log.e("Refusing to connect, the profile is invalid: $message")
            VpnStatusRepository.onFailure(TunnelErrorKind.INTERNAL, message)
            running.set(false)
            shutdown()
            return
        }

        profile = loaded
        logger.minLevel = if (loaded.debugLogging) LogLevel.DEBUG else LogLevel.INFO
        stopRequested = false
        networkChangePending = false
        reconnectPolicy.reset()

        VpnStatusRepository.onStarting()
        pushNotification()
        registerNetworkCallback()

        log.i("Connecting to ${loaded.server} (${loaded.name})")
        worker = Thread({ runTunnelLoop() }, WORKER_NAME).apply {
            isDaemon = true
            start()
        }
    }

    private fun stopTunnel(state: TunnelState) {
        stopRequested = true
        VpnStatusRepository.onState(state)
        pushNotification()
        interruptTunnel()
        // The worker calls shutdown() on its way out; if it was never started, do it here.
        if (worker == null) shutdown()
    }

    /**
     * Unblocks the tunnel thread. `stop()` alone only flips a flag inside the stack, so we also
     * tear down everything it could be blocked on: the protected sockets and the TUN descriptor.
     */
    private fun interruptTunnel() {
        runCatching { tunnel?.stop() }
        runCatching { socketFactory?.closeAll() }
        closeTunDescriptor()
        synchronized(wakeUp) { wakeUp.notifyAll() }
    }

    private fun shutdown() {
        unregisterNetworkCallback()
        VpnStatusRepository.onStopped()
        stopForegroundCompat()
        stopSelf()
    }

    // ---------------------------------------------------------------- tunnel loop

    private fun runTunnelLoop() {
        try {
            while (!stopRequested) {
                networkChangePending = false
                val attempt = runOnce()
                if (stopRequested) break

                val failure = when (attempt) {
                    is Attempt.Stopped -> break
                    is Attempt.Ended -> Failure(
                        TunnelErrorKind.PEER_DISCONNECTED,
                        "The tunnel closed",
                        retryable = true,
                    )

                    is Attempt.Failed -> Failure(attempt.kind, attempt.message, attempt.retryable)
                }

                log.w("Tunnel down: ${failure.kind} — ${failure.message}")
                VpnStatusRepository.onFailure(failure.kind, failure.message)

                if (!failure.retryable || !reconnectPolicy.shouldRetry(failure.kind)) {
                    log.e("Not retrying: ${failure.kind.label}")
                    VpnStatusRepository.onState(TunnelState.FAILED, failure.message)
                    pushNotification()
                    break
                }

                // A network handover is not a failure of the peer: restart at once and start the
                // backoff sequence over. The flag is consumed here so that awaitRetry() below
                // still sleeps, and so that a *new* handover during that sleep cuts it short.
                val handover = networkChangePending
                networkChangePending = false
                val delayMs = if (handover) {
                    reconnectPolicy.reset()
                    NETWORK_CHANGE_DELAY_MS
                } else {
                    reconnectPolicy.nextDelayMs()
                }

                val attemptNumber = reconnectPolicy.attempts.coerceAtLeast(1)
                VpnStatusRepository.onRetryScheduled(attemptNumber, delayMs)
                VpnStatusRepository.onState(
                    TunnelState.RECONNECTING,
                    "Retrying in ${delayMs / 1000} s · attempt $attemptNumber",
                )
                pushNotification()
                log.i("Reconnecting in $delayMs ms (attempt $attemptNumber)")
                awaitRetry(delayMs)
            }
        } catch (t: Throwable) {
            log.e("Tunnel supervisor crashed", t)
            VpnStatusRepository.onFailure(TunnelErrorKind.INTERNAL, t.message ?: t.toString())
        } finally {
            running.set(false)
            worker = null
            shutdown()
        }
    }

    private fun runOnce(): Attempt {
        val config = try {
            profile.toVpnConfig()
        } catch (e: IllegalArgumentException) {
            return Attempt.Failed(
                TunnelErrorKind.INTERNAL,
                e.message ?: "Invalid configuration",
                retryable = false,
            )
        }

        VpnStatusRepository.onState(TunnelState.RESOLVING, "Resolving ${config.serverHost}")
        pushNotification()

        val serverAddress = try {
            InetAddress.getByName(config.serverHost)
        } catch (e: UnknownHostException) {
            return Attempt.Failed(
                TunnelErrorKind.DNS_FAILURE,
                "Could not resolve ${config.serverHost}",
            )
        }
        log.i("Server ${config.serverHost} resolved to ${serverAddress.hostAddress}")

        val factory = AndroidUdpSocketFactory(this, serverAddress, logger)
        socketFactory = factory
        val tunProvider = AndroidTunProvider(
            service = this,
            onEstablished = { descriptor -> tunDescriptor = descriptor },
            sessionName = profile.name.ifBlank { VpnProfile.DEFAULT_NAME },
            configureIntent = configureIntent(),
            logger = logger,
        )

        val instance = L2tpIpsecTunnel(
            config = config,
            socketFactory = factory,
            tunProvider = tunProvider,
            listener = listener,
            logger = logger,
        )
        tunnel = instance

        return try {
            instance.run()
            if (stopRequested) Attempt.Stopped else Attempt.Ended
        } catch (e: TunnelException) {
            Attempt.Failed(e.kind, e.message ?: e.kind.label)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            Attempt.Stopped
        } catch (e: NotImplementedError) {
            // The protocol stack is still being wired up in :core. Report it like any other
            // internal failure instead of letting an Error kill the thread silently.
            Attempt.Failed(
                TunnelErrorKind.INTERNAL,
                "The protocol stack is not implemented yet (${e.message})",
                retryable = false,
            )
        } catch (t: Throwable) {
            if (stopRequested) {
                Attempt.Stopped
            } else {
                log.e("Unexpected failure inside the tunnel", t)
                Attempt.Failed(TunnelErrorKind.INTERNAL, t.message ?: t.toString())
            }
        } finally {
            tunnel = null
            socketFactory = null
            runCatching { factory.closeAll() }
            closeTunDescriptor()
        }
    }

    /** Sleeps up to [delayMs], returning early when the user stops or the network moves. */
    private fun awaitRetry(delayMs: Long) {
        val deadline = SystemClock.elapsedRealtime() + delayMs
        synchronized(wakeUp) {
            while (!stopRequested && !networkChangePending) {
                val remaining = deadline - SystemClock.elapsedRealtime()
                if (remaining <= 0) return
                try {
                    wakeUp.wait(remaining)
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return
                }
            }
        }
    }

    // ---------------------------------------------------------------- tunnel callbacks

    private val listener = object : TunnelListener {
        override fun onStateChanged(state: TunnelState, detail: String?) {
            VpnStatusRepository.onState(state, detail)
            pushNotification()
        }

        override fun onConnected(info: TunnelInfo) {
            // A connection that reached this point invalidates the backoff sequence.
            reconnectPolicy.reset()
            VpnStatusRepository.onConnected(info)
            log.i(
                "Connected: ${info.assignedAddress} peer=${info.peerAddress} mtu=${info.mtu} " +
                    "nat=${info.natDetected} udp-encap=${info.udpEncapsulated} " +
                    "p1=${info.phase1Description} p2=${info.phase2Description}",
            )
            pushNotification()
        }

        override fun onStats(stats: TunnelStats) {
            // Deliberately does not touch the notification: stats arrive far too often.
            VpnStatusRepository.onStats(stats)
        }

        override fun onFailed(kind: TunnelErrorKind, message: String, cause: Throwable?) {
            log.e("Tunnel reported ${kind.name}: $message", cause)
            VpnStatusRepository.onFailure(kind, message)
        }

        override fun onDisconnected() {
            log.i("Tunnel reported a clean disconnect")
        }
    }

    // ---------------------------------------------------------------- connectivity

    private fun registerNetworkCallback() {
        val manager = connectivityManager ?: return
        if (registeredCallback != null) return

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val previous = currentNetwork
                currentNetwork = network
                if (previous != null && previous != network) {
                    onDefaultNetworkChanged("Default network changed")
                }
            }

            override fun onLost(network: Network) {
                if (currentNetwork == network) currentNetwork = null
            }
        }
        runCatching { manager.registerDefaultNetworkCallback(callback) }
            .onSuccess { registeredCallback = callback }
            .onFailure { log.w("Could not register the default-network callback", it) }
    }

    private fun unregisterNetworkCallback() {
        val manager = connectivityManager ?: return
        registeredCallback?.let { callback ->
            runCatching { manager.unregisterNetworkCallback(callback) }
        }
        registeredCallback = null
        currentNetwork = null
    }

    /**
     * The IKE SA and both NAT-D hashes are bound to the source address we negotiated on. Once the
     * default network moves that address is gone, so the only correct answer is to rebuild the
     * tunnel from scratch rather than wait for a keepalive to time out.
     */
    private fun onDefaultNetworkChanged(reason: String) {
        if (!running.get() || stopRequested) return
        log.i("$reason; rebuilding the tunnel")
        networkChangePending = true
        VpnStatusRepository.onState(TunnelState.RECONNECTING, reason)
        pushNotification()
        interruptTunnel()
    }

    // ---------------------------------------------------------------- notification

    private fun pushNotification() {
        val notification = notifications.build(
            state = VpnStatusRepository.state.value,
            detail = VpnStatusRepository.detail.value,
            info = VpnStatusRepository.info.value,
            serverHost = profile.server,
        )
        if (foregroundStarted) {
            notifications.update(notification)
            return
        }
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(
                    VpnNotifications.NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
                )
            } else {
                startForeground(VpnNotifications.NOTIFICATION_ID, notification)
            }
            foregroundStarted = true
        } catch (e: Exception) {
            // Missing POST_NOTIFICATIONS or a background-start restriction; the tunnel can still
            // run, it just will not survive an aggressive Doze.
            log.w("Could not enter the foreground", e)
        }
    }

    private fun stopForegroundCompat() {
        foregroundStarted = false
        runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
    }

    private fun configureIntent(): PendingIntent = PendingIntent.getActivity(
        this,
        0,
        Intent(this, MainActivity::class.java).setFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
    )

    private fun closeTunDescriptor() {
        tunDescriptor?.let { descriptor -> runCatching { descriptor.close() } }
        tunDescriptor = null
    }

    // ---------------------------------------------------------------- types

    private data class Failure(
        val kind: TunnelErrorKind,
        val message: String,
        val retryable: Boolean,
    )

    private sealed interface Attempt {
        /** The user asked to stop. */
        data object Stopped : Attempt

        /** `run()` returned without an error, i.e. the peer closed the tunnel. */
        data object Ended : Attempt

        data class Failed(
            val kind: TunnelErrorKind,
            val message: String,
            val retryable: Boolean = true,
        ) : Attempt
    }

    companion object {
        private const val TAG = "Service"
        private const val WORKER_NAME = "l2tp-tunnel"
        private const val THREAD_JOIN_TIMEOUT_MS = 3_000L

        /** A handover needs a moment for the new interface to get an address. */
        private const val NETWORK_CHANGE_DELAY_MS = 1_000L

        const val ACTION_CONNECT = "com.arcansecurity.vpn.l2tpipsec.action.CONNECT"
        const val ACTION_DISCONNECT = "com.arcansecurity.vpn.l2tpipsec.action.DISCONNECT"

        /** Starts the tunnel from the profile stored in `ProfileRepository`. */
        fun connect(context: Context) {
            ContextCompat.startForegroundService(
                context,
                Intent(context, L2tpVpnService::class.java).setAction(ACTION_CONNECT),
            )
        }

        fun disconnect(context: Context) {
            ContextCompat.startForegroundService(
                context,
                Intent(context, L2tpVpnService::class.java).setAction(ACTION_DISCONNECT),
            )
        }
    }
}
