package com.arcansecurity.vpn.l2tpipsec.service

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
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
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.VpnConfig
import com.arcansecurity.vpn.l2tpipsec.core.util.Log
import com.arcansecurity.vpn.l2tpipsec.core.util.LogLevel
import com.arcansecurity.vpn.l2tpipsec.data.ProfileStoreState
import com.arcansecurity.vpn.l2tpipsec.data.SecretKind
import com.arcansecurity.vpn.l2tpipsec.data.VpnProfile
import com.arcansecurity.vpn.l2tpipsec.label
import com.arcansecurity.vpn.l2tpipsec.platform.AndroidLogger
import com.arcansecurity.vpn.l2tpipsec.platform.AndroidTunProvider
import com.arcansecurity.vpn.l2tpipsec.platform.AndroidUdpSocketFactory
import com.arcansecurity.vpn.l2tpipsec.platform.AppComponentsHolder
import com.arcansecurity.vpn.l2tpipsec.ui.MainActivity
import com.arcansecurity.vpn.l2tpipsec.data.wipe
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

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
 *  4. Notice that the network underneath the tunnel changed (Wi-Fi to mobile and back) and restart
 *     immediately, because the source address the IKE SA was negotiated on no longer exists.
 *  5. Publish everything worth showing to [VpnStatusRepository] so the UI needs no service binding.
 */
class L2tpVpnService : VpnService() {

    private val logger = AndroidLogger.shared
    private val log = Log(TAG, logger)

    private lateinit var notifications: VpnNotifications
    private val reconnectPolicy = ReconnectPolicy()
    private val running = AtomicBoolean(false)

    /** Signalled to cut a backoff sleep short. */
    private val retryLock = ReentrantLock()
    private val retryWakeUp = retryLock.newCondition()

    @Volatile private var worker: Thread? = null
    @Volatile private var tunnel: L2tpIpsecTunnel? = null
    @Volatile private var socketFactory: AndroidUdpSocketFactory? = null

    /**
     * The live TUN descriptor. An [AtomicReference] rather than a `@Volatile var` because both the
     * tunnel thread (establishing) and whichever thread calls [interruptTunnel] (closing) touch it:
     * a read-then-null on a plain field lets a close racing an establish drop the new descriptor on
     * the floor, and a dropped `ParcelFileDescriptor` is a leaked file descriptor.
     */
    private val tunDescriptor = AtomicReference<ParcelFileDescriptor?>(null)

    /**
     * Only what the notification needs, copied out of the profile once it is loaded. The profile
     * itself is not kept: the tunnel runs off the [VpnConfig] the worker assembled, so a profile
     * edited mid-connection cannot half-apply itself to a live tunnel.
     */
    @Volatile private var profileName: String = ""
    @Volatile private var serverHost: String = ""

    @Volatile private var stopRequested = false
    @Volatile private var networkChangePending = false

    /** Latest `startId`, so [shutdown] can leave a newer start command alone. */
    @Volatile private var lastStartId = 0

    private val foregroundLock = Any()
    private var foregroundState = ForegroundState.NOT_STARTED

    private val connectivityLock = Any()
    private var connectivityManager: ConnectivityManager? = null
    private var registeredCallback: ConnectivityManager.NetworkCallback? = null

    /** Written by the connectivity callback thread, read by [unregisterNetworkCallback]. */
    @Volatile private var currentNetwork: Network? = null
    @Volatile private var lastNetworkChangeMs = 0L

    override fun onCreate() {
        super.onCreate()
        notifications = VpnNotifications(this)
        notifications.ensureChannel()
        connectivityManager = getSystemService(ConnectivityManager::class.java)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        lastStartId = startId
        // Whatever the action is, we were possibly launched with startForegroundService and owe the
        // system a startForeground() call within a few seconds. A previous run may have left the
        // state at FINISHED, so this command gets a fresh right to enter the foreground.
        synchronized(foregroundLock) {
            if (foregroundState == ForegroundState.FINISHED) {
                foregroundState = ForegroundState.NOT_STARTED
            }
        }
        pushNotification()

        when (startActionFor(intent?.action, running.get())) {
            StartAction.CONNECT -> startTunnel()

            StartAction.DISCONNECT -> {
                if (intent?.action == ACTION_DISCONNECT) {
                    log.i("Disconnect requested by the user")
                } else {
                    log.w("Unexpected start command (${intent?.action}); stopping")
                }
                stopTunnel(TunnelState.DISCONNECTING)
            }

            StartAction.KEEP_RUNNING ->
                log.w("Start command with no action while the tunnel runs; left alone")
        }
        // Deliberately not sticky: a VPN that silently reappears after the process was killed is
        // worse than one the user has to start again. Always-on VPN does not rely on this — the
        // platform restarts the service itself with the android.net.VpnService action.
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        log.w("VPN permission revoked by the system or another VPN app")
        stopTunnel(TunnelState.DISCONNECTING)
        super.onRevoke()
    }

    override fun onDestroy() {
        // No join on the tunnel thread here. onDestroy runs on the main looper, the thread can take
        // seconds to unwind its polite teardown, and it owns nothing that is still open by now:
        // stopTunnel() has already closed the TUN and armed the socket reaper. Blocking the looper
        // on it would only trade a leak we do not have for an ANR we would.
        stopTunnel(TunnelState.DISCONNECTING)
        unregisterNetworkCallback()
        // Last, so a worker that outlives this instance can no longer re-post the notification:
        // an ongoing "Connected" line with no service behind it is unkillable from the shade.
        leaveForeground()
        super.onDestroy()
    }

    // ---------------------------------------------------------------- lifecycle

    /**
     * Starts the worker and returns immediately.
     *
     * Nothing is read here. Loading the active profile means opening a keystore-backed store, and
     * reading its secrets means a second round of keystore work; both used to happen on this line,
     * which is the main looper — `onStartCommand` runs there, and the system is timing us against
     * the five seconds it allows before it kills a foreground service that has not called
     * `startForeground`. [loadConfiguration] now does it on the worker instead.
     */
    private fun startTunnel() {
        if (!running.compareAndSet(false, true)) {
            if (stopRequested) {
                log.w("Connect requested while the previous tunnel is still stopping; ignored")
            } else {
                log.i("Connect requested while already running; ignored")
            }
            return
        }

        stopRequested = false
        networkChangePending = false
        reconnectPolicy.reset()

        VpnStatusRepository.onStarting()
        pushNotification()

        worker = Thread({ runTunnelLoop() }, WORKER_NAME).apply {
            isDaemon = true
            start()
        }
    }

    /**
     * Reads the active profile and its secrets. **Worker thread only.**
     *
     * The secrets are handed over as `CharArray`s and wiped as soon as [prepareConnect] has built
     * the configuration. That is only a partial win — `VpnConfig` takes `String`s, so the values do
     * end up in immortal objects for as long as the tunnel lives — but it keeps them out of the
     * vault's own buffers and out of anything that survives a failed attempt.
     */
    private fun loadConfiguration(): VpnConfig? {
        VpnStatusRepository.onState(TunnelState.RESOLVING, "Loading the profile")
        pushNotification()

        val components = try {
            AppComponentsHolder.getBlocking(this)
        } catch (e: Throwable) {
            reject("The profile store could not be opened: ${e.message ?: e.javaClass.simpleName}")
            return null
        }

        val store = components.profiles
        // Always-on VPN can start us before anything has read the store, so wait for it — but not
        // forever: a store that never leaves LOADING must fail visibly rather than hang the service.
        val ready = runBlocking {
            withTimeoutOrNull(STORE_READY_TIMEOUT_MS) {
                store.state.first { it != ProfileStoreState.LOADING }
            }
        }
        if (ready == null) {
            reject("The profile store did not finish loading")
            return null
        }

        val activeId = store.activeProfileId.value
        val profile = store.profiles.value.firstOrNull { it.id == activeId }
        var presharedKey: CharArray? = null
        var password: CharArray? = null
        return try {
            if (profile != null) {
                presharedKey = components.secrets.read(profile.id, SecretKind.PRESHARED_KEY)
                password = components.secrets.read(profile.id, SecretKind.PASSWORD)
            }
            when (val prepared = prepareConnect(profile, presharedKey, password)) {
                is ConnectPreparation.Rejected -> {
                    reject(prepared.reason)
                    null
                }

                is ConnectPreparation.Ready -> {
                    profileName = profile?.name.orEmpty()
                    serverHost = prepared.config.serverHost
                    logger.minLevel =
                        if (prepared.config.debugLogging) LogLevel.DEBUG else LogLevel.INFO
                    log.i("Connecting to $serverHost ($profileName)")
                    prepared.config
                }
            }
        } finally {
            presharedKey?.wipe()
            password?.wipe()
        }
    }

    /** Reports a configuration problem the user has to fix; never retried. */
    private fun reject(reason: String) {
        log.e("Refusing to connect: $reason")
        VpnStatusRepository.onFailure(TunnelErrorKind.INTERNAL, reason)
        VpnStatusRepository.onState(TunnelState.FAILED, reason)
        pushNotification()
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
     * close the TUN descriptor, which is the one read no timeout will ever interrupt.
     *
     * The sockets are deliberately left alone for a moment. The stack still has to push its PPP
     * Terminate, L2TP CDN/StopCCN and ISAKMP deletes through them, and a router that never sees
     * those keeps the old session open — a Livebox then ignores the next SCCRQ entirely and the
     * reconnect hangs. The tunnel closes them itself once the teardown is out; the reaper below is
     * only the backstop for a thread that never gets that far.
     */
    private fun interruptTunnel() {
        runCatching { tunnel?.stop() }
        closeTunDescriptor()
        retryLock.withLock { retryWakeUp.signalAll() }

        val factory = socketFactory ?: return
        Thread({
            runCatching { Thread.sleep(SOCKET_CLOSE_GRACE_MS) }
            runCatching { factory.closeAll() }
        }, "vpn-socket-reaper").apply { isDaemon = true }.start()
    }

    private fun shutdown() {
        unregisterNetworkCallback()
        VpnStatusRepository.onStopped()
        leaveForeground()
        // stopSelf(startId) rather than stopSelf(): if a newer start command has arrived since, it
        // owns the service now and must not be torn down by the run that is finishing here.
        stopSelf(lastStartId)
    }

    // ---------------------------------------------------------------- tunnel loop

    private fun runTunnelLoop() {
        try {
            // First thing on the worker: everything that touches storage. A rejection here is a
            // configuration problem, so it stops rather than entering the retry loop.
            val config = loadConfiguration() ?: return
            if (stopRequested) return
            registerNetworkCallback()

            while (!stopRequested) {
                networkChangePending = false
                val attempt = runOnce(config)
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
            // The order is load-bearing. `running` is what stops a Connect from installing a second
            // worker, so it is released only once this one has finished tearing down. Clearing it
            // first left a window in which a Connect started a new tunnel and this thread then went
            // on to unregister its network callback and stopSelf() the service out from under it.
            worker = null
            shutdown()
            running.set(false)
        }
    }

    private fun runOnce(config: VpnConfig): Attempt {
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
            onEstablished = { descriptor ->
                // Anything still held here belongs to an attempt that is already over.
                tunDescriptor.getAndSet(descriptor)?.let { stale -> runCatching { stale.close() } }
            },
            sessionName = profileName.ifBlank { VpnProfile.DEFAULT_NAME },
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
        retryLock.withLock {
            while (!stopRequested && !networkChangePending) {
                val remaining = deadline - SystemClock.elapsedRealtime()
                if (remaining <= 0) return
                try {
                    retryWakeUp.await(remaining, TimeUnit.MILLISECONDS)
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
            // Deliberately does not touch the notification: stats arrive once a second.
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

    /**
     * Watches the network *underneath* the tunnel.
     *
     * It must never watch the default network, because once the VPN is up the default network for
     * our own uid is the VPN: registering tun0 would look exactly like a handover, we would tear
     * down the tunnel we had just finished building, and the rebuild would do it again. That is an
     * infinite reconnect loop, and it is what "connects and disconnects instantly" looks like.
     */
    private fun registerNetworkCallback() {
        val manager = connectivityManager ?: return
        synchronized(connectivityLock) {
            if (registeredCallback != null) return

            val callback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    // Belt and braces: the request below already excludes VPNs, but the pre-31
                    // fallback watches the default network and would otherwise see our own tun0.
                    val capabilities = manager.getNetworkCapabilities(network)
                    if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) {
                        log.d { "Ignoring our own VPN network $network" }
                        return
                    }
                    val previous = currentNetwork
                    currentNetwork = network
                    if (previous != null && previous != network) {
                        onUnderlyingNetworkChanged("Underlying network changed")
                    }
                }

                override fun onLost(network: Network) {
                    if (currentNetwork == network) currentNetwork = null
                }
            }

            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    // Reports only the single best match, so it is the underlying default network
                    // with VPNs filtered out — exactly what the tunnel is built on.
                    manager.registerBestMatchingNetworkCallback(
                        request, callback, Handler(Looper.getMainLooper()),
                    )
                } else {
                    // Older platforms have no best-match callback. Watching every matching network
                    // would fire whenever a second one merely becomes available, so fall back to
                    // the default network and rely on the VPN filter above. A handover that happens
                    // while the tunnel is up may be missed; the L2TP keepalive notices it soon
                    // enough.
                    manager.registerDefaultNetworkCallback(callback)
                }
            }
                .onSuccess { registeredCallback = callback }
                .onFailure { log.w("Could not register the network callback", it) }
        }
    }

    /**
     * Must be safe to call from the tunnel thread as well as the main looper: the lock is what
     * guarantees the worker's `shutdown()` actually sees the callback the main thread registered.
     * A callback that survives its service is a leaked `NetworkRequest`, and the platform only
     * tolerates a hundred of those per uid before it starts throwing.
     */
    private fun unregisterNetworkCallback() {
        val manager = connectivityManager ?: return
        synchronized(connectivityLock) {
            registeredCallback?.let { callback ->
                runCatching { manager.unregisterNetworkCallback(callback) }
                    .onFailure { log.w("Could not unregister the network callback", it) }
            }
            registeredCallback = null
            currentNetwork = null
        }
    }

    /**
     * The IKE SA and both NAT-D hashes are bound to the source address we negotiated on. Once the
     * underlying network moves that address is gone, so the only correct answer is to rebuild the
     * tunnel from scratch rather than wait for a keepalive to time out.
     */
    private fun onUnderlyingNetworkChanged(reason: String) {
        if (!running.get() || stopRequested) return
        // A handover resets the backoff, so anything that fires this repeatedly turns into a tight
        // reconnect loop. Rate-limiting it keeps a future mistake here merely slow instead of
        // fatal, and real handovers never arrive this fast.
        val now = SystemClock.elapsedRealtime()
        if (now - lastNetworkChangeMs < NETWORK_CHANGE_DEBOUNCE_MS) {
            log.d { "Ignoring a network change ${now - lastNetworkChangeMs} ms after the last one" }
            return
        }
        lastNetworkChangeMs = now
        log.i("$reason; rebuilding the tunnel")
        networkChangePending = true
        VpnStatusRepository.onState(TunnelState.RECONNECTING, reason)
        pushNotification()
        interruptTunnel()
    }

    // ---------------------------------------------------------------- notification

    /**
     * Renders the current state into the ongoing notification, entering the foreground on the first
     * call after every start command.
     *
     * Called from the main looper and from the tunnel thread, hence the lock: without it a status
     * update racing [leaveForeground] can re-post the notification after the service has left the
     * foreground, leaving a "Connected" line in the shade with no tunnel behind it.
     */
    private fun pushNotification() {
        val notification = notifications.build(
            state = VpnStatusRepository.state.value,
            detail = VpnStatusRepository.detail.value,
            info = VpnStatusRepository.info.value,
            serverHost = serverHost,
        )
        synchronized(foregroundLock) {
            when (foregroundState) {
                ForegroundState.FINISHED -> return
                ForegroundState.STARTED -> {
                    notifications.update(notification)
                    return
                }

                ForegroundState.NOT_STARTED -> Unit
            }
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    // Must be a subset of android:foregroundServiceType in the manifest, which is
                    // specialUse. The constant does not exist below API 34; there the untyped
                    // overload resolves to the manifest declaration by itself.
                    startForeground(
                        VpnNotifications.NOTIFICATION_ID,
                        notification,
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
                    )
                } else {
                    startForeground(VpnNotifications.NOTIFICATION_ID, notification)
                }
                foregroundState = ForegroundState.STARTED
            } catch (e: Exception) {
                // ForegroundServiceStartNotAllowedException on API 31+, i.e. something started us
                // from the background without an exemption. Nothing here can recover, and the tunnel
                // is doomed anyway once the system notices the missing startForeground().
                log.e("Could not enter the foreground", e)
            }
        }
    }

    private fun leaveForeground() {
        synchronized(foregroundLock) {
            foregroundState = ForegroundState.FINISHED
            runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
        }
    }

    private fun configureIntent(): PendingIntent = PendingIntent.getActivity(
        this,
        0,
        Intent(this, MainActivity::class.java).setFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
    )

    private fun closeTunDescriptor() {
        tunDescriptor.getAndSet(null)?.let { descriptor -> runCatching { descriptor.close() } }
    }

    // ---------------------------------------------------------------- types

    private enum class ForegroundState { NOT_STARTED, STARTED, FINISHED }

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

        /** A handover needs a moment for the new interface to get an address. */
        private const val NETWORK_CHANGE_DELAY_MS = 1_000L

        /** Two handovers cannot legitimately land this close together. */
        private const val NETWORK_CHANGE_DEBOUNCE_MS = 3_000L

        /**
         * How long the sockets outlive a stop request so the polite teardown can leave. Must be
         * longer than the tunnel's own grace period, since this is only the backstop.
         */
        private const val SOCKET_CLOSE_GRACE_MS = 3_000L

        /**
         * How long the worker waits for the store to leave `LOADING`. Generous, because always-on
         * VPN can start the service during boot while the keystore is still warming up, but finite,
         * because a store that never becomes readable has to surface as a failure.
         */
        private const val STORE_READY_TIMEOUT_MS = 15_000L

        const val ACTION_CONNECT = "com.arcansecurity.vpn.l2tpipsec.action.CONNECT"
        const val ACTION_DISCONNECT = "com.arcansecurity.vpn.l2tpipsec.action.DISCONNECT"

        /** Starts the tunnel from the active profile in the `ProfileStore`. */
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
