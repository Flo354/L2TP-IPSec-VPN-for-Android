package com.arcansecurity.vpn.l2tpipsec.service

/** What [L2tpVpnService.onStartCommand] should do with an incoming start command. */
internal enum class StartAction {
    /** Bring the tunnel up from the stored profile. */
    CONNECT,

    /** Tear the tunnel down and stop the service. */
    DISCONNECT,

    /** Leave everything alone; the tunnel is already running and owns the service. */
    KEEP_RUNNING,
}

/**
 * Maps an `Intent` action onto a [StartAction].
 *
 * Three actions can legitimately arrive:
 *
 *  * [L2tpVpnService.ACTION_CONNECT] and [L2tpVpnService.ACTION_DISCONNECT] from our own UI.
 *  * `android.net.VpnService` from the platform. That is how always-on VPN is started — the
 *    framework calls `startService()` with `VpnService.SERVICE_INTERFACE` — and the manifest
 *    advertises support for it, so treating it as anything but a connect leaves always-on VPN
 *    permanently broken.
 *
 * A `null` action means the system redelivered a start command of its own; with no idea what was
 * asked for, the safe answer is to keep a running tunnel and to stop otherwise.
 *
 * Kept free of Android types so the dispatch can be unit-tested on a plain JVM.
 *
 * @param tunnelRunning whether a tunnel worker is currently alive.
 */
internal fun startActionFor(action: String?, tunnelRunning: Boolean): StartAction = when (action) {
    L2tpVpnService.ACTION_CONNECT, VPN_SERVICE_INTERFACE -> StartAction.CONNECT
    L2tpVpnService.ACTION_DISCONNECT -> StartAction.DISCONNECT
    null -> if (tunnelRunning) StartAction.KEEP_RUNNING else StartAction.DISCONNECT
    else -> StartAction.DISCONNECT
}

/** `android.net.VpnService.SERVICE_INTERFACE`, spelled out so this file stays Android-free. */
internal const val VPN_SERVICE_INTERFACE = "android.net.VpnService"
