package com.arcansecurity.vpn.l2tpipsec.platform

import android.util.Log
import com.arcansecurity.vpn.l2tpipsec.core.util.LogLevel
import com.arcansecurity.vpn.l2tpipsec.core.util.VpnLogger
import kotlinx.coroutines.flow.StateFlow

/**
 * The protocol stack's log sink on Android: every record goes to `logcat` *and* to an in-memory
 * ring buffer that the app's own log screen renders.
 *
 * Having the log inside the app matters more than it sounds — debugging an IKE negotiation against
 * a consumer router usually happens on a phone with no cable attached, where `adb logcat` is not
 * an option.
 */
class AndroidLogger(
    /** The ring buffer backing [lines]; injectable so tests can pin the clock. */
    val buffer: LogRingBuffer = LogRingBuffer(),
) : VpnLogger {

    /** Records below this level are dropped; raised to DEBUG by the profile's debug switch. */
    @Volatile
    var minLevel: LogLevel = LogLevel.INFO

    /** Live view of the ring buffer, oldest line first. */
    val lines: StateFlow<List<String>> get() = buffer.lines

    override fun log(level: LogLevel, tag: String, message: String, error: Throwable?) {
        if (level < minLevel) return

        val logcatTag = "$TAG_PREFIX$tag".take(MAX_LOGCAT_TAG)
        when (level) {
            LogLevel.DEBUG -> Log.d(logcatTag, message, error)
            LogLevel.INFO -> Log.i(logcatTag, message, error)
            LogLevel.WARN -> Log.w(logcatTag, message, error)
            LogLevel.ERROR -> Log.e(logcatTag, message, error)
        }
        buffer.append(level, tag, message, error)
    }

    /** The whole buffer as text, for the copy and share actions. */
    fun snapshot(): String = buffer.asText()

    fun clear() = buffer.clear()

    companion object {
        private const val TAG_PREFIX = "L2TP."
        /** `logcat` truncates tags past 23 characters on older platforms. */
        private const val MAX_LOGCAT_TAG = 23

        /**
         * Process-wide instance. The service produces the log and the UI consumes it without ever
         * binding to each other, so a single shared sink is the simplest thing that works.
         */
        val shared: AndroidLogger by lazy { AndroidLogger() }
    }
}
