package com.arcan.l2tpvpn.core.util

enum class LogLevel { DEBUG, INFO, WARN, ERROR }

/**
 * Sink for the stack's diagnostics. The Android app forwards it to `android.util.Log` and to the
 * in-app log screen; unit tests capture it or discard it.
 */
fun interface VpnLogger {
    fun log(level: LogLevel, tag: String, message: String, error: Throwable?)

    companion object {
        val NONE = VpnLogger { _, _, _, _ -> }

        val STDOUT = VpnLogger { level, tag, message, error ->
            println("[$level] $tag: $message")
            error?.printStackTrace()
        }
    }
}

/** Convenience wrapper binding a [VpnLogger] to a fixed tag. */
class Log(private val tag: String, private val sink: VpnLogger) {
    fun d(message: () -> String) = sink.log(LogLevel.DEBUG, tag, message(), null)
    fun i(message: String) = sink.log(LogLevel.INFO, tag, message, null)
    fun w(message: String, error: Throwable? = null) = sink.log(LogLevel.WARN, tag, message, error)
    fun e(message: String, error: Throwable? = null) = sink.log(LogLevel.ERROR, tag, message, error)
}
