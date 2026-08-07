package com.arcansecurity.vpn.l2tpipsec.core.util

enum class LogLevel { DEBUG, INFO, WARN, ERROR }

/**
 * Sink for the stack's diagnostics. The Android app forwards it to `android.util.Log` and to the
 * in-app log screen; unit tests capture it or discard it.
 */
fun interface VpnLogger {
    fun log(level: LogLevel, tag: String, message: String, error: Throwable?)

    /**
     * Whether a message at this level would be kept. Overriding it lets [Log.d] skip building a
     * string that the sink is only going to drop: the data path traces per packet, so on a phone
     * that formatting is real work done for nothing.
     */
    fun isEnabled(level: LogLevel): Boolean = true

    companion object {
        val NONE = object : VpnLogger {
            override fun log(level: LogLevel, tag: String, message: String, error: Throwable?) = Unit
            override fun isEnabled(level: LogLevel) = false
        }

        val STDOUT = VpnLogger { level, tag, message, error ->
            println("[$level] $tag: $message")
            error?.printStackTrace()
        }
    }
}

/** Convenience wrapper binding a [VpnLogger] to a fixed tag. */
class Log(private val tag: String, private val sink: VpnLogger) {
    /**
     * Debug traces take a lambda because they sit on the hot path — the message is only built if
     * something is actually going to keep it.
     */
    fun d(message: () -> String) {
        if (sink.isEnabled(LogLevel.DEBUG)) sink.log(LogLevel.DEBUG, tag, message(), null)
    }

    fun i(message: String) = sink.log(LogLevel.INFO, tag, message, null)
    fun w(message: String, error: Throwable? = null) = sink.log(LogLevel.WARN, tag, message, error)
    fun e(message: String, error: Throwable? = null) = sink.log(LogLevel.ERROR, tag, message, error)
}
