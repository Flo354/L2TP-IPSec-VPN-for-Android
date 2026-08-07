package com.arcansecurity.vpn.l2tpipsec.platform

import com.arcansecurity.vpn.l2tpipsec.core.util.LogLevel
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * A bounded, thread-safe list of formatted log lines exposed as a [StateFlow] so the log screen
 * can follow the protocol stack live.
 *
 * Once [capacity] lines have been recorded the oldest one is dropped, which keeps a long debugging
 * session from eating the heap while always showing the most recent — and therefore most
 * interesting — output.
 *
 * No Android types here on purpose: the buffer is unit-tested on a plain JVM.
 */
class LogRingBuffer(
    val capacity: Int = DEFAULT_CAPACITY,
    private val nowMs: () -> Long = System::currentTimeMillis,
    zone: ZoneId = ZoneId.systemDefault(),
) {

    init {
        require(capacity > 0) { "capacity must be positive" }
    }

    private val formatter: DateTimeFormatter = DateTimeFormatter.ofPattern(TIME_PATTERN).withZone(zone)
    private val entries = ArrayDeque<String>()
    private val _lines = MutableStateFlow<List<String>>(emptyList())

    /** Oldest line first. Replaced wholesale on every append, so Compose sees a new list. */
    val lines: StateFlow<List<String>> get() = _lines.asStateFlow()

    /** Formats and records one log record, plus a second line for [error] when present. */
    fun append(level: LogLevel, tag: String, message: String, error: Throwable? = null) {
        val stamp = formatter.format(Instant.ofEpochMilli(nowMs()))
        appendLine("$stamp ${level.symbol}/$tag: $message")
        if (error != null) {
            appendLine("$stamp ${level.symbol}/$tag:     ${error.javaClass.simpleName}: ${error.message}")
        }
    }

    /** Records an already-formatted line, evicting the oldest one when full. */
    fun appendLine(line: String) {
        synchronized(entries) {
            entries.addLast(line)
            while (entries.size > capacity) {
                entries.removeFirst()
            }
            _lines.value = entries.toList()
        }
    }

    fun clear() {
        synchronized(entries) {
            entries.clear()
            _lines.value = emptyList()
        }
    }

    /** The whole buffer as one blob, ready for the clipboard or a share intent. */
    fun asText(): String = _lines.value.joinToString("\n")

    companion object {
        const val DEFAULT_CAPACITY: Int = 500
        private const val TIME_PATTERN = "HH:mm:ss.SSS"
    }
}

/** Single-letter level marker, matching the shape of a `logcat` line. */
private val LogLevel.symbol: Char
    get() = when (this) {
        LogLevel.DEBUG -> 'D'
        LogLevel.INFO -> 'I'
        LogLevel.WARN -> 'W'
        LogLevel.ERROR -> 'E'
    }
