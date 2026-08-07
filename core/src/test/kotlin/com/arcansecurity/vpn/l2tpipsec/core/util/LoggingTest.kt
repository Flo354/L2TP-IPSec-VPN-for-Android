package com.arcansecurity.vpn.l2tpipsec.core.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LoggingTest {

    private class Recording(private val enabledFrom: LogLevel = LogLevel.DEBUG) : VpnLogger {
        val lines = mutableListOf<String>()
        override fun log(level: LogLevel, tag: String, message: String, error: Throwable?) {
            lines += "$level/$tag: $message"
        }

        override fun isEnabled(level: LogLevel) = level >= enabledFrom
    }

    @Test
    fun `a suppressed debug trace never builds its message`() {
        val sink = Recording(enabledFrom = LogLevel.INFO)
        val log = Log("test", sink)
        var built = 0

        log.d { built++; "expensive" }

        // The point of the lambda: on the data path this runs per dropped packet, so building a
        // string the sink is going to discard is pure waste.
        assertEquals("the message must not have been built", 0, built)
        assertTrue(sink.lines.isEmpty())
    }

    @Test
    fun `an enabled debug trace builds its message exactly once`() {
        val sink = Recording()
        val log = Log("test", sink)
        var built = 0

        log.d { built++; "cheap" }

        assertEquals(1, built)
        assertEquals(listOf("DEBUG/test: cheap"), sink.lines)
    }

    @Test
    fun `levels above debug are not gated`() {
        val sink = Recording(enabledFrom = LogLevel.ERROR)
        val log = Log("test", sink)

        log.i("info")
        log.w("warn")
        log.e("error")

        // Only `d` takes a lambda, so the others are delivered and it is the sink's job to filter.
        assertEquals(3, sink.lines.size)
    }

    @Test
    fun `the discarding logger reports itself disabled`() {
        assertFalse(VpnLogger.NONE.isEnabled(LogLevel.ERROR))
        var built = 0
        Log("test", VpnLogger.NONE).d { built++; "never" }
        assertEquals(0, built)
    }

    @Test
    fun `a plain lambda sink keeps everything`() {
        val seen = mutableListOf<LogLevel>()
        val sink = VpnLogger { level, _, _, _ -> seen += level }
        val log = Log("test", sink)

        log.d { "d" }
        log.i("i")

        assertEquals(listOf(LogLevel.DEBUG, LogLevel.INFO), seen)
    }
}
