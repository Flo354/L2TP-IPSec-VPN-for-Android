package com.arcansecurity.vpn.l2tpipsec.platform

import com.arcansecurity.vpn.l2tpipsec.core.util.LogLevel
import java.time.ZoneOffset
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LogRingBufferTest {

    /** A fixed clock so the formatted timestamps are deterministic. */
    private fun buffer(capacity: Int) =
        LogRingBuffer(capacity = capacity, nowMs = { 0L }, zone = ZoneOffset.UTC)

    @Test
    fun `caps at the capacity and keeps the newest lines`() {
        val buffer = buffer(5)

        repeat(12) { index -> buffer.appendLine("line $index") }

        val lines = buffer.lines.value
        assertEquals(5, lines.size)
        assertEquals(
            listOf("line 7", "line 8", "line 9", "line 10", "line 11"),
            lines,
        )
    }

    @Test
    fun `keeps everything while below the capacity`() {
        val buffer = buffer(500)

        repeat(50) { index -> buffer.appendLine("line $index") }

        assertEquals(50, buffer.lines.value.size)
        assertEquals("line 0", buffer.lines.value.first())
        assertEquals("line 49", buffer.lines.value.last())
    }

    @Test
    fun `formats records with a timestamp, a level and a tag`() {
        val buffer = buffer(10)

        buffer.append(LogLevel.WARN, "Ike", "no response from the peer")

        assertEquals(listOf("00:00:00.000 W/Ike: no response from the peer"), buffer.lines.value)
    }

    @Test
    fun `an error adds a second line`() {
        val buffer = buffer(10)

        buffer.append(LogLevel.ERROR, "Esp", "decrypt failed", IllegalStateException("bad icv"))

        val lines = buffer.lines.value
        assertEquals(2, lines.size)
        assertTrue(lines[1], lines[1].contains("IllegalStateException: bad icv"))
    }

    @Test
    fun `an error line also counts against the capacity`() {
        val buffer = buffer(3)

        repeat(3) { buffer.append(LogLevel.ERROR, "T", "boom", RuntimeException("x")) }

        assertEquals(3, buffer.lines.value.size)
    }

    @Test
    fun `clear empties the buffer`() {
        val buffer = buffer(10)
        buffer.appendLine("something")

        buffer.clear()

        assertEquals(emptyList<String>(), buffer.lines.value)
        assertEquals("", buffer.asText())
    }

    @Test
    fun `asText joins the lines for the clipboard`() {
        val buffer = buffer(10)
        buffer.appendLine("first")
        buffer.appendLine("second")

        assertEquals("first\nsecond", buffer.asText())
    }

    @Test
    fun `the default capacity is 500 lines`() {
        assertEquals(500, LogRingBuffer().capacity)
    }
}
