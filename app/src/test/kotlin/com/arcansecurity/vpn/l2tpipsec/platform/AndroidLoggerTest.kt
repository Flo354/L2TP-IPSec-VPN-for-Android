package com.arcansecurity.vpn.l2tpipsec.platform

import com.arcansecurity.vpn.l2tpipsec.core.util.LogLevel
import java.time.ZoneOffset
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Pins the level filter, which is the contract the protocol stack's `Log.d { … }` call sites lean
 * on: a record below [AndroidLogger.minLevel] must reach neither `logcat` nor the ring buffer, so
 * that skipping the work of building its message can never change what the user sees.
 */
class AndroidLoggerTest {

    private val emitted = mutableListOf<String>()

    private fun logger() = AndroidLogger(
        buffer = LogRingBuffer(nowMs = { 0L }, zone = ZoneOffset.UTC),
        logcat = { level, tag, message, _ -> emitted += "$level $tag $message" },
    )

    @Test
    fun `at the default level debug records reach neither sink`() {
        val logger = logger()

        logger.log(LogLevel.DEBUG, "Ike", "payload dump", null)

        assertEquals(emptyList<String>(), emitted)
        assertEquals(emptyList<String>(), logger.lines.value)
    }

    @Test
    fun `at the default level everything from info upwards reaches both sinks`() {
        val logger = logger()

        listOf(LogLevel.INFO, LogLevel.WARN, LogLevel.ERROR).forEach { level ->
            logger.log(level, "Ike", "kept $level", null)
        }

        assertEquals(
            listOf("INFO L2TP.Ike kept INFO", "WARN L2TP.Ike kept WARN", "ERROR L2TP.Ike kept ERROR"),
            emitted,
        )
        assertEquals(3, logger.lines.value.size)
    }

    @Test
    fun `raising minLevel to DEBUG lets debug records through`() {
        val logger = logger()
        logger.minLevel = LogLevel.DEBUG

        logger.log(LogLevel.DEBUG, "Ike", "payload dump", null)

        assertEquals(listOf("DEBUG L2TP.Ike payload dump"), emitted)
        assertEquals(listOf("00:00:00.000 D/Ike: payload dump"), logger.lines.value)
    }

    @Test
    fun `lowering minLevel to ERROR drops warnings`() {
        val logger = logger()
        logger.minLevel = LogLevel.ERROR

        logger.log(LogLevel.WARN, "Esp", "replay window slid", null)
        logger.log(LogLevel.ERROR, "Esp", "icv mismatch", null)

        assertEquals(listOf("ERROR L2TP.Esp icv mismatch"), emitted)
        assertEquals(listOf("00:00:00.000 E/Esp: icv mismatch"), logger.lines.value)
    }

    /** `logcat` truncates past 23 characters, so the prefixed tag is cut before it gets there. */
    @Test
    fun `the logcat tag is prefixed and truncated but the buffer keeps the real one`() {
        val logger = logger()

        logger.log(LogLevel.INFO, "AVeryLongComponentName", "hello", null)

        assertEquals(listOf("INFO L2TP.AVeryLongComponent hello"), emitted)
        assertEquals(23, emitted.single().substringAfter(' ').substringBefore(' ').length)
        assertEquals(
            listOf("00:00:00.000 I/AVeryLongComponentName: hello"),
            logger.lines.value,
        )
    }
}
