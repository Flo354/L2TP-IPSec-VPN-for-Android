package com.arcansecurity.vpn.l2tpipsec.core.util

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Bounds contract of the two cursors every codec in the stack is built on. A missing check here is
 * reachable from the network through any of them, so the limits are pinned rather than assumed.
 */
class ByteCursorTest {

    // ---------------------------------------------------------------- ByteReader

    @Test
    fun readsEveryWidthBigEndian() {
        val r = ByteReader(Bytes.fromHex("ff" + "8001" + "ff0102" + "fffefdfc"))
        assertEquals(0xFF, r.u8())
        assertEquals(0x8001, r.u16())
        assertEquals(0xFF0102, r.u24())
        assertEquals(0xFFFEFDFCL, r.u32())
        assertEquals(0, r.remaining)
    }

    /** [ByteReader.i32] keeps the raw bits, so an SPI with the top bit set survives the round trip. */
    @Test
    fun i32KeepsTheRawBits() {
        assertEquals(-1, ByteReader(Bytes.fromHex("ffffffff")).i32())
        assertEquals(0x89ABCDEF.toInt(), ByteReader(Bytes.fromHex("89abcdef")).i32())
    }

    @Test
    fun everyReadIsBoundsChecked() {
        expectProtocol("u8") { ByteReader(ByteArray(0)).u8() }
        expectProtocol("u16") { ByteReader(ByteArray(1)).u16() }
        expectProtocol("u24") { ByteReader(ByteArray(2)).u24() }
        expectProtocol("u32") { ByteReader(ByteArray(3)).u32() }
        expectProtocol("bytes") { ByteReader(ByteArray(3)).bytes(4) }
        expectProtocol("slice") { ByteReader(ByteArray(3)).slice(4) }
        expectProtocol("skip") { ByteReader(ByteArray(3)).skip(4) }
        expectProtocol("peek") { ByteReader(ByteArray(0)).peekU8() }
    }

    /** A negative length must be rejected outright; it would otherwise rewind the cursor. */
    @Test
    fun negativeLengthsAreRejected() {
        expectProtocol("bytes") { ByteReader(ByteArray(8)).bytes(-1) }
        expectProtocol("slice") { ByteReader(ByteArray(8)).slice(-1) }
        expectProtocol("skip") { ByteReader(ByteArray(8)).skip(-1) }
    }

    /** A huge length must not wrap the `remaining` comparison into an accepting one. */
    @Test
    fun anAbsurdLengthDoesNotWrapTheCheck() {
        expectProtocol("skip") { ByteReader(ByteArray(8)).skip(Int.MAX_VALUE) }
        expectProtocol("bytes") { ByteReader(ByteArray(8), 4).bytes(Int.MAX_VALUE) }
    }

    @Test
    fun aSliceCannotReadPastItsLimit() {
        val r = ByteReader(ByteArray(16) { it.toByte() })
        val s = r.slice(4)
        assertEquals(4, s.remaining)
        assertArrayEquals(byteArrayOf(0, 1, 2, 3), s.bytes(4))
        assertFalse(s.hasRemaining)
        expectProtocol("past the slice") { s.u8() }
        // The parent cursor moved past the slice, not into it.
        assertEquals(4, r.position)
        assertEquals(12, r.remaining)
    }

    @Test
    fun readsCopyOutOfTheBackingBuffer() {
        val buf = ByteArray(4) { 1 }
        val out = ByteReader(buf).bytes(4)
        buf[0] = 9
        assertEquals(1, out[0].toInt())
    }

    @Test
    fun rejectsAnOutOfRangeConstruction() {
        expectIllegalArgument("pos past the end") { ByteReader(ByteArray(4), 5) }
        expectIllegalArgument("negative pos") { ByteReader(ByteArray(4), -1) }
        expectIllegalArgument("limit past the end") { ByteReader(ByteArray(4), 0, 5) }
        expectIllegalArgument("limit before pos") { ByteReader(ByteArray(4), 3, 2) }
    }

    @Test
    fun expectEndCatchesTrailingBytes() {
        val r = ByteReader(ByteArray(2))
        r.u8()
        expectProtocol("trailing") { r.expectEnd("test") }
        r.u8()
        r.expectEnd("test")
    }

    // ---------------------------------------------------------------- ByteWriter

    @Test
    fun writesEveryWidthBigEndian() {
        val w = ByteWriter()
        w.u8(0xFF).u16(0x8001).u24(0xFF0102).u32(0xFFFEFDFCL).i32(-1)
        assertEquals("ff8001ff0102fffefdfcffffffff", Bytes.toHex(w.toByteArray()))
    }

    @Test
    fun patchesAReservedSlot() {
        val w = ByteWriter()
        w.u8(1)
        val at = w.reserve(4)
        w.u8(2)
        w.patchU32(at, 0xDEADBEEFL)
        w.patchU8(0, 9)
        assertEquals("09deadbeef02", Bytes.toHex(w.toByteArray()))
        expectIllegalArgument("past the end") { w.patchU16(5, 0) }
        expectIllegalArgument("negative offset") { w.patchU8(-1, 0) }
    }

    @Test
    fun growsPastTheInitialCapacity() {
        val w = ByteWriter(16)
        w.bytes(ByteArray(1000) { it.toByte() })
        assertEquals(1000, w.size)
        assertEquals(999.toByte(), w.toByteArray()[999])
    }

    @Test
    fun toByteArrayCopies() {
        val w = ByteWriter().apply { u32(0) }
        assertNotSame(w.toByteArray(), w.toByteArray())
    }

    /** A negative count must be rejected, not left to `System.arraycopy` to notice. */
    @Test
    fun rejectsNegativeCounts() {
        expectIllegalArgument("bytes") { ByteWriter().bytes(ByteArray(4), 0, -1) }
        expectIllegalArgument("zeros") { ByteWriter().zeros(-1) }
        expectIllegalArgument("reserve") { ByteWriter().reserve(-1) }
    }

    /**
     * Growth must fail fast instead of doubling the capacity past 2^31: the doubling used to wrap
     * to a negative value and then to zero, and the loop never terminated.
     */
    @Test(timeout = 20_000)
    fun rejectsAGrowthRequestNoArrayCouldHold() {
        expectIllegalArgument("absurd count") { ByteWriter().bytes(ByteArray(8), 0, Int.MAX_VALUE) }
        expectIllegalArgument("absurd zeros") { ByteWriter().zeros(Int.MAX_VALUE) }
    }

    // ---------------------------------------------------------------- helpers

    private fun expectProtocol(what: String, block: () -> Unit) {
        try {
            block()
            fail("expected ProtocolException: $what")
        } catch (expected: ProtocolException) {
            assertTrue(expected.message!!.isNotEmpty())
        }
    }

    private fun expectIllegalArgument(what: String, block: () -> Unit) {
        try {
            block()
            fail("expected IllegalArgumentException: $what")
        } catch (expected: IllegalArgumentException) {
            // ok
        }
    }
}
