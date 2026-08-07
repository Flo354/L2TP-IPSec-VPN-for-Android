package com.arcansecurity.vpn.l2tpipsec.core.util

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class BytesTest {

    @Test
    fun hexRoundTripsIncludingTheSignBit() {
        val raw = ByteArray(256) { it.toByte() }
        assertArrayEquals(raw, Bytes.fromHex(Bytes.toHex(raw)))
        assertEquals("00ff80", Bytes.toHex(Bytes.fromHex("00FF80")))
    }

    /** Test vectors get pasted with whatever separators their source used. */
    @Test
    fun fromHexIgnoresSeparators() {
        val expected = Bytes.fromHex("deadbeef")
        assertArrayEquals(expected, Bytes.fromHex("de ad be ef"))
        assertArrayEquals(expected, Bytes.fromHex("de:ad:be:ef"))
        assertArrayEquals(expected, Bytes.fromHex("de-ad-be-ef"))
        assertArrayEquals(expected, Bytes.fromHex("dead\n beef"))
    }

    @Test
    fun fromHexRejectsGarbage() {
        expectIllegalArgument("odd length") { Bytes.fromHex("abc") }
        expectIllegalArgument("bad char") { Bytes.fromHex("zz") }
    }

    @Test
    fun constantTimeEqualsMatchesContentEquals() {
        assertTrue(Bytes.constantTimeEquals(ByteArray(0), ByteArray(0)))
        assertTrue(Bytes.constantTimeEquals(Bytes.fromHex("80ff00"), Bytes.fromHex("80ff00")))
        assertFalse(Bytes.constantTimeEquals(Bytes.fromHex("80ff00"), Bytes.fromHex("80ff01")))
        // A difference only in the sign bit must still be seen.
        assertFalse(Bytes.constantTimeEquals(Bytes.fromHex("80"), Bytes.fromHex("00")))
        assertFalse(Bytes.constantTimeEquals(Bytes.fromHex("00"), Bytes.fromHex("0000")))
    }

    /**
     * Both truncation and padding must hand back a private copy: the callers are key-derivation
     * paths that go on to wipe or reuse the buffer they passed in.
     */
    @Test
    fun truncateAndLeftPadNeverAliasTheirInput() {
        val key = ByteArray(8) { 1 }
        assertNotSame(key, Bytes.truncate(key, key.size))
        assertNotSame(key, Bytes.leftPad(key, key.size))

        val padded = Bytes.leftPad(key, key.size)
        padded.fill(0)
        assertEquals(1, key[0].toInt())
    }

    @Test
    fun leftPadPrependsZeroes() {
        assertEquals("0000dead", Bytes.toHex(Bytes.leftPad(Bytes.fromHex("dead"), 4)))
        expectIllegalArgument("too long") { Bytes.leftPad(ByteArray(5), 4) }
        expectIllegalArgument("too short") { Bytes.truncate(ByteArray(3), 4) }
    }

    @Test
    fun concatAndXor() {
        assertEquals("aabbcc", Bytes.toHex(Bytes.concat(Bytes.fromHex("aa"), Bytes.fromHex("bbcc"))))
        assertEquals(0, Bytes.concat().size)
        assertEquals("ff00", Bytes.toHex(Bytes.xor(Bytes.fromHex("f00f"), Bytes.fromHex("0f0f"))))
        expectIllegalArgument("length mismatch") { Bytes.xor(ByteArray(1), ByteArray(2)) }
    }

    @Test
    fun ipv4LiteralsRoundTrip() {
        assertEquals("c0a8010a", Bytes.toHex(Bytes.ipv4ToBytes("192.168.1.10")))
        assertEquals("255.255.255.255", Bytes.ipv4ToString(Bytes.ipv4ToBytes("255.255.255.255")))
        assertEquals("10.0.0.1", Bytes.ipv4ToString(Bytes.fromHex("ffff0a000001"), 2))
        expectIllegalArgument("three parts") { Bytes.ipv4ToBytes("1.2.3") }
        expectIllegalArgument("out of range") { Bytes.ipv4ToBytes("1.2.3.256") }
        expectIllegalArgument("not a number") { Bytes.ipv4ToBytes("1.2.3.x") }
    }

    @Test
    fun randomNonZeroNeverReturnsAllZeroes() {
        repeat(200) { assertTrue(Bytes.randomNonZero(2).any { b -> b.toInt() != 0 }) }
        assertEquals(16, Bytes.random(16).size)
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
