package com.arcansecurity.vpn.l2tpipsec.core.net

import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class InternetChecksumTest {

    /** The worked example of RFC 1071 section 3: 00 01 f2 03 f4 f5 f6 f7 sums to 0xddf2 -> 0x220d. */
    @Test
    fun rfc1071WorkedExample() {
        assertEquals(0x220D, InternetChecksum.compute(Bytes.fromHex("0001f203f4f5f6f7")))
    }

    /** Verifying is the same operation as computing: a correct buffer checksums to zero. */
    @Test
    fun checksumOverAValidHeaderIsZero() {
        val header = Bytes.fromHex("4500003c1c46400040069cbcc0a80068c0a80001")
        assertEquals(0, InternetChecksum.compute(header))
    }

    @Test
    fun aSingleFlippedBitBreaksTheChecksum() {
        val header = Bytes.fromHex("4500003c1c46400040069cbcc0a80068c0a80001")
        header[8] = (header[8].toInt() xor 0x01).toByte() // TTL 0x40 -> 0x41
        assertEquals(true, InternetChecksum.compute(header) != 0)
    }

    /** RFC 1071 section 4.1: an odd-length buffer is padded on the right with a zero byte. */
    @Test
    fun oddLengthIsRightPaddedWithZero() {
        assertEquals(
            InternetChecksum.compute(Bytes.fromHex("0102030400")),
            InternetChecksum.compute(Bytes.fromHex("01020304")),
        )
        assertEquals(
            InternetChecksum.compute(Bytes.fromHex("aabbcc00")),
            InternetChecksum.compute(Bytes.fromHex("aabbcc")),
        )
    }

    @Test
    fun honoursOffsetAndLength() {
        val padded = Bytes.fromHex("ffff" + "0001f203f4f5f6f7" + "ffff")
        assertEquals(0x220D, InternetChecksum.compute(padded, 2, 8))
    }

    /**
     * A UDP datagram carrying a correct checksum verifies to zero when the pseudo-header is
     * prepended, which is how a receiver validates it (RFC 768).
     */
    @Test
    fun pseudoHeaderChecksumOverAValidDatagramIsZero() {
        val src = Bytes.ipv4ToBytes("192.168.1.10")
        val dst = Bytes.ipv4ToBytes("10.0.0.1")
        val datagram = Bytes.fromHex("06a506a500125ebdc802000c000100000000")
        assertEquals(
            0,
            InternetChecksum.computeWithPseudoHeader(src, dst, Ipv4Header.PROTO_UDP, datagram),
        )
    }

    /** `computeWithPseudoHeader(..., payload, offset)` covers the payload from [offset] to the end. */
    @Test
    fun pseudoHeaderChecksumWithoutALengthTakesTheRestOfTheBuffer() {
        val src = Bytes.ipv4ToBytes("192.168.1.10")
        val dst = Bytes.ipv4ToBytes("10.0.0.1")
        val datagram = Bytes.fromHex("06a506a500125ebdc802000c000100000000")
        val padded = Bytes.fromHex("aabbcc") + datagram
        assertEquals(
            InternetChecksum.computeWithPseudoHeader(src, dst, Ipv4Header.PROTO_UDP, datagram),
            InternetChecksum.computeWithPseudoHeader(src, dst, Ipv4Header.PROTO_UDP, padded, 3),
        )
    }

    /**
     * A length whose end does not fit in an `Int` must be rejected: wrapping it used to make the
     * sum loop exit immediately and return a plausible-looking checksum over nothing at all.
     */
    @Test
    fun rejectsARangeWhoseEndOverflows() {
        val data = Bytes.fromHex("0001f203f4f5f6f7")
        try {
            InternetChecksum.compute(data, 1, Int.MAX_VALUE)
            fail("expected IllegalArgumentException")
        } catch (expected: IllegalArgumentException) {
            // ok
        }
    }

    /** Independently computed with a reference implementation over the same pseudo-header. */
    @Test
    fun pseudoHeaderChecksumMatchesReferenceValue() {
        val src = Bytes.ipv4ToBytes("192.168.1.10")
        val dst = Bytes.ipv4ToBytes("10.0.0.1")
        val zeroChecksum = Bytes.fromHex("06a506a500120000c802000c000100000000")
        assertEquals(
            0x5EBD,
            InternetChecksum.computeWithPseudoHeader(src, dst, Ipv4Header.PROTO_UDP, zeroChecksum),
        )
    }
}
