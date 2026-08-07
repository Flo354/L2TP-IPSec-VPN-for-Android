package com.arcansecurity.vpn.l2tpipsec.core.net

import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import com.arcansecurity.vpn.l2tpipsec.core.util.ProtocolException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.Assert.fail

class UdpDatagramTest {

    private val payload = Bytes.fromHex("c802000c000100000000")
    private val src = Bytes.ipv4ToBytes("192.168.1.10")
    private val dst = Bytes.ipv4ToBytes("10.0.0.1")

    /** A UDP/1701 datagram carrying a 10-byte L2TP message; checksum from a reference tool. */
    private val capturedHex = "06a506a500125ebdc802000c000100000000"

    @Test
    fun encodeParseRoundTrip() {
        val datagram = UdpDatagram.encode(1701, 1701, payload)
        assertEquals(UdpDatagram.HEADER_SIZE + payload.size, datagram.size)

        val parsed = UdpDatagram.parse(datagram)
        assertEquals(1701, parsed.sourcePort)
        assertEquals(1701, parsed.destinationPort)
        assertEquals(UdpDatagram.HEADER_SIZE, parsed.payloadOffset)
        assertEquals(payload.size, parsed.payloadLength)
        assertArrayEquals(
            payload,
            datagram.copyOfRange(parsed.payloadOffset, parsed.payloadOffset + parsed.payloadLength),
        )
    }

    /**
     * Without addresses the checksum stays 0, which is what the tunnel sends: behind a NAT the
     * outer source address is rewritten anyway (RFC 3948 section 3.1.2).
     */
    @Test
    fun checksumIsZeroWithoutAddresses() {
        val datagram = UdpDatagram.encode(1701, 1701, payload)
        assertEquals(0, datagram[6].toInt())
        assertEquals(0, datagram[7].toInt())
    }

    @Test
    fun checksumVerifiesWhenAddressesAreSupplied() {
        val datagram = UdpDatagram.encode(
            sourcePort = 1701,
            destinationPort = 1701,
            payload = payload,
            sourceIp = src,
            destinationIp = dst,
        )
        assertEquals(Bytes.toHex(Bytes.fromHex(capturedHex)), Bytes.toHex(datagram))
        // A receiver validates by summing the pseudo-header and the datagram: the result is zero.
        assertEquals(
            0,
            InternetChecksum.computeWithPseudoHeader(src, dst, Ipv4Header.PROTO_UDP, datagram),
        )
    }

    @Test
    fun parsesACapturedDatagram() {
        val raw = Bytes.fromHex(capturedHex)
        val parsed = UdpDatagram.parse(raw)
        assertEquals(1701, parsed.sourcePort)
        assertEquals(1701, parsed.destinationPort)
        assertEquals(8, parsed.payloadOffset)
        assertEquals(10, parsed.payloadLength)
        assertArrayEquals(payload, raw.copyOfRange(8, 18))
    }

    @Test
    fun encodeIntoMatchesEncodeAndReturnsTheLength() {
        val expected = UdpDatagram.encode(4500, 1701, payload)
        val out = ByteArray(64) { 0x7F }
        val written = UdpDatagram.encodeInto(out, 5, 4500, 1701, payload, 0, payload.size)
        assertEquals(expected.size, written)
        assertArrayEquals(expected, out.copyOfRange(5, 5 + written))
        assertEquals(0x7F.toByte(), out[4]) // nothing written before the offset
        assertEquals(0x7F.toByte(), out[5 + written])
    }

    @Test
    fun encodesASliceOfThePayload() {
        val bigger = Bytes.fromHex("ffff") + payload + Bytes.fromHex("ffff")
        val datagram = UdpDatagram.encode(1701, 1701, bigger, 2, payload.size)
        val parsed = UdpDatagram.parse(datagram)
        assertArrayEquals(
            payload,
            datagram.copyOfRange(parsed.payloadOffset, parsed.payloadOffset + parsed.payloadLength),
        )
    }

    /** `encode(..., payload, offset)` means "from [offset] to the end", as everywhere else here. */
    @Test
    fun encodeWithoutALengthTakesTheRestOfTheBuffer() {
        val bigger = Bytes.fromHex("ffff") + payload
        val datagram = UdpDatagram.encode(1701, 1701, bigger, 2)
        assertEquals(UdpDatagram.HEADER_SIZE + payload.size, datagram.size)
        val parsed = UdpDatagram.parse(datagram)
        assertArrayEquals(
            payload,
            datagram.copyOfRange(parsed.payloadOffset, parsed.payloadOffset + parsed.payloadLength),
        )
    }

    /** A length whose end does not fit in an `Int` must not wrap the range check into a pass. */
    @Test
    fun rejectsARangeWhoseEndOverflows() {
        val raw = Bytes.fromHex(capturedHex)
        expectProtocolException { UdpDatagram.parse(raw, 1, Int.MAX_VALUE) }
        expectProtocolException { UdpDatagram.parse(raw, raw.size + 1, 0) }
    }

    /**
     * The whole point of [UdpDatagram.encodeInto] is filling a buffer the caller already owns, so
     * wrapping a payload that is already sitting in that buffer has to work: the header must not
     * land on payload bytes that have not been moved yet.
     */
    @Test
    fun encodeIntoWrapsAPayloadAlreadyInTheOutputBuffer() {
        for (payloadOffset in 0..UdpDatagram.HEADER_SIZE) {
            val buffer = ByteArray(64) { 0x11 }
            System.arraycopy(payload, 0, buffer, payloadOffset, payload.size)
            val written = UdpDatagram.encodeInto(
                buffer, 0, 1701, 1701, buffer, payloadOffset, payload.size,
            )
            val parsed = UdpDatagram.parse(buffer, 0, written)
            assertEquals("offset $payloadOffset", 1701, parsed.sourcePort)
            assertArrayEquals(
                "offset $payloadOffset",
                payload,
                buffer.copyOfRange(parsed.payloadOffset, parsed.payloadOffset + parsed.payloadLength),
            )
        }
    }

    @Test
    fun emptyPayloadIsLegal() {
        val datagram = UdpDatagram.encode(1701, 1701, ByteArray(0))
        assertEquals(8, datagram.size)
        assertEquals(0, UdpDatagram.parse(datagram).payloadLength)
    }

    @Test
    fun parsesAtAnOffsetAndIgnoresTrailingPadding() {
        val raw = Bytes.fromHex("aabbcc" + capturedHex + "dddddddddd")
        val parsed = UdpDatagram.parse(raw, 3, raw.size - 3)
        assertEquals(1701, parsed.sourcePort)
        assertEquals(10, parsed.payloadLength) // the length field wins over the padded buffer
        assertEquals(11, parsed.payloadOffset)
    }

    @Test
    fun rejectsATruncatedHeader() {
        expectProtocolException { UdpDatagram.parse(Bytes.fromHex("06a506a5")) }
    }

    @Test
    fun rejectsALengthFieldBelowTheHeaderSize() {
        expectProtocolException { UdpDatagram.parse(Bytes.fromHex("06a506a500030000")) }
    }

    @Test
    fun rejectsALengthFieldBeyondTheBuffer() {
        expectProtocolException { UdpDatagram.parse(Bytes.fromHex("06a506a501000000")) }
    }

    private fun expectProtocolException(block: () -> Unit) {
        try {
            block()
            fail("expected ProtocolException")
        } catch (expected: ProtocolException) {
            // ok
        }
    }
}
