package com.arcansecurity.vpn.l2tpipsec.core.net

import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import com.arcansecurity.vpn.l2tpipsec.core.util.ProtocolException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class Ipv4HeaderTest {

    /** 192.168.0.104 -> 192.168.0.1, TCP, DF set, total length 60, checksum from a reference tool. */
    private val tcpHeaderHex = "4500003c1c46400040069cbcc0a80068c0a80001"

    @Test
    fun parsesAHandWrittenHeader() {
        val h = Ipv4Header.parse(Bytes.fromHex(tcpHeaderHex))
        assertEquals(4, h.version)
        assertEquals(5, h.ihl)
        assertEquals(0, h.dscp)
        assertEquals(60, h.totalLength)
        assertEquals(0x1C46, h.identification)
        assertEquals(Ipv4Header.FLAG_DONT_FRAGMENT, h.flags)
        assertEquals(0, h.fragmentOffset)
        assertEquals(64, h.ttl)
        assertEquals(Ipv4Header.PROTO_TCP, h.protocol)
        assertEquals(0x9CBC, h.headerChecksum)
        assertEquals("192.168.0.104", h.sourceIp)
        assertEquals("192.168.0.1", h.destinationIp)
        assertEquals(20, h.headerLength)
        assertEquals(40, h.payloadLength)
        assertFalse(h.isFragment)
    }

    @Test
    fun theHandWrittenHeaderCarriesACorrectChecksum() {
        assertEquals(0, InternetChecksum.compute(Bytes.fromHex(tcpHeaderHex)))
    }

    @Test
    fun encodeReproducesTheOriginalBytes() {
        val raw = Bytes.fromHex(tcpHeaderHex)
        val h = Ipv4Header.parse(raw)
        assertArrayEquals(raw, h.encode(h.payloadLength))
    }

    @Test
    fun parseEncodeRoundTrip() {
        val original = Ipv4Header(
            version = 4,
            ihl = 5,
            dscp = 0x2E, // EF, as a VoIP-marked packet would carry
            totalLength = 0,
            identification = 0xBEEF,
            flags = Ipv4Header.FLAG_DONT_FRAGMENT,
            fragmentOffset = 0,
            ttl = 64,
            protocol = Ipv4Header.PROTO_UDP,
            headerChecksum = 0,
            sourceAddress = Bytes.ipv4ToBytes("10.11.12.13"),
            destinationAddress = Bytes.ipv4ToBytes("8.8.8.8"),
        )
        val payload = ByteArray(100) { it.toByte() }
        val encoded = original.encode(payload.size)
        assertEquals(Ipv4Header.MIN_HEADER_SIZE, encoded.size)

        val parsed = Ipv4Header.parse(encoded)
        assertEquals(original.dscp, parsed.dscp)
        assertEquals(original.identification, parsed.identification)
        assertEquals(original.flags, parsed.flags)
        assertEquals(original.ttl, parsed.ttl)
        assertEquals(original.protocol, parsed.protocol)
        assertArrayEquals(original.sourceAddress, parsed.sourceAddress)
        assertArrayEquals(original.destinationAddress, parsed.destinationAddress)
        assertEquals(120, parsed.totalLength)
        assertEquals(100, parsed.payloadLength)
        // The encoder stamps a valid checksum, so the whole header verifies to zero.
        assertEquals(0, InternetChecksum.compute(encoded))
        // ... and re-encoding the parsed copy is a fixed point.
        assertArrayEquals(encoded, parsed.encode(payload.size))
        assertEquals(parsed, Ipv4Header.parse(parsed.encode(payload.size)))
    }

    @Test
    fun parsesAtAnOffset() {
        val padded = Bytes.fromHex("dead" + tcpHeaderHex)
        assertEquals("192.168.0.104", Ipv4Header.parse(padded, 2).sourceIp)
    }

    @Test
    fun ipVersionRecognisesV4V6AndGarbage() {
        val v4 = Bytes.fromHex(tcpHeaderHex)
        assertEquals(4, Ipv4Header.ipVersion(v4, 0, v4.size))

        // IPv6 header: version 6, 40 bytes minimum.
        val v6 = ByteArray(40).also { it[0] = 0x60 }
        assertEquals(6, Ipv4Header.ipVersion(v6, 0, v6.size))

        assertEquals(-1, Ipv4Header.ipVersion(ByteArray(20), 0, 20)) // version nibble 0
        assertEquals(-1, Ipv4Header.ipVersion(byteArrayOf(0x55), 0, 1)) // version nibble 5
        assertEquals(-1, Ipv4Header.ipVersion(ByteArray(0), 0, 0)) // empty
        assertEquals(-1, Ipv4Header.ipVersion(v4, 0, 19)) // claims v4 but is too short
        assertEquals(-1, Ipv4Header.ipVersion(v6, 0, 39)) // claims v6 but is too short
        assertEquals(-1, Ipv4Header.ipVersion(v4, 0, 100)) // length beyond the buffer
    }

    @Test
    fun rejectsNonIpv4() {
        expectProtocolException { Ipv4Header.parse(ByteArray(40).also { it[0] = 0x60 }) }
    }

    @Test
    fun rejectsShortInternetHeaderLength() {
        val bad = Bytes.fromHex(tcpHeaderHex).also { it[0] = 0x44 }
        expectProtocolException { Ipv4Header.parse(bad) }
    }

    @Test
    fun rejectsATruncatedHeader() {
        expectProtocolException { Ipv4Header.parse(Bytes.fromHex(tcpHeaderHex).copyOf(12)) }
    }

    @Test
    fun rejectsATotalLengthBelowTheHeaderSize() {
        val bad = Bytes.fromHex(tcpHeaderHex)
        bad[2] = 0
        bad[3] = 8
        expectProtocolException { Ipv4Header.parse(bad) }
    }

    @Test
    fun detectsFragments() {
        val raw = Bytes.fromHex(tcpHeaderHex)
        raw[6] = 0x20 // more-fragments flag
        raw[7] = 0x01 // fragment offset 1
        val h = Ipv4Header.parse(raw)
        assertTrue(h.isFragment)
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
