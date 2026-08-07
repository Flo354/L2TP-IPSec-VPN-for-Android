package com.arcansecurity.vpn.l2tpipsec.core.ppp

import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import com.arcansecurity.vpn.l2tpipsec.core.util.ProtocolException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class PppFrameTest {

    private val payload = Bytes.fromHex("0102030405")

    @Test
    fun `encodes address control and protocol by default`() {
        assertEquals("ff03c0210102030405", Bytes.toHex(PppFrame.encode(PppProtocol.LCP, payload)))
    }

    @Test
    fun `encodes without address control when asked`() {
        val frame = PppFrame.encode(PppProtocol.IPCP, payload, withAddressControl = false)
        assertEquals("80210102030405", Bytes.toHex(frame))
    }

    @Test
    fun `round trips through parse`() {
        for (withAc in listOf(true, false)) {
            val frame = PppFrame.encode(PppProtocol.CHAP, payload, withAddressControl = withAc)
            val parsed = PppFrame.parse(frame)
            assertEquals(PppProtocol.CHAP, parsed.protocol)
            assertEquals(PppFrame.headerSize(withAc), parsed.payloadOffset)
            assertEquals(payload.size, parsed.payloadLength)
            assertArrayEquals(
                payload,
                frame.copyOfRange(parsed.payloadOffset, parsed.payloadOffset + parsed.payloadLength),
            )
        }
    }

    @Test
    fun `parses a frame without address and control`() {
        val parsed = PppFrame.parse(Bytes.fromHex("00214500"))
        assertEquals(PppProtocol.IPV4, parsed.protocol)
        assertEquals(2, parsed.payloadOffset)
        assertEquals(2, parsed.payloadLength)
    }

    @Test
    fun `parses a protocol field compressed to one byte`() {
        // RFC 1661 section 6.5: 0x0021 (IPv4) compresses to the single odd byte 0x21.
        val parsed = PppFrame.parse(Bytes.fromHex("ff03214500"))
        assertEquals(PppProtocol.IPV4, parsed.protocol)
        assertEquals(3, parsed.payloadOffset)
        assertEquals(2, parsed.payloadLength)

        val withoutAc = PppFrame.parse(Bytes.fromHex("214500"))
        assertEquals(PppProtocol.IPV4, withoutAc.protocol)
        assertEquals(1, withoutAc.payloadOffset)
    }

    @Test
    fun `parses at an offset inside a bigger buffer`() {
        val buffer = Bytes.fromHex("deadbeef" + "ff03c0210102030405" + "cafe")
        val parsed = PppFrame.parse(buffer, 4, 9)
        assertEquals(PppProtocol.LCP, parsed.protocol)
        assertArrayEquals(
            payload,
            buffer.copyOfRange(parsed.payloadOffset, parsed.payloadOffset + parsed.payloadLength),
        )
    }

    @Test
    fun `encodeInto is byte identical to encode`() {
        for (withAc in listOf(true, false)) {
            val expected = PppFrame.encode(PppProtocol.LCP, payload, 1, 3, withAc)
            val out = ByteArray(64) { 0x7F }
            val written = PppFrame.encodeInto(out, 7, PppProtocol.LCP, payload, 1, 3, withAc)
            assertEquals(expected.size, written)
            assertArrayEquals(expected, out.copyOfRange(7, 7 + written))
            // Nothing outside the requested window may be touched.
            assertEquals(0x7F.toByte(), out[6])
            assertEquals(0x7F.toByte(), out[7 + written])
        }
    }

    @Test
    fun `header size accounts for the address and control field`() {
        assertEquals(4, PppFrame.headerSize())
        assertEquals(2, PppFrame.headerSize(withAddressControl = false))
    }

    @Test
    fun `rejects frames that are too short`() {
        assertThrows(ProtocolException::class.java) { PppFrame.parse(ByteArray(0)) }
        assertThrows(ProtocolException::class.java) { PppFrame.parse(Bytes.fromHex("ff03")) }
        // An even first byte announces a two-byte protocol field that is not there.
        assertThrows(ProtocolException::class.java) { PppFrame.parse(Bytes.fromHex("c0")) }
        assertThrows(ProtocolException::class.java) { PppFrame.parse(Bytes.fromHex("ff03c021"), 0, 8) }
    }
}
