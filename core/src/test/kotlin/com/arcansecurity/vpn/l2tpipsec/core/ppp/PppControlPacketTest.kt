package com.arcansecurity.vpn.l2tpipsec.core.ppp

import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import com.arcansecurity.vpn.l2tpipsec.core.util.ProtocolException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class PppControlPacketTest {

    @Test
    fun `encodes a configure request with options`() {
        val packet = PppControlPacket.ofOptions(
            PppCode.CONFIGURE_REQUEST,
            0x2A,
            listOf(
                PppOption(LcpOption.MRU, Bytes.fromHex("05dc")),
                PppOption(LcpOption.MAGIC_NUMBER, Bytes.fromHex("12345678")),
            ),
        )
        // code 01, id 2a, length 0x000e, then 01 04 05 dc and 05 06 12 34 56 78
        assertEquals("012a000e010405dc050612345678", Bytes.toHex(packet.encode()))
    }

    @Test
    fun `round trips through parse`() {
        val options = listOf(
            PppOption(LcpOption.MRU, Bytes.fromHex("05dc")),
            PppOption(LcpOption.AUTH_PROTOCOL, Bytes.fromHex("c22381")),
            PppOption(LcpOption.MAGIC_NUMBER, Bytes.fromHex("deadbeef")),
        )
        val original = PppControlPacket.ofOptions(PppCode.CONFIGURE_ACK, 7, options)
        val parsed = PppControlPacket.parse(original.encode())
        assertEquals(original, parsed)
        assertEquals(PppCode.CONFIGURE_ACK, parsed.code)
        assertEquals(7, parsed.identifier)
        assertEquals(options, parsed.options())
    }

    @Test
    fun `parses at an offset and ignores framing padding`() {
        val encoded = PppControlPacket(PppCode.ECHO_REQUEST, 3, Bytes.fromHex("00000001")).encode()
        val buffer = Bytes.concat(Bytes.fromHex("ff03c021"), encoded, Bytes.fromHex("0000"))
        val parsed = PppControlPacket.parse(buffer, 4, buffer.size - 4)
        assertEquals(PppCode.ECHO_REQUEST, parsed.code)
        assertArrayEquals(Bytes.fromHex("00000001"), parsed.data)
    }

    @Test
    fun `option list is empty for an option free packet`() {
        assertTrue(PppControlPacket(PppCode.CONFIGURE_REQUEST, 1, ByteArray(0)).options().isEmpty())
    }

    @Test
    fun `rejects a truncated packet`() {
        assertThrows(ProtocolException::class.java) { PppControlPacket.parse(Bytes.fromHex("0102")) }
    }

    @Test
    fun `rejects a length field larger than the data`() {
        // Claims 20 bytes but only 6 are present.
        assertThrows(ProtocolException::class.java) { PppControlPacket.parse(Bytes.fromHex("010200140102")) }
    }

    @Test
    fun `rejects a length field below the header size`() {
        assertThrows(ProtocolException::class.java) { PppControlPacket.parse(Bytes.fromHex("01020003ff")) }
    }

    @Test
    fun `rejects a range outside the buffer`() {
        assertThrows(ProtocolException::class.java) {
            PppControlPacket.parse(Bytes.fromHex("01020004"), 2, 8)
        }
    }

    @Test
    fun `rejects an option with an impossible length`() {
        // Option type 1 with length 1: length must cover the type and length bytes themselves.
        val packet = PppControlPacket(PppCode.CONFIGURE_REQUEST, 1, Bytes.fromHex("0101"))
        assertThrows(ProtocolException::class.java) { packet.options() }
    }

    @Test
    fun `rejects an option running past the end of the packet`() {
        val packet = PppControlPacket(PppCode.CONFIGURE_REQUEST, 1, Bytes.fromHex("010405"))
        assertThrows(ProtocolException::class.java) { packet.options() }
    }

    @Test
    fun `equality uses the content of the byte arrays`() {
        val a = PppControlPacket(1, 2, Bytes.fromHex("aabb"))
        val b = PppControlPacket(1, 2, Bytes.fromHex("aabb"))
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertEquals(PppOption(3, Bytes.fromHex("c023")), PppOption(3, Bytes.fromHex("c023")))
    }
}
