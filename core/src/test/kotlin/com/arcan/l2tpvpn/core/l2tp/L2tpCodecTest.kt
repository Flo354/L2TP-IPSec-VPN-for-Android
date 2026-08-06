package com.arcan.l2tpvpn.core.l2tp

import com.arcan.l2tpvpn.core.util.Bytes
import com.arcan.l2tpvpn.core.util.ProtocolException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Header and AVP wire format, RFC 2661 sections 3.1 and 4.1. */
class L2tpCodecTest {

    // ------------------------------------------------------------------------------- header

    @Test
    fun `control header round trips`() {
        val avps = listOf(
            L2tpAvp.u16(L2tpAvpType.MessageType, L2tpMessageType.SCCRQ.code),
            L2tpAvp.text(L2tpAvpType.HostName, "android"),
        )
        val packet = L2tpCodec.encodeControl(tunnelId = 0x1234, sessionId = 0, ns = 7, nr = 9, avps = avps)

        val (header, payloadOffset) = L2tpCodec.parseHeader(packet)
        assertTrue(header.isControl)
        assertTrue(header.hasLength)
        assertTrue(header.hasSequence)
        assertFalse(header.hasOffset)
        assertFalse(header.isPriority)
        assertEquals(L2tpCodec.VERSION, header.version)
        assertEquals(packet.size, header.length)
        assertEquals(0x1234, header.tunnelId)
        assertEquals(0, header.sessionId)
        assertEquals(7, header.ns)
        assertEquals(9, header.nr)
        assertEquals(12, header.headerSize)
        assertEquals(12, payloadOffset)
        assertEquals(avps, L2tpCodec.parseAvps(packet, payloadOffset, header.payloadLength))
    }

    @Test
    fun `zero length body is a valid control message`() {
        val zlb = L2tpCodec.encodeControl(tunnelId = 1, sessionId = 0, ns = 3, nr = 4, avps = emptyList())
        val (header, payloadOffset) = L2tpCodec.parseHeader(zlb)

        assertEquals(12, zlb.size)
        assertEquals(0, header.payloadLength)
        assertEquals(emptyList<L2tpAvp>(), L2tpCodec.parseAvps(zlb, payloadOffset, header.payloadLength))
    }

    @Test
    fun `data header round trips`() {
        val ppp = Bytes.fromHex("c021 0101 0004")
        val packet = L2tpCodec.encodeData(tunnelId = 0xABCD, sessionId = 0xEF01, payload = ppp)

        val (header, payloadOffset) = L2tpCodec.parseHeader(packet)
        assertFalse(header.isControl)
        assertTrue(header.hasLength)
        // Sequencing is pointless under ESP, so the S bit must stay clear.
        assertFalse(header.hasSequence)
        assertEquals(0xABCD, header.tunnelId)
        assertEquals(0xEF01, header.sessionId)
        assertEquals(packet.size, header.length)
        assertEquals(8, payloadOffset)
        assertArrayEquals(ppp, packet.copyOfRange(payloadOffset, payloadOffset + header.payloadLength))
    }

    @Test
    fun `data header without the length bit uses the received size`() {
        val ppp = Bytes.fromHex("c0210101")
        val packet = L2tpCodec.encodeData(1, 2, ppp, includeLength = false)

        val (header, payloadOffset) = L2tpCodec.parseHeader(packet)
        assertFalse(header.hasLength)
        assertEquals(6, payloadOffset)
        assertEquals(packet.size, header.length)
        assertArrayEquals(ppp, packet.copyOfRange(payloadOffset, payloadOffset + header.payloadLength))
    }

    @Test
    fun `hand written control header decodes`() {
        // T=1 L=1 S=1 ver=2, length 12, tunnel 0x1234, session 0, Ns=1, Nr=2: a ZLB acknowledgement.
        val packet = Bytes.fromHex("c802 000c 1234 0000 0001 0002")
        val (header, payloadOffset) = L2tpCodec.parseHeader(packet)

        assertTrue(header.isControl)
        assertEquals(12, header.length)
        assertEquals(0x1234, header.tunnelId)
        assertEquals(0, header.sessionId)
        assertEquals(1, header.ns)
        assertEquals(2, header.nr)
        assertEquals(0, header.payloadLength)
        assertEquals(12, payloadOffset)
    }

    @Test
    fun `hand written data header decodes`() {
        // L=1 ver=2, length 10, tunnel 0x1234, session 0x5678, two payload bytes.
        val packet = Bytes.fromHex("4002 000a 1234 5678 aabb")
        val (header, payloadOffset) = L2tpCodec.parseHeader(packet)

        assertFalse(header.isControl)
        assertTrue(header.hasLength)
        assertFalse(header.hasSequence)
        assertEquals(10, header.length)
        assertEquals(0x1234, header.tunnelId)
        assertEquals(0x5678, header.sessionId)
        assertEquals(8, payloadOffset)
        assertArrayEquals(Bytes.fromHex("aabb"), packet.copyOfRange(payloadOffset, packet.size))
    }

    @Test
    fun `hand written header with the offset field skips the padding`() {
        // L=1 O=1 ver=2, length 14, offset size 2 so "dead" is padding and "beef" is the payload.
        val packet = Bytes.fromHex("4202 000e 1111 2222 0002 dead beef")
        val (header, payloadOffset) = L2tpCodec.parseHeader(packet)

        assertTrue(header.hasOffset)
        assertEquals(2, header.offsetSize)
        assertEquals(14, header.length)
        assertEquals(12, header.headerSize)
        assertEquals(12, payloadOffset)
        assertEquals(2, header.payloadLength)
        assertArrayEquals(Bytes.fromHex("beef"), packet.copyOfRange(payloadOffset, packet.size))
    }

    @Test
    fun `priority bit is decoded`() {
        // L=1 P=1 ver=2.
        val packet = Bytes.fromHex("4102 000a 1111 2222 aabb")
        val (header, _) = L2tpCodec.parseHeader(packet)
        assertTrue(header.isPriority)
    }

    @Test
    fun `version other than 2 is rejected`() {
        val v3 = Bytes.fromHex("c803 000c 1234 0000 0001 0002")
        val e = assertThrows(ProtocolException::class.java) { L2tpCodec.parseHeader(v3) }
        assertTrue(e.message!!.contains("version 3"))
    }

    @Test
    fun `truncated header is rejected`() {
        // Stops in the middle of the Nr field.
        val short = Bytes.fromHex("c802 000c 1234 0000 0001")
        assertThrows(ProtocolException::class.java) { L2tpCodec.parseHeader(short) }
    }

    @Test
    fun `declared length beyond the received bytes is rejected`() {
        val packet = Bytes.fromHex("c802 0014 1234 0000 0001 0002")
        val e = assertThrows(ProtocolException::class.java) { L2tpCodec.parseHeader(packet) }
        assertTrue(e.message!!.contains("truncated"))
    }

    @Test
    fun `declared length shorter than the header is rejected`() {
        val packet = Bytes.fromHex("c802 0004 1234 0000 0001 0002")
        assertThrows(ProtocolException::class.java) { L2tpCodec.parseHeader(packet) }
    }

    @Test
    fun `offset field beyond the received bytes is rejected`() {
        // Offset size 0x0010 with nothing behind it.
        val packet = Bytes.fromHex("4202 000e 1111 2222 0010 dead beef")
        assertThrows(ProtocolException::class.java) { L2tpCodec.parseHeader(packet) }
    }

    @Test
    fun `control message without the length and sequence bits is rejected`() {
        val packet = Bytes.fromHex("8002 1234 0000")
        val e = assertThrows(ProtocolException::class.java) { L2tpCodec.parseHeader(packet) }
        assertTrue(e.message!!.contains("L and S"))
    }

    @Test
    fun `range outside the buffer is rejected`() {
        val packet = Bytes.fromHex("c802 000c 1234 0000 0001 0002")
        assertThrows(ProtocolException::class.java) { L2tpCodec.parseHeader(packet, 4, 20) }
    }

    @Test
    fun `header is parsed at an offset inside a larger buffer`() {
        val packet = L2tpCodec.encodeData(0x1111, 0x2222, Bytes.fromHex("aabbcc"))
        val embedded = Bytes.concat(ByteArray(16), packet, ByteArray(7))

        val (header, payloadOffset) = L2tpCodec.parseHeader(embedded, 16, packet.size)
        assertEquals(0x1111, header.tunnelId)
        assertEquals(16 + 8, payloadOffset)
        assertArrayEquals(
            Bytes.fromHex("aabbcc"),
            embedded.copyOfRange(payloadOffset, payloadOffset + header.payloadLength),
        )
    }

    // ---------------------------------------------------------------------------------- AVPs

    @Test
    fun `avp round trip preserves every field`() {
        val avps = listOf(
            L2tpAvp.u16(L2tpAvpType.MessageType, L2tpMessageType.SCCRQ.code),
            L2tpAvp.u32(L2tpAvpType.FramingCapabilities, 0x0000_0003L, mandatory = false),
            L2tpAvp.text(L2tpAvpType.HostName, "livebox-pro"),
            L2tpAvp.raw(L2tpAvpType.Challenge, Bytes.fromHex("00112233445566778899aabbccddeeff")),
            // Hidden AVPs stay verbatim when no secret is supplied, which is what lets them round trip.
            L2tpAvp(mandatory = true, hidden = true, vendorId = 0, type = L2tpAvpType.Challenge.code, value = Bytes.fromHex("cafebabe")),
            // A vendor-specific AVP with an empty value: the shortest legal AVP.
            L2tpAvp(mandatory = false, hidden = false, vendorId = 0x9999, type = 3, value = ByteArray(0)),
        )

        val encoded = L2tpCodec.encodeAvps(avps)
        assertEquals(avps, L2tpCodec.parseAvps(encoded, 0, encoded.size))
    }

    @Test
    fun `avp accessors decode their values`() {
        assertEquals(0x0100, L2tpAvp.u16(L2tpAvpType.ProtocolVersion, 0x0100).asU16())
        assertEquals(100_000_000L, L2tpAvp.u32(L2tpAvpType.TxConnectSpeed, 100_000_000L).asU32())
        assertEquals(0xFFFF_FFFFL, L2tpAvp.u32(L2tpAvpType.TxConnectSpeed, 0xFFFF_FFFFL).asU32())
        assertEquals("android", L2tpAvp.text(L2tpAvpType.HostName, "android").asText())
        // Some LNSes NUL-terminate their host name; it must not leak into the UI.
        assertEquals("livebox", L2tpAvp.raw(L2tpAvpType.HostName, Bytes.fromHex("6c697665626f7800")).asText())
    }

    @Test
    fun `avp accessors reject values of the wrong size`() {
        val avp = L2tpAvp.raw(L2tpAvpType.Challenge, Bytes.fromHex("aabbcc"))
        assertThrows(ProtocolException::class.java) { avp.asU16() }
        assertThrows(ProtocolException::class.java) { avp.asU32() }
    }

    @Test
    fun `hand written SCCRQ avp block decodes`() {
        val block = Bytes.fromHex(
            "8008 0000 0000 0001" + // Message Type = SCCRQ
                "8008 0000 0002 0100" + // Protocol Version = 1.0
                "8009 0000 0007 616263" + // Host Name = "abc"
                "800a 0000 0003 00000003" + // Framing Capabilities = async + sync
                "8008 0000 0009 1234", // Assigned Tunnel ID
        )

        val avps = L2tpCodec.parseAvps(block, 0, block.size)
        assertEquals(5, avps.size)
        assertTrue(avps.all { it.mandatory && !it.hidden && it.vendorId == 0 })
        assertEquals(L2tpMessageType.SCCRQ.code, avps[0].asU16())
        assertEquals(L2tpAvpType.MessageType, avps[0].avpType)
        assertEquals(0x0100, avps[1].asU16())
        assertEquals("abc", avps[2].asText())
        assertEquals(3L, avps[3].asU32())
        assertEquals(0x1234, avps[4].asU16())
        assertEquals(0x1234, avps.requireAvp(L2tpAvpType.AssignedTunnelId, "SCCRQ").asU16())
        assertNull(avps.find(L2tpAvpType.Challenge))
        assertThrows(ProtocolException::class.java) { avps.requireAvp(L2tpAvpType.Challenge, "SCCRQ") }
    }

    @Test
    fun `avp length shorter than the avp header is rejected`() {
        val block = Bytes.fromHex("8005 0000 0007 616263")
        val e = assertThrows(ProtocolException::class.java) { L2tpCodec.parseAvps(block, 0, block.size) }
        assertTrue(e.message!!.contains("shorter"))
    }

    @Test
    fun `avp length beyond the message is rejected`() {
        val block = Bytes.fromHex("8020 0000 0007 616263")
        val e = assertThrows(ProtocolException::class.java) { L2tpCodec.parseAvps(block, 0, block.size) }
        assertTrue(e.message!!.contains("overruns"))
    }

    @Test
    fun `trailing garbage after the last avp is rejected`() {
        val block = Bytes.fromHex("8008 0000 0000 0001 8008")
        assertThrows(ProtocolException::class.java) { L2tpCodec.parseAvps(block, 0, block.size) }
    }

    @Test
    fun `avp longer than the 10 bit length field is rejected`() {
        val huge = L2tpAvp.raw(L2tpAvpType.Challenge, ByteArray(L2tpAvp.MAX_ENCODED_SIZE))
        assertThrows(IllegalArgumentException::class.java) { L2tpCodec.encodeAvps(listOf(huge)) }
    }

    @Test
    fun `mandatory and hidden bits survive the wire`() {
        val block = L2tpCodec.encodeAvps(
            listOf(
                L2tpAvp(mandatory = true, hidden = false, vendorId = 0, type = 1, value = ByteArray(0)),
                L2tpAvp(mandatory = false, hidden = true, vendorId = 0, type = 2, value = ByteArray(0)),
                L2tpAvp(mandatory = true, hidden = true, vendorId = 0, type = 3, value = ByteArray(0)),
                L2tpAvp(mandatory = false, hidden = false, vendorId = 0, type = 4, value = ByteArray(0)),
            ),
        )
        assertEquals("8006 4006 c006 0006", flagWords(block))
    }

    // ------------------------------------------------------------------------------ data path

    @Test
    fun `encodeDataInto is byte identical to encodeData`() {
        val ppp = Bytes.random(64)
        for (includeLength in listOf(true, false)) {
            val expected = L2tpCodec.encodeData(0x1234, 0x5678, ppp, 8, 40, includeLength)

            val scratch = ByteArray(expected.size + 24)
            val written = L2tpCodec.encodeDataInto(scratch, 11, 0x1234, 0x5678, ppp, 8, 40, includeLength)

            assertEquals(expected.size, written)
            assertArrayEquals(expected, scratch.copyOfRange(11, 11 + written))
        }
    }

    @Test
    fun `data header size matches what the encoder emits`() {
        for (includeLength in listOf(true, false)) {
            val packet = L2tpCodec.encodeData(1, 2, ByteArray(37), includeLength = includeLength)
            assertEquals(L2tpCodec.dataHeaderSize(includeLength), packet.size - 37)

            val (header, payloadOffset) = L2tpCodec.parseHeader(packet)
            assertEquals(L2tpCodec.dataHeaderSize(includeLength), payloadOffset)
            assertEquals(L2tpCodec.dataHeaderSize(includeLength), header.headerSize)
            assertEquals(37, header.payloadLength)
        }
    }

    @Test
    fun `encodeDataInto validates its ranges`() {
        assertThrows(IllegalArgumentException::class.java) {
            L2tpCodec.encodeDataInto(ByteArray(10), 0, 1, 2, ByteArray(8), 0, 8)
        }
        assertThrows(IllegalArgumentException::class.java) {
            L2tpCodec.encodeDataInto(ByteArray(64), 0, 1, 2, ByteArray(8), 4, 8)
        }
    }

    /** Renders the first 16-bit word of every AVP so flag bits can be asserted directly. */
    private fun flagWords(block: ByteArray): String {
        val words = mutableListOf<String>()
        var i = 0
        while (i < block.size) {
            words += Bytes.toHex(block.copyOfRange(i, i + 2))
            i += (block[i].toInt() and 0x03 shl 8) or (block[i + 1].toInt() and 0xFF)
        }
        return words.joinToString(" ")
    }
}
