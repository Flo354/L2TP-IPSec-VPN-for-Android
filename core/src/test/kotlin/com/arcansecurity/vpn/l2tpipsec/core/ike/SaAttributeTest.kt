package com.arcansecurity.vpn.l2tpipsec.core.ike

import com.arcansecurity.vpn.l2tpipsec.core.util.ByteReader
import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import com.arcansecurity.vpn.l2tpipsec.core.util.ProtocolException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SaAttributeTest {

    @Test
    fun `basic attributes encode as type with the top bit set plus a 16-bit value`() {
        val encoded = SaAttribute.encodeAll(
            listOf(SaAttribute.tv(Phase1Attribute.ENCRYPTION, 7)),
        )
        assertEquals("80010007", Bytes.toHex(encoded))
    }

    @Test
    fun `variable attributes encode as type, length and value`() {
        val encoded = SaAttribute.encodeAll(
            listOf(SaAttribute.tlv32(Phase1Attribute.LIFE_DURATION, 10800)),
        )
        assertEquals("000c000400002a30", Bytes.toHex(encoded))
    }

    @Test
    fun `both forms survive a round trip in one attribute list`() {
        val attributes = listOf(
            SaAttribute.tv(Phase1Attribute.ENCRYPTION, 7),
            SaAttribute.tv(Phase1Attribute.KEY_LENGTH, 256),
            SaAttribute.tv(Phase1Attribute.HASH, 4),
            SaAttribute.tlv32(Phase1Attribute.LIFE_DURATION, 28800),
            SaAttribute.tlv(99, Bytes.fromHex("deadbeefcafe")),
        )
        val decoded = SaAttribute.decodeAll(SaAttribute.encodeAll(attributes))
        assertEquals(attributes, decoded)

        assertTrue(decoded[0].basic)
        assertFalse(decoded[3].basic)
        assertEquals(7, decoded[0].intValue)
        assertEquals(256, decoded[1].intValue)
        // A four-byte life duration is the whole reason the TLV form exists here.
        assertEquals(28800, decoded[3].intValue)
        assertEquals(4, decoded[3].value.size)
    }

    @Test
    fun `a decoded basic attribute reports the 15-bit type without the flag`() {
        val decoded = SaAttribute.decodeAll(Bytes.fromHex("800e0100"))
        assertEquals(1, decoded.size)
        assertEquals(Phase1Attribute.KEY_LENGTH, decoded[0].type)
        assertEquals(256, decoded[0].intValue)
    }

    @Test
    fun `truncated attributes raise a protocol exception`() {
        assertThrows(ProtocolException::class.java) {
            SaAttribute.decodeAll(Bytes.fromHex("8001"))
        }
        assertThrows(ProtocolException::class.java) {
            // TLV announcing eight bytes but carrying two.
            SaAttribute.decodeAll(Bytes.fromHex("000c00080011"))
        }
    }

    @Test
    fun `oversized values are not integers`() {
        val attribute = SaAttribute.tlv(1, ByteArray(8))
        assertThrows(ProtocolException::class.java) { attribute.intValue }
    }

    @Test
    fun `decoding stops at the end of the reader`() {
        val reader = ByteReader(Bytes.fromHex("80010007800e0100"))
        assertEquals(2, SaAttribute.decodeAll(reader).size)
        assertFalse(reader.hasRemaining)
    }
}
