package com.arcan.l2tpvpn.core.esp

import com.arcan.l2tpvpn.core.crypto.EspEncryption
import com.arcan.l2tpvpn.core.crypto.EspIntegrity
import com.arcan.l2tpvpn.core.util.Bytes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class UdpEncapsulationTest {

    private fun espPacket(): ByteArray = EspOutboundSa(
        0x11223344,
        EspEncryption.ESP_AES_CBC_256,
        EspIntegrity.HMAC_SHA2_256_128,
        ByteArray(32) { it.toByte() },
        ByteArray(32) { (it + 1).toByte() },
    ).encapsulate(ByteArray(100))

    @Test
    fun markerAndKeepaliveHaveTheRfcValues() {
        assertArrayEquals(Bytes.fromHex("00000000"), UdpEncapsulation.NON_ESP_MARKER)
        assertArrayEquals(Bytes.fromHex("ff"), UdpEncapsulation.NAT_KEEPALIVE)
        assertEquals(4500, UdpEncapsulation.PORT)
    }

    /** RFC 3948 section 2.2: IKE on port 4500 is prefixed with four zero bytes. */
    @Test
    fun classifiesAMarkedIkeMessage() {
        // Marker + a minimal ISAKMP header (cookies, next payload, version, exchange, flags, ...).
        val ike = UdpEncapsulation.NON_ESP_MARKER +
            Bytes.fromHex("11111111111111112222222222222222" + "01100200" + "00000000" + "0000001c")
        assertEquals(UdpEncapsulation.Kind.IKE, UdpEncapsulation.classify(ike, 0, ike.size))
    }

    @Test
    fun classifiesARealEspPacket() {
        val esp = espPacket()
        assertEquals(UdpEncapsulation.Kind.ESP, UdpEncapsulation.classify(esp, 0, esp.size))
    }

    /** RFC 3948 section 4: the keepalive is one 0xFF byte and nothing else. */
    @Test
    fun classifiesTheNatKeepalive() {
        val ka = UdpEncapsulation.NAT_KEEPALIVE
        assertEquals(UdpEncapsulation.Kind.KEEPALIVE, UdpEncapsulation.classify(ka, 0, ka.size))
    }

    @Test
    fun classifiesGarbageAsUnknown() {
        assertEquals(UdpEncapsulation.Kind.UNKNOWN, UdpEncapsulation.classify(ByteArray(0), 0, 0))
        // One byte that is not the keepalive.
        assertEquals(
            UdpEncapsulation.Kind.UNKNOWN,
            UdpEncapsulation.classify(Bytes.fromHex("01"), 0, 1),
        )
        // Non-zero SPI but far too short to hold an IV and an ICV.
        assertEquals(
            UdpEncapsulation.Kind.UNKNOWN,
            UdpEncapsulation.classify(Bytes.fromHex("1122334400000001"), 0, 8),
        )
        // The bare marker with no IKE message behind it.
        assertEquals(
            UdpEncapsulation.Kind.UNKNOWN,
            UdpEncapsulation.classify(UdpEncapsulation.NON_ESP_MARKER, 0, 4),
        )
        // Out-of-range slices are never classified.
        assertEquals(UdpEncapsulation.Kind.UNKNOWN, UdpEncapsulation.classify(espPacket(), 0, 9999))
        assertEquals(UdpEncapsulation.Kind.UNKNOWN, UdpEncapsulation.classify(espPacket(), -1, 4))
    }

    @Test
    fun classifiesAtAnOffset() {
        val esp = espPacket()
        val buffer = ByteArray(esp.size + 8)
        System.arraycopy(esp, 0, buffer, 8, esp.size)
        assertEquals(UdpEncapsulation.Kind.ESP, UdpEncapsulation.classify(buffer, 8, esp.size))
        // The zero-filled prefix looks like a marked IKE message, which is exactly the point of
        // the marker: the SPI field of an ESP packet is never zero.
        assertEquals(UdpEncapsulation.Kind.IKE, UdpEncapsulation.classify(buffer, 0, buffer.size))
    }

    @Test
    fun anEspPacketNeverLooksLikeIke() {
        val esp = espPacket()
        assertEquals(false, UdpEncapsulation.hasNonEspMarker(esp, 0))
    }
}
