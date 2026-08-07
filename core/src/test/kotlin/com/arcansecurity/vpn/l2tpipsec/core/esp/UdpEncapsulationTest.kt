package com.arcansecurity.vpn.l2tpipsec.core.esp

import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspIntegrity
import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
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
        assertEquals(false, UdpEncapsulation.hasNonEspMarker(esp, 0, esp.size))
    }

    /**
     * The reader thread reuses one buffer for every datagram, so the marker probe has to stop at
     * the end of the datagram: past it lies whatever the previous packet left behind, and a
     * zero-filled tail would otherwise be read as a marker that was never received.
     */
    @Test
    fun theMarkerIsNeverSearchedPastTheDatagram() {
        val buffer = ByteArray(64) // the stale tail of a reused receive buffer, all zeros
        assertEquals(false, UdpEncapsulation.hasNonEspMarker(buffer, 0, 0))
        assertEquals(false, UdpEncapsulation.hasNonEspMarker(buffer, 0, 3))
        assertEquals(true, UdpEncapsulation.hasNonEspMarker(buffer, 0, 4))
        // Out-of-range slices are never a marker either.
        assertEquals(false, UdpEncapsulation.hasNonEspMarker(buffer, 62, 4))
        assertEquals(false, UdpEncapsulation.hasNonEspMarker(buffer, -1, 4))
    }

    /** A length whose end does not fit in an `Int` must not wrap the range check into a pass. */
    @Test
    fun rejectsARangeWhoseEndOverflows() {
        val esp = espPacket()
        assertEquals(UdpEncapsulation.Kind.UNKNOWN, UdpEncapsulation.classify(esp, 1, Int.MAX_VALUE))
        assertEquals(
            false,
            UdpEncapsulation.hasNonEspMarker(ByteArray(64), 1, Int.MAX_VALUE),
        )
    }
}
