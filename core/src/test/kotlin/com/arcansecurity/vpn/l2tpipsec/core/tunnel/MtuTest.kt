package com.arcansecurity.vpn.l2tpipsec.core.tunnel

import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspIntegrity
import com.arcansecurity.vpn.l2tpipsec.core.esp.EspOutboundSa
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MtuTest {

    private val aes256 = EspEncryption.ESP_AES_CBC_256
    private val sha256 = EspIntegrity.HMAC_SHA2_256_128

    @Test
    fun `esp budget removes the outer ipv4 and udp headers`() {
        assertEquals(1472, Mtu.espBudget(1500))
        assertEquals(1400, Mtu.espBudget(1428))
    }

    @Test
    fun `max esp payload fits inside the budget and one more byte does not`() {
        for (budget in 200..1600 step 7) {
            val payload = Mtu.maxEspPayload(budget, aes256, sha256)
            if (payload <= 0) continue
            assertTrue("payload $payload must fit in $budget", onWire(payload) <= budget)
            assertTrue("payload ${payload + 1} must not fit in $budget", onWire(payload + 1) > budget)
        }
    }

    @Test
    fun `tunnel mtu leaves room for every inner header`() {
        val mtu = Mtu.tunnelMtu(1500, aes256, sha256, configuredCeiling = 1500)
        // An IP packet of exactly `mtu` bytes must survive PPP + L2TP + UDP + ESP inside 1472 bytes.
        val espPayload = mtu + Mtu.PPP_HEADER + Mtu.L2TP_DATA_HEADER + Mtu.INNER_UDP_HEADER
        assertTrue(onWire(espPayload) <= Mtu.espBudget(1500))
        assertTrue(onWire(espPayload + 1) > Mtu.espBudget(1500))
    }

    @Test
    fun `configured ceiling wins when it is lower`() {
        assertEquals(1400, Mtu.tunnelMtu(1500, aes256, sha256, configuredCeiling = 1400))
    }

    @Test
    fun `mtu never drops below the ipv4 minimum`() {
        assertEquals(576, Mtu.tunnelMtu(600, aes256, sha256, configuredCeiling = 1400))
    }

    /**
     * The MTU budget has to be worked out before any SA exists, so [Mtu.maxEspPayload] duplicates
     * the arithmetic of `EspOutboundSa.maxPayloadFor`. Two copies of a formula that only shows its
     * disagreement on full-size packets is exactly the wrong thing to leave to luck, so pin them
     * to each other over every algorithm pair and every interesting budget.
     */
    @Test
    fun `the mtu budget agrees with the esp layer for every algorithm`() {
        for (encryption in EspEncryption.entries) {
            for (integrity in EspIntegrity.entries) {
                val sa = EspOutboundSa(
                    spi = 0x11223344,
                    encryption = encryption,
                    integrity = integrity,
                    encryptionKey = ByteArray(encryption.keyBytes),
                    integrityKey = ByteArray(integrity.keyBytes),
                )
                for (budget in 0..1600) {
                    assertEquals(
                        "$encryption/$integrity disagree on a $budget-byte budget",
                        sa.maxPayloadFor(budget),
                        Mtu.maxEspPayload(budget, encryption, integrity),
                    )
                }
            }
        }
    }

    /**
     * The other half of the same guarantee: a payload of exactly that size really does encrypt to
     * something that fits, and one byte more does not. This is what stops both copies of the
     * formula being wrong in the same direction.
     */
    @Test
    fun `the budget the mtu hands out survives real encryption`() {
        val sa = EspOutboundSa(
            spi = 0x11223344,
            encryption = aes256,
            integrity = sha256,
            encryptionKey = ByteArray(aes256.keyBytes),
            integrityKey = ByteArray(sha256.keyBytes),
        )
        for (budget in 100..1600 step 13) {
            val payload = Mtu.maxEspPayload(budget, aes256, sha256)
            if (payload <= 0) continue
            assertTrue(
                "a $payload-byte payload overflowed a $budget-byte budget",
                sa.encapsulate(ByteArray(payload)).size <= budget,
            )
            assertTrue(
                "a ${payload + 1}-byte payload should not have fitted in $budget",
                sa.encapsulate(ByteArray(payload + 1)).size > budget,
            )
        }
    }

    /** Mirrors the ESP layout: SPI, sequence, IV, padded plaintext, ICV. */
    private fun onWire(payload: Int): Int {
        val block = aes256.blockBytes
        val padded = ((payload + 2 + block - 1) / block) * block
        return 4 + 4 + block + padded + sha256.icvBytes
    }
}
