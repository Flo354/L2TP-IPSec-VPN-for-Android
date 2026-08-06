package com.arcan.l2tpvpn.core.tunnel

import com.arcan.l2tpvpn.core.crypto.EspEncryption
import com.arcan.l2tpvpn.core.crypto.EspIntegrity
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

    /** Mirrors the ESP layout: SPI, sequence, IV, padded plaintext, ICV. */
    private fun onWire(payload: Int): Int {
        val block = aes256.blockBytes
        val padded = ((payload + 2 + block - 1) / block) * block
        return 4 + 4 + block + padded + sha256.icvBytes
    }
}
