package com.arcan.l2tpvpn.core.crypto

import com.arcan.l2tpvpn.core.util.Bytes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class PrfTest {

    private val sha256 = Prf(IkeHash.SHA2_256)

    /** RFC 4231 test case 1. */
    @Test
    fun `hmac sha256 matches RFC 4231 case 1`() {
        val key = ByteArray(20) { 0x0b }
        val data = "Hi There".toByteArray(Charsets.US_ASCII)
        assertEquals(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            Bytes.toHex(sha256.mac(key, data)),
        )
    }

    /** RFC 4231 test case 2, which also exercises a key shorter than the block size. */
    @Test
    fun `hmac sha256 matches RFC 4231 case 2`() {
        val key = "Jefe".toByteArray(Charsets.US_ASCII)
        val data = "what do ya want for nothing?".toByteArray(Charsets.US_ASCII)
        assertEquals(
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            Bytes.toHex(sha256.mac(key, data)),
        )
    }

    @Test
    fun `mac concatenates its parts`() {
        val key = ByteArray(20) { 0x0b }
        val whole = "Hi There".toByteArray(Charsets.US_ASCII)
        assertArrayEquals(
            sha256.mac(key, whole),
            sha256.mac(key, "Hi ".toByteArray(), "The".toByteArray(), "re".toByteArray()),
        )
    }

    @Test
    fun `digest is the plain unkeyed hash`() {
        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            Bytes.toHex(sha256.digest()),
        )
        assertEquals(32, sha256.outputBytes)
        assertEquals(16, Prf(IkeHash.MD5).outputBytes)
    }

    @Test
    fun `expand follows the K1 = mac(seed), Kn = mac(K(n-1) or seed) chain`() {
        val key = Bytes.fromHex("00112233445566778899aabbccddeeff")
        val seed = "quick mode keymat seed".toByteArray(Charsets.US_ASCII)

        val k1 = sha256.mac(key, seed)
        val k2 = sha256.mac(key, k1, seed)
        val k3 = sha256.mac(key, k2, seed)

        assertArrayEquals(k1, sha256.expand(key, seed, 32))
        assertArrayEquals(Bytes.concat(k1, k2), sha256.expand(key, seed, 64))
        assertArrayEquals(
            Bytes.truncate(Bytes.concat(k1, k2, k3), 80),
            sha256.expand(key, seed, 80),
        )
    }

    @Test
    fun `expand honours the requested length exactly`() {
        val key = ByteArray(16) { 0x42 }
        val seed = ByteArray(8)
        assertEquals(0, sha256.expand(key, seed, 0).size)
        assertEquals(1, sha256.expand(key, seed, 1).size)
        assertEquals(48, sha256.expand(key, seed, 48).size)
        assertEquals(200, sha256.expand(key, seed, 200).size)
        // A truncated request is a prefix of a longer one.
        assertArrayEquals(
            Bytes.truncate(sha256.expand(key, seed, 200), 48),
            sha256.expand(key, seed, 48),
        )
    }
}
