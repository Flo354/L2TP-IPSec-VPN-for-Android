package com.arcansecurity.vpn.l2tpipsec.core.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The MODP primes are transcribed by hand from RFC 2409 and RFC 3526. A single mistyped nibble
 * would still produce a plausible-looking key exchange that silently fails to agree with the peer,
 * so the bit length and the primality are checked here rather than discovered in the field.
 */
class PrimeSanityTest {

    @Test
    fun `each group advertises the bit length its name claims`() {
        assertEquals(1024, DhGroup.MODP_1024.prime.bitLength())
        assertEquals(1536, DhGroup.MODP_1536.prime.bitLength())
        assertEquals(2048, DhGroup.MODP_2048.prime.bitLength())
    }

    @Test
    fun `every modulus is prime`() {
        for (group in DhGroup.entries) {
            assertTrue("$group modulus is not prime", group.prime.isProbablePrime(64))
        }
    }

    @Test
    fun `value length matches the modulus length`() {
        assertEquals(128, DhGroup.MODP_1024.valueBytes)
        assertEquals(192, DhGroup.MODP_1536.valueBytes)
        assertEquals(256, DhGroup.MODP_2048.valueBytes)
    }

    @Test
    fun `group ids are the IANA numbers and are looked up by id`() {
        assertEquals(DhGroup.MODP_1024, DhGroup.find(2))
        assertEquals(DhGroup.MODP_1536, DhGroup.find(5))
        assertEquals(DhGroup.MODP_2048, DhGroup.find(14))
        assertEquals(null, DhGroup.find(99))
    }
}
