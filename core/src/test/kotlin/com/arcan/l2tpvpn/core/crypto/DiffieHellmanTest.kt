package com.arcan.l2tpvpn.core.crypto

import com.arcan.l2tpvpn.core.util.Bytes
import com.arcan.l2tpvpn.core.util.ProtocolException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.math.BigInteger

class DiffieHellmanTest {

    @Test
    fun `two parties agree on the shared secret`() {
        val group = DhGroup.MODP_1024
        val alice = DiffieHellman.generate(group)
        val bob = DiffieHellman.generate(group)

        assertArrayEquals(
            alice.computeSharedSecret(bob.publicValue),
            bob.computeSharedSecret(alice.publicValue),
        )
        assertEquals(group.valueBytes, alice.publicValue.size)
        assertNotEquals(Bytes.toHex(alice.publicValue), Bytes.toHex(bob.publicValue))
    }

    @Test
    fun `fromPrivateValue is reproducible`() {
        val priv = BigInteger("12345678901234567890123456789012345678901234567890")
        val a = DiffieHellman.fromPrivateValue(DhGroup.MODP_2048, priv)
        val b = DiffieHellman.fromPrivateValue(DhGroup.MODP_2048, priv)
        assertArrayEquals(a.publicValue, b.publicValue)
        assertEquals(DhGroup.MODP_2048.valueBytes, a.publicValue.size)
    }

    /**
     * With tiny exponents the values are only a couple of bytes wide; RFC 2409 still requires them
     * to go on the wire at the full modulus length, and SKEYID would be computed over the wrong
     * byte string otherwise.
     */
    @Test
    fun `public values and shared secrets are left-padded to the modulus length`() {
        val group = DhGroup.MODP_1024
        val alice = DiffieHellman.fromPrivateValue(group, BigInteger.valueOf(2))
        val bob = DiffieHellman.fromPrivateValue(group, BigInteger.valueOf(3))

        assertEquals(group.valueBytes, alice.publicValue.size)
        assertEquals(BigInteger.valueOf(4), BigInteger(1, alice.publicValue))
        assertEquals(BigInteger.valueOf(8), BigInteger(1, bob.publicValue))
        // 126 leading zero bytes then 0x0004.
        assertEquals("00".repeat(126) + "0004", Bytes.toHex(alice.publicValue))

        val secret = alice.computeSharedSecret(bob.publicValue)
        assertEquals(group.valueBytes, secret.size)
        assertEquals(BigInteger.valueOf(64), BigInteger(1, secret))
        assertArrayEquals(secret, bob.computeSharedSecret(alice.publicValue))
    }

    @Test
    fun `degenerate peer public values are rejected`() {
        val group = DhGroup.MODP_1024
        val alice = DiffieHellman.generate(group)
        for (bad in listOf(BigInteger.ZERO, BigInteger.ONE, group.prime - BigInteger.ONE, group.prime)) {
            assertThrows(ProtocolException::class.java) {
                alice.computeSharedSecret(Bytes.leftPad(bad.toByteArray().let {
                    if (it.size > 1 && it[0].toInt() == 0) it.copyOfRange(1, it.size) else it
                }, group.valueBytes))
            }
        }
    }
}
