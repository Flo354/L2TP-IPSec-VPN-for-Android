package com.arcansecurity.vpn.l2tpipsec.core.ppp

import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import org.junit.Assert.assertEquals
import org.junit.Test

/** The complete RFC 1320 appendix A.5 test suite. */
class Md4Test {

    private fun md4(s: String) = Bytes.toHex(Md4.digest(s.toByteArray(Charsets.US_ASCII)))

    @Test
    fun `empty string`() {
        assertEquals("31d6cfe0d16ae931b73c59d7e0c089c0", md4(""))
    }

    @Test
    fun `single character`() {
        assertEquals("bde52cb31de33e46245e05fbdbd6fb24", md4("a"))
    }

    @Test
    fun abc() {
        assertEquals("a448017aaf21d8525fc10ae87aa6729d", md4("abc"))
    }

    @Test
    fun `message digest`() {
        assertEquals("d9130a8164549fe818874806e1c7014b", md4("message digest"))
    }

    @Test
    fun alphabet() {
        assertEquals("d79e1c308aa5bbcdeea8ed63df412da9", md4("abcdefghijklmnopqrstuvwxyz"))
    }

    @Test
    fun `alphanumeric alphabet`() {
        assertEquals(
            "043f8582f241db351ce627e153e7f0e4",
            md4("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
        )
    }

    @Test
    fun `eighty digits`() {
        // Crosses the 64-byte block boundary, which exercises the padding of a second block.
        assertEquals("e33b4ddc9c38f2199c3e7b164fcc0536", md4("1234567890".repeat(8)))
    }

    @Test
    fun `digest is always sixteen bytes`() {
        for (size in 0..200) {
            assertEquals(16, Md4.digest(ByteArray(size) { it.toByte() }).size)
        }
    }
}
