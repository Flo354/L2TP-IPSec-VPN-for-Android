package com.arcansecurity.vpn.l2tpipsec.core.ppp

import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/** The RFC 2759 section 9.2 test vector, checked step by step. */
class MsChapV2Test {

    private val userName = "User"
    private val password = "clientPass"
    private val authenticatorChallenge = Bytes.fromHex("5B5D7C7D7B3F2F3E3C2C602132262628")
    private val peerChallenge = Bytes.fromHex("21402324255E262A28295F2B3A337C7E")

    @Test
    fun `challenge hash matches the rfc`() {
        assertEquals(
            "d02e4386bce91226",
            Bytes.toHex(MsChapV2.challengeHash(peerChallenge, authenticatorChallenge, userName)),
        )
    }

    @Test
    fun `nt password hash matches the rfc`() {
        assertEquals("44ebba8d5312b8d611474411f56989ae", Bytes.toHex(MsChapV2.ntPasswordHash(password)))
    }

    @Test
    fun `hashed nt password hash matches the rfc`() {
        assertEquals(
            "41c00c584bd2d91c4017a2a12fa59f3f",
            Bytes.toHex(MsChapV2.hashNtPasswordHash(MsChapV2.ntPasswordHash(password))),
        )
    }

    @Test
    fun `nt response matches the rfc`() {
        val ntResponse = MsChapV2.generateNtResponse(authenticatorChallenge, peerChallenge, userName, password)
        assertEquals(24, ntResponse.size)
        assertEquals("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF", Bytes.toHex(ntResponse).uppercase())
    }

    @Test
    fun `authenticator response matches the rfc`() {
        val ntResponse = MsChapV2.generateNtResponse(authenticatorChallenge, peerChallenge, userName, password)
        val response = MsChapV2.generateAuthenticatorResponse(
            password, ntResponse, peerChallenge, authenticatorChallenge, userName,
        )
        assertEquals("S=407A5589115FD0D6209F510FE9C04566932CDA56", response)
    }

    @Test
    fun `a different password yields a different authenticator response`() {
        val ntResponse = MsChapV2.generateNtResponse(authenticatorChallenge, peerChallenge, userName, password)
        assertNotEquals(
            MsChapV2.generateAuthenticatorResponse(
                password, ntResponse, peerChallenge, authenticatorChallenge, userName,
            ),
            MsChapV2.generateAuthenticatorResponse(
                "wrongPass", ntResponse, peerChallenge, authenticatorChallenge, userName,
            ),
        )
    }

    @Test
    fun `des key expansion spreads seven bytes over eight with odd parity`() {
        val expanded = MsChapV2.expandDesKey(Bytes.fromHex("ffffffffffffff"), 0)
        assertEquals("fefefefefefefefe", Bytes.toHex(expanded))
        for (b in expanded) {
            assertEquals(1, Integer.bitCount(b.toInt() and 0xFF) and 1)
        }
    }

    @Test
    fun `password is hashed as utf16 little endian`() {
        // Non-ASCII passwords must not be mangled into ISO-8859-1 or UTF-8.
        assertEquals(
            Bytes.toHex(Md4.digest("pässword".toByteArray(Charsets.UTF_16LE))),
            Bytes.toHex(MsChapV2.ntPasswordHash("pässword")),
        )
    }
}
