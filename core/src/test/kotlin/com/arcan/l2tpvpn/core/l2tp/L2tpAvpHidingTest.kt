package com.arcan.l2tpvpn.core.l2tp

import com.arcan.l2tpvpn.core.util.Bytes
import com.arcan.l2tpvpn.core.util.ProtocolException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * AVP hiding (RFC 2661 section 4.3) and tunnel authentication (section 5.1.1).
 *
 * The hiding side is implemented here rather than in the codec on purpose: the client never hides
 * what it sends, so re-deriving the transform from the RFC is what actually validates the parser.
 */
class L2tpAvpHidingTest {

    private val secret = "sup3r-s3cr3t"
    private val randomVector = Bytes.fromHex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")

    @Test
    fun `hidden avp spanning several md5 blocks is recovered`() {
        // 20 bytes of value plus the 2-byte length and 3 bytes of padding needs two MD5 blocks.
        val challenge = Bytes.fromHex("000102030405060708090a0b0c0d0e0f10111213")
        val body = hide(L2tpAvpType.Challenge, challenge, padding = 3)
        assertEquals(25, body.size)

        val avps = parseWithVector(hiddenAvp(L2tpAvpType.Challenge, body))

        assertEquals(1, avps.size)
        assertTrue("the H bit records how the AVP arrived", avps[0].hidden)
        assertArrayEquals(challenge, avps[0].value)
    }

    @Test
    fun `hidden avp shorter than one md5 block is recovered`() {
        val value = Bytes.fromHex("cafebabedeadbeef")
        val body = hide(L2tpAvpType.Challenge, value, padding = 0)
        assertEquals(10, body.size)

        val avps = parseWithVector(hiddenAvp(L2tpAvpType.Challenge, body))
        assertArrayEquals(value, avps[0].value)
    }

    @Test
    fun `hidden avp exactly one md5 block is recovered`() {
        val value = Bytes.fromHex("00112233445566778899aabbccdd")
        val body = hide(L2tpAvpType.Challenge, value, padding = 0)
        assertEquals(16, body.size)

        val avps = parseWithVector(hiddenAvp(L2tpAvpType.Challenge, body))
        assertArrayEquals(value, avps[0].value)
    }

    @Test
    fun `random vector avp inside the message is used for the avps that follow it`() {
        val challenge = Bytes.fromHex("00112233445566778899aabbccddeeff")
        val block = L2tpCodec.encodeAvps(
            listOf(
                L2tpAvp.u16(L2tpAvpType.MessageType, L2tpMessageType.SCCRP.code),
                L2tpAvp.raw(L2tpAvpType.RandomVector, randomVector),
                hiddenAvp(L2tpAvpType.Challenge, hide(L2tpAvpType.Challenge, challenge, padding = 5)),
            ),
        )

        val avps = L2tpCodec.parseAvps(block, 0, block.size, hiddenSecret = secret)
        assertArrayEquals(challenge, avps.requireAvp(L2tpAvpType.Challenge, "SCCRP").value)
    }

    @Test
    fun `hidden avp stays opaque without the secret`() {
        val challenge = Bytes.fromHex("00112233445566778899aabbccddeeff")
        val body = hide(L2tpAvpType.Challenge, challenge, padding = 0)
        val block = L2tpCodec.encodeAvps(listOf(hiddenAvp(L2tpAvpType.Challenge, body)))

        val avps = L2tpCodec.parseAvps(block, 0, block.size)
        assertArrayEquals(body, avps[0].value)
        assertFalse(challenge.contentEquals(avps[0].value))
    }

    @Test
    fun `hidden avp without a random vector is rejected`() {
        val body = hide(L2tpAvpType.Challenge, Bytes.fromHex("00112233"), padding = 0)
        val block = L2tpCodec.encodeAvps(listOf(hiddenAvp(L2tpAvpType.Challenge, body)))

        val e = assertThrows(ProtocolException::class.java) {
            L2tpCodec.parseAvps(block, 0, block.size, hiddenSecret = secret)
        }
        assertTrue(e.message!!.contains("Random Vector"))
    }

    @Test
    fun `hidden avp with an impossible original length is rejected`() {
        // Claim 0xFFFF value bytes inside a 6-byte cleartext.
        val plain = Bytes.concat(Bytes.fromHex("ffff"), Bytes.fromHex("00112233"))
        val block = L2tpCodec.encodeAvps(
            listOf(hiddenAvp(L2tpAvpType.Challenge, obfuscate(L2tpAvpType.Challenge, plain))),
        )

        assertThrows(ProtocolException::class.java) {
            L2tpCodec.parseAvps(block, 0, block.size, hiddenSecret = secret, randomVector = randomVector)
        }
    }

    @Test
    fun `wrong secret does not recover the value`() {
        val challenge = Bytes.fromHex("00112233445566778899aabbccddeeff")
        val block = L2tpCodec.encodeAvps(
            listOf(hiddenAvp(L2tpAvpType.Challenge, hide(L2tpAvpType.Challenge, challenge, padding = 0))),
        )

        // A bad secret yields garbage; the declared length then usually fails the sanity check.
        val recovered = runCatching {
            L2tpCodec.parseAvps(block, 0, block.size, hiddenSecret = "wrong", randomVector = randomVector)
                .first().value
        }.getOrNull()
        assertFalse(challenge.contentEquals(recovered))
    }

    @Test
    fun `challenge response matches the rfc formula`() {
        val challenge = Bytes.fromHex("0102030405060708090a0b0c0d0e0f10")

        val expected = MessageDigest.getInstance("MD5").digest(
            Bytes.concat(
                byteArrayOf(L2tpMessageType.SCCCN.code.toByte()),
                secret.toByteArray(Charsets.UTF_8),
                challenge,
            ),
        )

        assertArrayEquals(expected, L2tpAuth.challengeResponse(L2tpMessageType.SCCCN, secret, challenge))
        // The message type is part of the digest, so a response is only valid for one message.
        assertFalse(
            expected.contentEquals(L2tpAuth.challengeResponse(L2tpMessageType.SCCRP, secret, challenge)),
        )
    }

    // ------------------------------------------------------------------------------- RFC 4.3

    private fun parseWithVector(avp: L2tpAvp): List<L2tpAvp> {
        val block = L2tpCodec.encodeAvps(listOf(avp))
        return L2tpCodec.parseAvps(block, 0, block.size, hiddenSecret = secret, randomVector = randomVector)
    }

    private fun hiddenAvp(type: L2tpAvpType, body: ByteArray): L2tpAvp =
        L2tpAvp(mandatory = true, hidden = true, vendorId = 0, type = type.code, value = body)

    /** Builds the hidden sub-format: 2-byte original length, the value, then arbitrary padding. */
    private fun hide(type: L2tpAvpType, value: ByteArray, padding: Int): ByteArray {
        val plain = ByteArray(2 + value.size + padding)
        plain[0] = (value.size ushr 8).toByte()
        plain[1] = value.size.toByte()
        System.arraycopy(value, 0, plain, 2, value.size)
        for (i in 0 until padding) plain[2 + value.size + i] = (0xA0 + i).toByte()
        return obfuscate(type, plain)
    }

    /**
     * The XOR chain itself: `MD5(attribute type | secret | random vector)` for the first block,
     * `MD5(secret | previous ciphertext block)` for every following one.
     */
    private fun obfuscate(type: L2tpAvpType, plain: ByteArray): ByteArray {
        val secretBytes = secret.toByteArray(Charsets.UTF_8)
        val md5 = MessageDigest.getInstance("MD5")
        md5.update(byteArrayOf((type.code ushr 8).toByte(), type.code.toByte()))
        md5.update(secretBytes)
        md5.update(randomVector)
        var pad = md5.digest()

        val out = ByteArray(plain.size)
        var i = 0
        while (i < plain.size) {
            val n = minOf(pad.size, plain.size - i)
            for (j in 0 until n) out[i + j] = (plain[i + j].toInt() xor pad[j].toInt()).toByte()
            md5.reset()
            md5.update(secretBytes)
            md5.update(out, i, n)
            pad = md5.digest()
            i += n
        }
        return out
    }
}
