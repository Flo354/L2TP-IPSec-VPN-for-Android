package com.arcansecurity.vpn.l2tpipsec.core.ike

import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeHash
import com.arcansecurity.vpn.l2tpipsec.core.crypto.Prf
import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Pinned key schedule. The expected values were produced by an independent implementation of
 * RFC 2409 section 5 (python `hmac`), so a refactor that quietly reorders a concatenation is
 * caught here instead of by a server that drops every ESP packet.
 */
class IkeKeyDerivationTest {

    private val psk = "s3cr3t-psk".toByteArray(Charsets.UTF_8)
    private val ni = ByteArray(32) { it.toByte() }
    private val nr = ByteArray(32) { (it + 0x20).toByte() }
    private val gxy = ByteArray(64) { (it + 0x40).toByte() }
    private val gxi = ByteArray(64) { (it + 0x80).toByte() }
    private val gxr = ByteArray(64) { (it + 0xc0).toByte() }
    private val initiatorCookie = Bytes.fromHex("0011223344556677")
    private val responderCookie = Bytes.fromHex("8899aabbccddeeff")

    private val saBody = Bytes.fromHex(
        "00000001" + "00000001" + "00000030" + "01010001" + "00000028" + "01010000" +
            "80010007" + "800e0100" + "80020004" + "80030001" + "8004000e" + "800b0001" +
            "000c000400002a30",
    )
    private val idBody = Bytes.fromHex("01000000c0a80105")

    @Test
    fun `SKEYID chain is pinned for SHA-256 with AES-256`() {
        val keys = IkeKeyDerivation.phase1(
            Prf(IkeHash.SHA2_256), psk, ni, nr, gxy, initiatorCookie, responderCookie,
            IkeEncryption.AES_CBC_256.keyBytes,
        )
        assertEquals(
            "b03cec7f06e64d478406ab62f1b94974efe863f7f30cffa85b996716cf18cd00",
            Bytes.toHex(keys.skeyid),
        )
        assertEquals(
            "92e01b5f4dc148b263fc1c2a35fc326ad09a4d046e01017f4b5f7d8e0e0c6bfe",
            Bytes.toHex(keys.skeyidD),
        )
        assertEquals(
            "54435a1d294c04b8ededdd8955e6b6835bf61da7d2bb414d8c7a3466ae9607f2",
            Bytes.toHex(keys.skeyidA),
        )
        assertEquals(
            "fe720f35946b4ce45c9efff2df59eda9b0989eff437ba483bef9788328c4c0da",
            Bytes.toHex(keys.skeyidE),
        )
        // SHA-256 produces exactly the 32 bytes AES-256 needs, so no expansion happens.
        assertArrayEquals(keys.skeyidE, keys.encryptionKey)
    }

    @Test
    fun `HASH_I and HASH_R are pinned and differ only by the swapped roles`() {
        val prf = Prf(IkeHash.SHA2_256)
        val skeyid = Bytes.fromHex("b03cec7f06e64d478406ab62f1b94974efe863f7f30cffa85b996716cf18cd00")

        val hashI = IkeKeyDerivation.phase1AuthHash(
            prf, skeyid, gxi, gxr, initiatorCookie, responderCookie, saBody, idBody,
        )
        val hashR = IkeKeyDerivation.phase1AuthHash(
            prf, skeyid, gxr, gxi, responderCookie, initiatorCookie, saBody, idBody,
        )
        assertEquals(
            "71fe20b6e9cbc4edc53f32d782a1b4f8fdc1b201ed365ed038f219821505b5fb",
            Bytes.toHex(hashI),
        )
        assertEquals(
            "38d25bcb2af68b9afa6ddcff48bdb43c73a2c030d4ec93077b8eda42a564d278",
            Bytes.toHex(hashR),
        )
    }

    @Test
    fun `KEYMAT is pinned`() {
        val keymat = IkeKeyDerivation.keymat(
            Prf(IkeHash.SHA2_256),
            Bytes.fromHex("92e01b5f4dc148b263fc1c2a35fc326ad09a4d046e01017f4b5f7d8e0e0c6bfe"),
            ByteArray(0),
            ProtocolId.ESP,
            0xdeadbeef.toInt(),
            ni,
            nr,
            48,
        )
        assertEquals(
            "cc4a8a21fa2308ba8ff2d8228396f92320b47188b95965d8e0913a5b9fa93c67" +
                "5068380f2cdb7e4f2a8e9b93fa6f6f69",
            Bytes.toHex(keymat),
        )
    }

    /** MD5 gives a 16-byte SKEYID_e, so 3DES forces the RFC 2409 appendix B expansion. */
    @Test
    fun `a short SKEYID_e is stretched per appendix B`() {
        val keys = IkeKeyDerivation.phase1(
            Prf(IkeHash.MD5), psk, ni, nr, gxy, initiatorCookie, responderCookie,
            IkeEncryption.TRIPLE_DES_CBC.keyBytes,
        )
        assertEquals("2e6ed2cf69af878e19749c14981adec6", Bytes.toHex(keys.skeyid))
        assertEquals("5b9f14c50872c3ce4cb6b21f1b51527e", Bytes.toHex(keys.skeyidD))
        assertEquals("fd87e2eb980acef5e5aa8af366389d47", Bytes.toHex(keys.skeyidA))
        assertEquals("c504e20a608f1867886abfd03466f700", Bytes.toHex(keys.skeyidE))
        assertEquals(24, keys.encryptionKey.size)
        assertEquals(
            "88de5b8e736c7a6bedca1d6f4964ad786e881530e931d0a1",
            Bytes.toHex(keys.encryptionKey),
        )
    }

    /**
     * The appendix B stretch does *not* repeat the seed in later blocks, unlike [Prf.expand];
     * mixing the two up produces a key that is right for the first block and wrong afterwards.
     */
    @Test
    fun `appendix B expansion differs from the quick mode expansion`() {
        val prf = Prf(IkeHash.MD5)
        val skeyidE = Bytes.fromHex("c504e20a608f1867886abfd03466f700")
        val appendixB = IkeKeyDerivation.cipherKey(prf, skeyidE, 24)
        val quickMode = prf.expand(skeyidE, ByteArray(1), 24)
        assertArrayEquals(Bytes.truncate(appendixB, 16), Bytes.truncate(quickMode, 16))
        assertEquals(false, Bytes.constantTimeEquals(appendixB, quickMode))
    }
}
