package com.arcan.l2tpvpn.core.crypto

import com.arcan.l2tpvpn.core.util.Bytes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class CbcCipherTest {

    // NIST SP 800-38A section F.2.5 / F.2.6, CBC-AES256.
    private val key = Bytes.fromHex("603deb1015ca71be2b73aef0857d7781 1f352c073b6108d72d9810a30914dff4")
    private val iv = Bytes.fromHex("000102030405060708090a0b0c0d0e0f")
    private val plaintext = Bytes.fromHex(
        "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411e5fbc1191a0a52ef" +
            "f69f2445df4f9b17ad2b417be66c3710",
    )
    private val ciphertext = Bytes.fromHex(
        "f58c4c04d6e5f1ba779eabfb5f7bfbd6" +
            "9cfc4e967edb808d679f777bc6702c7d" +
            "39f23369a9d9bacfa530e26304231461" +
            "b2eb05e2c39be9fcda6c19078c6a9d1b",
    )

    private val aes256 = CbcCipher.forIke(IkeEncryption.AES_CBC_256)

    @Test
    fun `aes 256 cbc encryption matches NIST SP 800-38A F 2 5`() {
        assertArrayEquals(ciphertext, aes256.encrypt(key, iv, plaintext))
    }

    @Test
    fun `aes 256 cbc decryption matches NIST SP 800-38A F 2 6`() {
        assertArrayEquals(plaintext, aes256.decrypt(key, iv, ciphertext))
    }

    @Test
    fun `round trip over every supported transform`() {
        val transforms = listOf(
            CbcCipher.forIke(IkeEncryption.TRIPLE_DES_CBC) to IkeEncryption.TRIPLE_DES_CBC.keyBytes,
            CbcCipher.forIke(IkeEncryption.AES_CBC_128) to IkeEncryption.AES_CBC_128.keyBytes,
            CbcCipher.forIke(IkeEncryption.AES_CBC_192) to IkeEncryption.AES_CBC_192.keyBytes,
            CbcCipher.forEsp(EspEncryption.ESP_3DES) to EspEncryption.ESP_3DES.keyBytes,
            CbcCipher.forEsp(EspEncryption.ESP_AES_CBC_256) to EspEncryption.ESP_AES_CBC_256.keyBytes,
        )
        for ((cipher, keyBytes) in transforms) {
            val k = ByteArray(keyBytes) { it.toByte() }
            val blockIv = ByteArray(cipher.blockBytes) { (it * 7).toByte() }
            val data = ByteArray(cipher.blockBytes * 3) { (it * 3 + 1).toByte() }
            assertArrayEquals(
                "round trip failed for ${cipher.transformation}",
                data,
                cipher.decrypt(k, blockIv, cipher.encrypt(k, blockIv, data)),
            )
        }
    }

    @Test
    fun `block sizes come from the algorithm table`() {
        assertEquals(16, CbcCipher.forIke(IkeEncryption.AES_CBC_128).blockBytes)
        assertEquals(8, CbcCipher.forIke(IkeEncryption.TRIPLE_DES_CBC).blockBytes)
        assertEquals(8, CbcCipher.forEsp(EspEncryption.ESP_3DES).blockBytes)
    }

    @Test
    fun `unaligned input and wrong sized ivs are refused`() {
        assertThrows(IllegalArgumentException::class.java) {
            aes256.encrypt(key, iv, ByteArray(17))
        }
        assertThrows(IllegalArgumentException::class.java) {
            aes256.encrypt(key, ByteArray(8), ByteArray(16))
        }
    }
}
