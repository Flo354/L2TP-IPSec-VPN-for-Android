package com.arcansecurity.vpn.l2tpipsec.core.crypto

import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.util.concurrent.atomic.AtomicInteger

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

    /**
     * The JCE cipher behind a [CbcCipher] is cached per thread, so one shared instance — which is
     * what the ESP layer has, encrypting the same outbound SA from the uplink thread, the
     * maintenance thread's HELLOs and the control path — must still produce byte-for-byte the same
     * result as the single-threaded case. A cache that were merely shared instead of per-thread
     * would let two packets interleave one `Cipher`'s state and corrupt both.
     */
    @Test
    fun `one shared instance produces the same bytes from many threads at once`() {
        val shared = CbcCipher.forEsp(EspEncryption.ESP_AES_CBC_256)
        val workers = 8
        val keys = List(workers) { t -> ByteArray(32) { (it * 31 + t).toByte() } }
        val ivs = List(workers) { t -> ByteArray(16) { (it * 7 + t).toByte() } }
        val plaintexts = List(workers) { t -> ByteArray(64) { (it + t * 13).toByte() } }
        // Pinned single-threaded, before any concurrency, so a race cannot corrupt the reference.
        val expected = List(workers) { t -> shared.encrypt(keys[t], ivs[t], plaintexts[t]) }

        val mismatches = AtomicInteger()
        val threads = List(workers) { t ->
            Thread {
                repeat(300) {
                    if (!shared.encrypt(keys[t], ivs[t], plaintexts[t]).contentEquals(expected[t])) {
                        mismatches.incrementAndGet()
                    }
                    if (!shared.decrypt(keys[t], ivs[t], expected[t]).contentEquals(plaintexts[t])) {
                        mismatches.incrementAndGet()
                    }
                }
            }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }
        assertEquals(0, mismatches.get())
    }

    /** Alternating transformations on one thread must not let a cached cipher answer for another. */
    @Test
    fun `interleaving transformations on one thread keeps them apart`() {
        val aes = CbcCipher.forIke(IkeEncryption.AES_CBC_128)
        val des3 = CbcCipher.forEsp(EspEncryption.ESP_3DES)
        val aesKey = ByteArray(16) { it.toByte() }
        val des3Key = ByteArray(24) { (it + 5).toByte() }

        repeat(4) {
            val aesData = ByteArray(32) { (it * 3).toByte() }
            val des3Data = ByteArray(24) { (it * 5).toByte() }
            assertArrayEquals(
                aesData,
                aes.decrypt(aesKey, iv, aes.encrypt(aesKey, iv, aesData)),
            )
            val des3Iv = ByteArray(8) { (it + 1).toByte() }
            assertArrayEquals(
                des3Data,
                des3.decrypt(des3Key, des3Iv, des3.encrypt(des3Key, des3Iv, des3Data)),
            )
        }
        // The pinned NIST vector must still hold after all that reuse.
        assertArrayEquals(ciphertext, aes256.encrypt(key, iv, plaintext))
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
