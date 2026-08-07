package com.arcansecurity.vpn.l2tpipsec.core.esp

import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspIntegrity
import com.arcansecurity.vpn.l2tpipsec.core.net.Ipv4Header
import com.arcansecurity.vpn.l2tpipsec.core.net.UdpDatagram
import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * End-to-end tests of the ESP transport-mode layer. Every "payload" here is a transport-layer
 * datagram, never an inner IP packet: that is what transport mode protects (RFC 3948 section 2.1).
 */
class EspSaTest {

    private class Suite(
        val encryption: EspEncryption,
        val integrity: EspIntegrity,
        val spi: Int = 0x11223344,
    ) {
        val encryptionKey = ByteArray(encryption.keyBytes) { (it * 3 + 1).toByte() }
        val integrityKey = ByteArray(integrity.keyBytes) { (it * 5 + 2).toByte() }

        fun outbound() = EspOutboundSa(spi, encryption, integrity, encryptionKey, integrityKey)
        fun inbound(windowSize: Int = 64) =
            EspInboundSa(spi, encryption, integrity, encryptionKey, integrityKey, windowSize)

        override fun toString() = "${encryption.name}/${integrity.name}"
    }

    private val suites = listOf(
        Suite(EspEncryption.ESP_AES_CBC_256, EspIntegrity.HMAC_SHA2_256_128),
        Suite(EspEncryption.ESP_3DES, EspIntegrity.HMAC_SHA1_96),
    )

    private fun payload(n: Int) = ByteArray(n) { (it * 7 + 3).toByte() }

    // ---------------------------------------------------------------- round trip

    @Test
    fun roundTripsEveryPaddingCase() {
        for (suite in suites) {
            val block = suite.encryption.blockBytes
            // 0 / 1 / block-3 / block / block+1 exercise every possible pad length, 1400 is a
            // full-size inner datagram.
            for (size in listOf(0, 1, block - 3, block, block + 1, 1400)) {
                val out = suite.outbound()
                val inb = suite.inbound()
                val original = payload(size)
                val packet = out.encapsulate(original)

                // 4 + 4 + IV + ciphertext + ICV, with the ciphertext a whole number of blocks.
                val ciphertext = packet.size - 8 - block - suite.integrity.icvBytes
                assertEquals("$suite/$size ciphertext blocks", 0, ciphertext % block)
                assertTrue("$suite/$size ciphertext covers payload", ciphertext >= size + 2)

                val result = inb.decapsulate(packet)
                assertArrayEquals("$suite/$size", original, result.payload)
                assertEquals(Ipv4Header.PROTO_UDP, result.nextHeader)
                assertEquals(1L, result.sequenceNumber)
                assertEquals(1L, inb.packetsAccepted)
                assertEquals(0L, inb.packetsDropped)
            }
        }
    }

    @Test
    fun roundTripsAWholeInnerUdpDatagram() {
        // The realistic shape: a UDP/1701 datagram carrying L2TP, protected in transport mode.
        val suite = suites[0]
        val l2tp = Bytes.fromHex("c802000c00010000000000000000")
        val datagram = UdpDatagram.encode(UdpDatagram.L2TP_PORT, UdpDatagram.L2TP_PORT, l2tp)
        val result = suite.inbound().decapsulate(suite.outbound().encapsulate(datagram))
        assertArrayEquals(datagram, result.payload)
        assertEquals(Ipv4Header.PROTO_UDP, result.nextHeader)

        val parsed = UdpDatagram.parse(result.payload)
        assertEquals(UdpDatagram.L2TP_PORT, parsed.destinationPort)
        assertEquals(l2tp.size, parsed.payloadLength)
    }

    @Test
    fun sequenceNumbersStartAtOneAndIncrease() {
        for (suite in suites) {
            val out = suite.outbound()
            val inb = suite.inbound()
            assertEquals(0L, out.sequenceNumber)
            for (expected in 1L..20L) {
                val result = inb.decapsulate(out.encapsulate(payload(64)))
                assertEquals("$suite", expected, result.sequenceNumber)
                assertEquals("$suite", expected, out.sequenceNumber)
            }
        }
    }

    @Test
    fun encapsulatesFromAnOffsetAndCarriesAnArbitraryNextHeader() {
        val suite = suites[0]
        val framed = Bytes.fromHex("deadbeef") + payload(50) + Bytes.fromHex("cafe")
        val packet = suite.outbound()
            .encapsulate(framed, 4, 50, nextHeader = Ipv4Header.PROTO_TCP)
        val result = suite.inbound().decapsulate(packet)
        assertArrayEquals(payload(50), result.payload)
        assertEquals(Ipv4Header.PROTO_TCP, result.nextHeader)
    }

    /** `encapsulate(buffer, offset)` means "from [offset] to the end", like every range API here. */
    @Test
    fun encapsulateWithoutALengthTakesTheRestOfTheBuffer() {
        val suite = suites[0]
        val framed = Bytes.fromHex("deadbeef") + payload(50)
        val result = suite.inbound().decapsulate(suite.outbound().encapsulate(framed, 4))
        assertArrayEquals(payload(50), result.payload)
    }

    /** The next-header field is one byte on the wire, so a wider value must not be truncated. */
    @Test
    fun rejectsANextHeaderThatDoesNotFitInAByte() {
        val suite = suites[0]
        for (bad in listOf(-1, 256, 0x1FF)) {
            try {
                suite.outbound().encapsulate(payload(8), nextHeader = bad)
                fail("expected IllegalArgumentException for next header $bad")
            } catch (expected: IllegalArgumentException) {
                // ok
            }
        }
    }

    @Test
    fun decapsulatesFromAnOffsetInsideALargerBuffer() {
        val suite = suites[0]
        val packet = suite.outbound().encapsulate(payload(32))
        val buffer = ByteArray(packet.size + 40) { 0x55 }
        System.arraycopy(packet, 0, buffer, 16, packet.size)
        val result = suite.inbound().decapsulate(buffer, 16, packet.size)
        assertArrayEquals(payload(32), result.payload)
    }

    // ---------------------------------------------------------------- tamper detection

    @Test
    fun anySingleFlippedBitIsRejected() {
        for (suite in suites) {
            val packet = suite.outbound().encapsulate(payload(40))
            for (byteIndex in packet.indices) {
                for (bit in 0 until 8) {
                    val tampered = packet.copyOf()
                    tampered[byteIndex] = (tampered[byteIndex].toInt() xor (1 shl bit)).toByte()
                    // A fresh SA per attempt so a rejection can never be attributed to the window.
                    expectEspException("$suite byte $byteIndex bit $bit") {
                        suite.inbound().decapsulate(tampered)
                    }
                }
            }
        }
    }

    @Test
    fun tamperingWithEachFieldIsRejected() {
        for (suite in suites) {
            val block = suite.encryption.blockBytes
            val icv = suite.integrity.icvBytes
            val packet = suite.outbound().encapsulate(payload(40))
            val regions = mapOf(
                "spi" to 0,
                "sequence" to 4,
                "iv" to 8,
                "ciphertext" to 8 + block,
                "icv" to packet.size - icv,
            )
            for ((name, index) in regions) {
                val tampered = packet.copyOf()
                tampered[index] = (tampered[index].toInt() xor 0x80).toByte()
                expectEspException("$suite $name") { suite.inbound().decapsulate(tampered) }
            }
            // Truncation and extension are rejected too.
            expectEspException("$suite truncated") {
                suite.inbound().decapsulate(packet.copyOf(packet.size - 1))
            }
            expectEspException("$suite extended") {
                suite.inbound().decapsulate(packet + ByteArray(block))
            }
            expectEspException("$suite empty") { suite.inbound().decapsulate(ByteArray(0)) }
        }
    }

    /**
     * A slice whose end does not fit in an `Int` must be caught by the range check itself, not by
     * an arithmetic accident further down the receive path.
     */
    @Test
    fun rejectsARangeWhoseEndOverflows() {
        val suite = suites[0]
        val packet = suite.outbound().encapsulate(payload(32))
        for (length in listOf(Int.MAX_VALUE, Int.MAX_VALUE - 3, packet.size + 1)) {
            try {
                suite.inbound().decapsulate(packet, 1, length)
                fail("expected EspException for length $length")
            } catch (e: EspException) {
                assertTrue("$length: ${e.message}", e.message!!.contains("outside"))
            }
        }
    }

    @Test
    fun aPacketFromAnotherKeyIsRejected() {
        val suite = suites[0]
        // Same SPI and same transforms, different keys: only the ICV can tell them apart.
        val foreign = EspOutboundSa(
            suite.spi,
            EspEncryption.ESP_AES_CBC_256,
            EspIntegrity.HMAC_SHA2_256_128,
            ByteArray(32) { 0x42 },
            ByteArray(32) { 0x43 },
        )
        expectEspException("foreign key") { suite.inbound().decapsulate(foreign.encapsulate(payload(20))) }
    }

    @Test
    fun countersTrackDrops() {
        val suite = suites[0]
        val out = suite.outbound()
        val inb = suite.inbound()
        inb.decapsulate(out.encapsulate(payload(10)))
        val bad = out.encapsulate(payload(10))
        bad[bad.size - 1] = (bad[bad.size - 1].toInt() xor 0xFF).toByte()
        expectEspException("bad icv") { inb.decapsulate(bad) }
        assertEquals(1L, inb.packetsAccepted)
        assertEquals(1L, inb.packetsDropped)
    }

    // ---------------------------------------------------------------- replay

    @Test
    fun replayIsRejectedAndCounted() {
        for (suite in suites) {
            val out = suite.outbound()
            val inb = suite.inbound()
            val first = out.encapsulate(payload(24))
            val second = out.encapsulate(payload(24))

            assertEquals(1L, inb.decapsulate(first).sequenceNumber)
            assertEquals(2L, inb.decapsulate(second).sequenceNumber)
            assertEquals(2L, inb.packetsAccepted)
            assertEquals(0L, inb.packetsDropped)

            expectEspException("$suite replay of 1") { inb.decapsulate(first) }
            expectEspException("$suite replay of 2") { inb.decapsulate(second) }
            assertEquals(2L, inb.packetsAccepted)
            assertEquals(2L, inb.packetsDropped)
            assertTrue(inb.isReplay(1))
            assertFalse(inb.isReplay(3))
        }
    }

    @Test
    fun outOfOrderInsideTheWindowIsAccepted() {
        val suite = suites[0]
        val out = suite.outbound()
        val inb = suite.inbound()
        val packets = (1..10).map { out.encapsulate(payload(16)) }
        // Deliver in reverse: everything is still inside the 64-packet window.
        for (packet in packets.reversed()) inb.decapsulate(packet)
        assertEquals(10L, inb.packetsAccepted)
        assertEquals(10L, inb.highestSequenceNumber)
        for (packet in packets) expectEspException("replay") { inb.decapsulate(packet) }
        assertEquals(10L, inb.packetsDropped)
    }

    @Test
    fun aPacketLeftOfTheWindowIsDropped() {
        val suite = suites[0]
        val out = suite.outbound()
        val inb = suite.inbound(windowSize = 4)
        val old = out.encapsulate(payload(16)) // sequence 1
        repeat(6) { out.encapsulate(payload(16)) } // sequences 2..7 are lost in transit
        inb.decapsulate(out.encapsulate(payload(16))) // sequence 8 arrives
        expectEspException("outside the window") { inb.decapsulate(old) }
    }

    // ---------------------------------------------------------------- encapsulateInto

    @Test
    fun encapsulateIntoMatchesEncapsulate() {
        for (suite in suites) {
            val iv = ByteArray(suite.encryption.blockBytes) { (0xA0 + it).toByte() }
            val original = payload(77)

            val a = suite.outbound().apply { ivSource = { iv.copyOf() } }
            val expected = a.encapsulate(original)

            val b = suite.outbound().apply { ivSource = { iv.copyOf() } }
            val out = ByteArray(expected.size + 32) { 0x5A }
            val written = b.encapsulateInto(out, 9, original, 0, original.size)

            assertEquals("$suite", expected.size, written)
            assertEquals("$suite", Bytes.toHex(expected), Bytes.toHex(out.copyOfRange(9, 9 + written)))
            assertEquals(0x5A.toByte(), out[8]) // nothing written before the offset
            assertEquals(0x5A.toByte(), out[9 + written]) // nor after the packet
            assertArrayEquals(original, suite.inbound().decapsulate(out, 9, written).payload)
        }
    }

    /**
     * [EspOutboundSa.encapsulateInto] promises the output buffer may be the payload buffer, which
     * only holds as long as nothing is written back before the plaintext has been read out - the
     * ESP header, the IV and the ciphertext all land on top of where the payload was.
     */
    @Test
    fun encapsulateIntoWrapsAPayloadAlreadyInTheOutputBuffer() {
        val suite = suites[0]
        val original = payload(200)
        for (payloadOffset in listOf(0, 4, 8, 24, 33)) {
            val buffer = ByteArray(suite.outbound().packetLength(original.size) + 64)
            System.arraycopy(original, 0, buffer, payloadOffset, original.size)
            val written = suite.outbound()
                .encapsulateInto(buffer, 0, buffer, payloadOffset, original.size)
            assertArrayEquals(
                "payload at $payloadOffset",
                original,
                suite.inbound().decapsulate(buffer, 0, written).payload,
            )
        }
    }

    @Test
    fun encapsulateIntoRejectsAShortBuffer() {
        val suite = suites[0]
        val out = suite.outbound()
        val original = payload(100)
        val exact = out.packetLength(original.size)
        try {
            out.encapsulateInto(ByteArray(exact - 1), 0, original, 0, original.size)
            fail("expected IllegalArgumentException")
        } catch (expected: IllegalArgumentException) {
            // ok
        }
    }

    // ---------------------------------------------------------------- sizing

    @Test
    fun maxPayloadForIsExact() {
        for (suite in suites) {
            val out = suite.outbound()
            val minimum = out.packetLength(0)
            for (budget in minimum..(minimum + 300)) {
                val n = out.maxPayloadFor(budget)
                assertTrue("$suite budget $budget -> $n", n >= 0)
                val fits = out.encapsulate(payload(n)).size
                assertTrue("$suite budget $budget fits $fits", fits <= budget)
                val next = out.encapsulate(payload(n + 1)).size
                assertTrue("$suite budget $budget next $next", next > budget)
            }
            // Budgets that cannot hold even an empty payload are reported as 0.
            assertEquals(0, out.maxPayloadFor(minimum - 1))
            assertEquals(0, out.maxPayloadFor(0))
        }
    }

    @Test
    fun packetLengthMatchesTheProducedPacket() {
        for (suite in suites) {
            val out = suite.outbound()
            for (size in listOf(0, 1, 15, 16, 17, 1400)) {
                assertEquals("$suite/$size", out.packetLength(size), out.encapsulate(payload(size)).size)
                assertEquals(
                    "$suite/$size",
                    out.packetLength(size) - size,
                    out.overheadFor(size),
                )
            }
        }
    }

    @Test
    fun theSaReportsItselfExhaustedBeforeTheWrap() {
        val out = suites[0].outbound()
        assertFalse(out.exhausted)
        out.setSequenceNumber(EspOutboundSa.REKEY_THRESHOLD - 1)
        assertFalse(out.exhausted)
        out.encapsulate(payload(8))
        assertTrue(out.exhausted)

        // Past 2^32 a sequence number would repeat, which RFC 4303 section 3.3.3 forbids.
        out.setSequenceNumber(0xFFFFFFFFL)
        expectEspException("wrap") { out.encapsulate(payload(8)) }
    }

    @Test
    fun rejectsKeysOfTheWrongLength() {
        try {
            EspOutboundSa(
                1,
                EspEncryption.ESP_AES_CBC_256,
                EspIntegrity.HMAC_SHA2_256_128,
                ByteArray(16),
                ByteArray(32),
            )
            fail("expected IllegalArgumentException")
        } catch (expected: IllegalArgumentException) {
            // ok
        }
        try {
            EspInboundSa(
                1,
                EspEncryption.ESP_AES_CBC_256,
                EspIntegrity.HMAC_SHA2_256_128,
                ByteArray(32),
                ByteArray(8),
            )
            fail("expected IllegalArgumentException")
        } catch (expected: IllegalArgumentException) {
            // ok
        }
    }

    // ---------------------------------------------------------------- known-answer vectors

    /**
     * Pinned wire format for AES-256-CBC + HMAC-SHA-256-128. The expected bytes were produced
     * independently (openssl for the cipher, python hmac for the ICV), so a refactor that changes
     * the padding, the field order or the ICV coverage cannot pass unnoticed.
     */
    @Test
    fun knownAnswerAes256Sha256() {
        val encryptionKey = Bytes.fromHex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        val integrityKey = Bytes.fromHex(
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        )
        val iv = Bytes.fromHex("0f0e0d0c0b0a09080706050403020100")
        val payload = Bytes.fromHex("cafebabedeadbeef")
        val expected = "12345678" + // SPI
            "00000001" + // sequence number
            "0f0e0d0c0b0a09080706050403020100" + // IV
            "0e1573dee0ce118de8bc664b11a12468" + // E(payload | 01..06 | 06 | 11)
            "98e5ff44c60254a88ced95f0d748b131" // truncated HMAC-SHA-256

        val out = EspOutboundSa(
            0x12345678,
            EspEncryption.ESP_AES_CBC_256,
            EspIntegrity.HMAC_SHA2_256_128,
            encryptionKey,
            integrityKey,
        ).apply { ivSource = { iv } }
        assertEquals(expected, Bytes.toHex(out.encapsulate(payload)))

        // The same vector must also decode, which pins the receive path to the same layout.
        val inb = EspInboundSa(
            0x12345678,
            EspEncryption.ESP_AES_CBC_256,
            EspIntegrity.HMAC_SHA2_256_128,
            encryptionKey,
            integrityKey,
        )
        val result = inb.decapsulate(Bytes.fromHex(expected))
        assertArrayEquals(payload, result.payload)
        assertEquals(Ipv4Header.PROTO_UDP, result.nextHeader)
        assertEquals(1L, result.sequenceNumber)
    }

    /** Same, for 3DES + HMAC-SHA1-96: an 8-byte block and a 12-byte ICV. */
    @Test
    fun knownAnswer3desSha1() {
        val encryptionKey = Bytes.fromHex("000102030405060708090a0b0c0d0e0f1011121314151617")
        val integrityKey = Bytes.fromHex("202122232425262728292a2b2c2d2e2f30313233")
        val iv = Bytes.fromHex("f0e1d2c3b4a59687")
        val payload = Bytes.fromHex("48656c6c6f")
        val expected = "89abcdef" + // SPI
            "00000002" + // sequence number
            "f0e1d2c3b4a59687" + // IV
            "2d64d4e1f61525f2" + // E(payload | 01 | 01 | 11)
            "c22025e4fabdc43132dead19" // truncated HMAC-SHA-1

        val out = EspOutboundSa(
            0x89ABCDEF.toInt(),
            EspEncryption.ESP_3DES,
            EspIntegrity.HMAC_SHA1_96,
            encryptionKey,
            integrityKey,
        ).apply {
            ivSource = { iv }
            setSequenceNumber(1) // so the packet carries sequence 2
        }
        assertEquals(expected, Bytes.toHex(out.encapsulate(payload)))

        val inb = EspInboundSa(
            0x89ABCDEF.toInt(),
            EspEncryption.ESP_3DES,
            EspIntegrity.HMAC_SHA1_96,
            encryptionKey,
            integrityKey,
        )
        val result = inb.decapsulate(Bytes.fromHex(expected))
        assertArrayEquals(payload, result.payload)
        assertEquals(2L, result.sequenceNumber)
    }

    /** RFC 4303 section 2.4: the default pad pattern is 1, 2, 3, ... */
    @Test
    fun paddingUsesTheMonotonicPattern() {
        val encryptionKey = Bytes.fromHex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        val iv = Bytes.fromHex("0f0e0d0c0b0a09080706050403020100")
        val out = EspOutboundSa(
            1,
            EspEncryption.ESP_AES_CBC_256,
            EspIntegrity.HMAC_SHA2_256_128,
            encryptionKey,
            ByteArray(32),
        ).apply { ivSource = { iv } }
        // The ciphertext of the pinned vector decrypts to payload | 01 02 03 04 05 06 | 06 | 11.
        val packet = out.encapsulate(Bytes.fromHex("cafebabedeadbeef"))
        val ciphertext = Bytes.toHex(packet.copyOfRange(24, 40))
        assertEquals("0e1573dee0ce118de8bc664b11a12468", ciphertext)
    }

    /** A receiver must accept any pad bytes, not just the ones it would have sent itself. */
    @Test
    fun acceptsNonDefaultPadding() {
        val suite = suites[0]
        val out = suite.outbound()
        val iv = ByteArray(16) { 0x11 }
        out.ivSource = { iv }
        // Build a packet by hand with all-zero padding.
        val payload = payload(5)
        val plaintext = ByteArray(16)
        System.arraycopy(payload, 0, plaintext, 0, payload.size)
        plaintext[14] = 9 // pad length, pad bytes left at zero
        plaintext[15] = Ipv4Header.PROTO_UDP.toByte()
        val handMade = handBuild(suite, iv, 1, plaintext)
        val result = suite.inbound().decapsulate(handMade)
        assertArrayEquals(payload, result.payload)
    }

    @Test
    fun rejectsAPadLengthLongerThanThePlaintext() {
        val suite = suites[0]
        val iv = ByteArray(16) { 0x22 }
        val plaintext = ByteArray(16)
        plaintext[14] = 0xFF.toByte() // 255 pad bytes in a 16-byte plaintext
        plaintext[15] = Ipv4Header.PROTO_UDP.toByte()
        expectEspException("pad length") {
            suite.inbound().decapsulate(handBuild(suite, iv, 1, plaintext))
        }
    }

    /** Encrypts [plaintext] verbatim and stamps a valid ICV, bypassing the padding rules. */
    private fun handBuild(suite: Suite, iv: ByteArray, sequence: Long, plaintext: ByteArray): ByteArray {
        val cipher = com.arcansecurity.vpn.l2tpipsec.core.crypto.CbcCipher.forEsp(suite.encryption)
        val ciphertext = cipher.encrypt(suite.encryptionKey, iv, plaintext)
        val body = ByteArray(8) + iv + ciphertext
        body[0] = (suite.spi ushr 24).toByte()
        body[1] = (suite.spi ushr 16).toByte()
        body[2] = (suite.spi ushr 8).toByte()
        body[3] = suite.spi.toByte()
        body[7] = sequence.toByte()
        val mac = javax.crypto.Mac.getInstance(suite.integrity.jceMac)
        mac.init(javax.crypto.spec.SecretKeySpec(suite.integrityKey, suite.integrity.jceMac))
        val icv = Bytes.truncate(mac.doFinal(body), suite.integrity.icvBytes)
        return body + icv
    }

    private fun expectEspException(what: String, block: () -> Unit) {
        try {
            block()
            fail("expected EspException: $what")
        } catch (expected: EspException) {
            // ok
        }
    }
}
