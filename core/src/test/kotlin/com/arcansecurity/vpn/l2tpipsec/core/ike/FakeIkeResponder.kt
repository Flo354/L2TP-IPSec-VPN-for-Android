package com.arcansecurity.vpn.l2tpipsec.core.ike

import com.arcansecurity.vpn.l2tpipsec.core.crypto.CbcCipher
import com.arcansecurity.vpn.l2tpipsec.core.crypto.DhGroup
import com.arcansecurity.vpn.l2tpipsec.core.crypto.DiffieHellman
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.EspIntegrity
import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeEncryption
import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeHash
import com.arcansecurity.vpn.l2tpipsec.core.crypto.Prf
import com.arcansecurity.vpn.l2tpipsec.core.util.ByteReader
import com.arcansecurity.vpn.l2tpipsec.core.util.ByteWriter
import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import java.net.InetAddress

/**
 * The responder half of an IKEv1 exchange, good enough to drive [IkeV1Negotiator] end to end.
 *
 * It shares the message codec with the production code — re-implementing the wire format would
 * test nothing but the test — yet every key is derived here straight from the formulas in RFC 2409
 * section 5, without touching [IkeKeyDerivation]. A transposition in the production key schedule
 * therefore shows up as two sides that disagree, which is exactly how it would show up in the
 * field.
 */
class FakeIkeResponder(
    presharedKey: String,
    private val initiatorAddress: InetAddress,
    private val responderAddress: InetAddress,
    /** The initiator source port as this responder observes it; a NAT would rewrite it. */
    private val observedInitiatorPort: Int,
    private val ikePort: Int = 500,
    private val encryption: IkeEncryption = IkeEncryption.AES_CBC_256,
    hash: IkeHash = IkeHash.SHA2_256,
    private val dhGroup: DhGroup = DhGroup.MODP_2048,
    private val espEncryption: EspEncryption = EspEncryption.ESP_AES_CBC_256,
    private val espIntegrity: EspIntegrity = EspIntegrity.HMAC_SHA2_256_128,
    /** `null` makes the responder advertise no NAT traversal support at all. */
    private val natTraversalVendorId: ByteArray? = VendorIds.RFC_3947,
) {

    private val psk = presharedKey.toByteArray(Charsets.UTF_8)
    private val prf = Prf(hash)
    private val cipher = CbcCipher.forIke(encryption)
    private val natdPayloadType =
        if (natTraversalVendorId != null && !natTraversalVendorId.contentEquals(VendorIds.RFC_3947)) {
            PayloadType.NAT_D_DRAFT
        } else {
            PayloadType.NAT_D
        }

    val responderCookie: ByteArray = Bytes.randomNonZero(8)

    lateinit var initiatorCookie: ByteArray
        private set

    lateinit var skeyid: ByteArray
        private set
    lateinit var skeyidD: ByteArray
        private set
    lateinit var skeyidA: ByteArray
        private set
    lateinit var skeyidE: ByteArray
        private set
    lateinit var encryptionKey: ByteArray
        private set
    lateinit var phase1Iv: ByteArray
        private set

    var initiatorBehindNat = false
        private set

    /** The source NAT-D hash the initiator sent; the forceencaps test inspects it directly. */
    var receivedSourceNatD: ByteArray? = null
        private set

    var hashIVerified = false
        private set
    var quickModeHash1Verified = false
        private set
    var quickModeHash3Verified = false
        private set

    var inboundSpi = 0
        private set
    var outboundSpi = 0
        private set
    lateinit var inboundEncryptionKey: ByteArray
        private set
    lateinit var inboundIntegrityKey: ByteArray
        private set
    lateinit var outboundEncryptionKey: ByteArray
        private set
    lateinit var outboundIntegrityKey: ByteArray
        private set
    var selectedEncapsulationMode = 0
        private set
    var receivedNatOaCount = 0
        private set

    var informationalsReceived = 0
        private set
    val receivedNotifyTypes = mutableListOf<Int>()
    val receivedDeleteProtocols = mutableListOf<Int>()

    private lateinit var dh: DiffieHellman
    private lateinit var gxi: ByteArray
    private lateinit var gxr: ByteArray
    private lateinit var ni: ByteArray
    private lateinit var nr: ByteArray
    private lateinit var initiatorSaBody: ByteArray
    private lateinit var initiatorIdBody: ByteArray

    private var quickModeStage = 0
    /** Message id of a Quick Mode this responder started itself, so answers can be told apart. */
    private var peerQuickModeMessageId: Int? = null
    private var peerQuickModeIv: ByteArray? = null
    private var peerQuickModeAnswered = false
    private var quickModeIv: ByteArray? = null
    private var quickModeSecret = ByteArray(0)
    private lateinit var quickModeNi: ByteArray
    private lateinit var quickModeNr: ByteArray

    /** Feeds one datagram to the responder and returns its reply, or null when none is due. */
    fun onMessage(raw: ByteArray): ByteArray? {
        val header = IsakmpHeader.decode(raw)
        return when (header.exchangeType) {
            ExchangeType.IDENTITY_PROTECTION -> when {
                !header.isEncrypted && header.nextPayload == PayloadType.SA -> mainMode2(header, raw)
                !header.isEncrypted && header.nextPayload == PayloadType.KE -> mainMode4(header, raw)
                header.isEncrypted -> mainMode6(header, raw)
                else -> null
            }

            ExchangeType.AGGRESSIVE ->
                if (header.isEncrypted) aggressiveMode3(header, raw) else aggressiveMode2(header, raw)

            ExchangeType.QUICK_MODE -> quickMode(header, raw)
            ExchangeType.INFORMATIONAL -> informational(header, raw)
            else -> null
        }
    }

    // -- Main Mode ---------------------------------------------------------------------------

    private fun mainMode2(header: IsakmpHeader, raw: ByteArray): ByteArray {
        initiatorCookie = header.initiatorCookie
        val chain = IsakmpCodec.decodeMessage(raw, header)
        initiatorSaBody = chain.bodyAt(chain.indexOfType(PayloadType.SA))
        val payloads = mutableListOf<IkePayload>(echoSa(chain))
        natTraversalVendorId?.let { payloads += VendorIdPayload(it) }
        payloads += VendorIdPayload(VendorIds.DPD_1_0)
        return IsakmpCodec.buildMessage(
            initiatorCookie, responderCookie, ExchangeType.IDENTITY_PROTECTION, 0, 0, payloads,
        )
    }

    private fun mainMode4(header: IsakmpHeader, raw: ByteArray): ByteArray {
        val chain = IsakmpCodec.decodeMessage(raw, header)
        gxi = chain.find<KeyExchangePayload>()!!.data
        ni = chain.find<NoncePayload>()!!.data
        dh = DiffieHellman.generate(dhGroup)
        gxr = dh.publicValue
        nr = Bytes.random(32)
        derivePhase1Keys(dh.computeSharedSecret(gxi))
        inspectNatDiscovery(chain)
        phase1Iv = Bytes.truncate(prf.digest(gxi, gxr), cipher.blockBytes)

        return IsakmpCodec.buildMessage(
            initiatorCookie, responderCookie, ExchangeType.IDENTITY_PROTECTION, 0, 0,
            listOf(KeyExchangePayload(gxr), NoncePayload(nr)) + natDiscoveryPayloads(),
        )
    }

    private fun mainMode6(header: IsakmpHeader, raw: ByteArray): ByteArray {
        val ciphertext5 = raw.copyOfRange(IsakmpCodec.HEADER_SIZE, raw.size)
        val chain = IsakmpCodec.decodeBlock(
            cipher.decrypt(encryptionKey, phase1Iv, ciphertext5), header.nextPayload,
        )
        initiatorIdBody = chain.bodyAt(chain.indexOfType(PayloadType.ID))
        verifyHashI(chain.find<HashPayload>()!!.data)

        val idr = responderIdPayload()
        val hashR = prf.mac(
            skeyid, gxr, gxi, responderCookie, initiatorCookie, initiatorSaBody, idr.encodeBody(),
        )
        val ciphertext6 = cipher.encrypt(
            encryptionKey,
            lastBlock(ciphertext5),
            pad(IsakmpCodec.encodeChain(listOf(idr, HashPayload(hashR)))),
        )
        phase1Iv = lastBlock(ciphertext6)
        return IsakmpCodec.buildMessage(
            initiatorCookie, responderCookie, ExchangeType.IDENTITY_PROTECTION,
            IsakmpFlags.ENCRYPTION, 0, PayloadType.ID, ciphertext6,
        )
    }

    // -- Aggressive Mode ---------------------------------------------------------------------

    private fun aggressiveMode2(header: IsakmpHeader, raw: ByteArray): ByteArray {
        initiatorCookie = header.initiatorCookie
        val chain = IsakmpCodec.decodeMessage(raw, header)
        initiatorSaBody = chain.bodyAt(chain.indexOfType(PayloadType.SA))
        initiatorIdBody = chain.bodyAt(chain.indexOfType(PayloadType.ID))
        gxi = chain.find<KeyExchangePayload>()!!.data
        ni = chain.find<NoncePayload>()!!.data

        dh = DiffieHellman.generate(dhGroup)
        gxr = dh.publicValue
        nr = Bytes.random(32)
        derivePhase1Keys(dh.computeSharedSecret(gxi))
        phase1Iv = Bytes.truncate(prf.digest(gxi, gxr), cipher.blockBytes)

        val idr = responderIdPayload()
        val hashR = prf.mac(
            skeyid, gxr, gxi, responderCookie, initiatorCookie, initiatorSaBody, idr.encodeBody(),
        )
        val payloads = mutableListOf(
            echoSa(chain), KeyExchangePayload(gxr), NoncePayload(nr), idr, HashPayload(hashR),
        )
        payloads += natDiscoveryPayloads()
        natTraversalVendorId?.let { payloads += VendorIdPayload(it) }
        payloads += VendorIdPayload(VendorIds.DPD_1_0)
        return IsakmpCodec.buildMessage(
            initiatorCookie, responderCookie, ExchangeType.AGGRESSIVE, 0, 0, payloads,
        )
    }

    private fun aggressiveMode3(header: IsakmpHeader, raw: ByteArray): ByteArray? {
        val ciphertext = raw.copyOfRange(IsakmpCodec.HEADER_SIZE, raw.size)
        val chain = IsakmpCodec.decodeBlock(
            cipher.decrypt(encryptionKey, phase1Iv, ciphertext), header.nextPayload,
        )
        verifyHashI(chain.find<HashPayload>()!!.data)
        inspectNatDiscovery(chain)
        phase1Iv = lastBlock(ciphertext)
        return null
    }

    // -- Quick Mode --------------------------------------------------------------------------

    private fun quickMode(header: IsakmpHeader, raw: ByteArray): ByteArray? {
        val ciphertext = raw.copyOfRange(IsakmpCodec.HEADER_SIZE, raw.size)
        val messageId = int32(header.messageId)
        if (header.messageId == peerQuickModeMessageId) {
            // A client that repeats its answer gets nothing back; the exchange is already done.
            if (peerQuickModeAnswered) return null
            return peerQuickModeMessage3(header, raw)
        }
        return if (quickModeStage == 0) {
            val iv = Bytes.truncate(prf.digest(phase1Iv, messageId), cipher.blockBytes)
            val chain = IsakmpCodec.decodeBlock(
                cipher.decrypt(encryptionKey, iv, ciphertext), header.nextPayload,
            )
            quickModeStage = 1
            quickModeMessage2(header, chain, messageId, lastBlock(ciphertext))
        } else {
            val chain = IsakmpCodec.decodeBlock(
                cipher.decrypt(encryptionKey, quickModeIv!!, ciphertext), header.nextPayload,
            )
            val expected = prf.mac(skeyidA, ByteArray(1), messageId, quickModeNi, quickModeNr)
            quickModeHash3Verified = Bytes.constantTimeEquals(expected, chain.bodyAt(0))
            deriveEspKeys()
            // Ready for the next exchange: a rekey is just another Quick Mode.
            quickModeStage = 0
            null
        }
    }

    private fun quickModeMessage2(
        header: IsakmpHeader,
        chain: PayloadChain,
        messageId: ByteArray,
        ivForReply: ByteArray,
    ): ByteArray {
        val expectedHash1 = prf.mac(skeyidA, messageId, chain.bytesAfter(0))
        quickModeHash1Verified = chain.indexOfType(PayloadType.HASH) == 0 &&
            Bytes.constantTimeEquals(expectedHash1, chain.bodyAt(0))

        quickModeNi = chain.find<NoncePayload>()!!.data
        quickModeNr = Bytes.random(32)
        receivedNatOaCount = chain.all<NatOriginalAddressPayload>().size

        val proposal = chain.find<SaPayload>()!!.proposals[0]
        val transform = proposal.transforms[0]
        outboundSpi = ByteReader(proposal.spi).i32()
        inboundSpi = ByteReader(Bytes.randomNonZero(4)).i32()
        selectedEncapsulationMode =
            transform.intAttribute(Phase2Attribute.ENCAPSULATION_MODE) ?: EncapsulationMode.TUNNEL

        val payloads = mutableListOf<IkePayload>(
            SaPayload(listOf(ProposalPayload(1, ProtocolId.ESP, int32(inboundSpi), listOf(transform)))),
            NoncePayload(quickModeNr),
        )
        chain.find<KeyExchangePayload>()?.let {
            val pfs = DiffieHellman.generate(dhGroup)
            quickModeSecret = pfs.computeSharedSecret(it.data)
            payloads += KeyExchangePayload(pfs.publicValue)
        }
        payloads += chain.all<IdentificationPayload>()

        val hash2 = prf.mac(
            skeyidA, messageId, quickModeNi, IsakmpCodec.encodeChain(payloads),
        )
        val ciphertext = cipher.encrypt(encryptionKey, ivForReply, pad(chainAfterHash(hash2, payloads)))
        quickModeIv = lastBlock(ciphertext)
        return IsakmpCodec.buildMessage(
            initiatorCookie, responderCookie, ExchangeType.QUICK_MODE, IsakmpFlags.ENCRYPTION,
            header.messageId, PayloadType.HASH, ciphertext,
        )
    }

    /**
     * Starts a Quick Mode of its own, which is what a router that rekeys on its own schedule does.
     * The client is the responder for this exchange.
     */
    fun startQuickMode(messageId: Int = 0x51a10000): ByteArray {
        peerQuickModeMessageId = messageId
        peerQuickModeAnswered = false
        quickModeNi = Bytes.random(32)
        quickModeSecret = ByteArray(0)
        inboundSpi = ByteReader(Bytes.randomNonZero(4)).i32()
        val transform = TransformPayload(
            1,
            espEncryption.transformId,
            listOf(
                SaAttribute.tv(Phase2Attribute.SA_LIFE_TYPE, Phase2Attribute.LIFE_TYPE_SECONDS),
                SaAttribute.tlv32(Phase2Attribute.SA_LIFE_DURATION, 3600),
                SaAttribute.tv(Phase2Attribute.ENCAPSULATION_MODE, EncapsulationMode.UDP_TRANSPORT),
                SaAttribute.tv(Phase2Attribute.AUTHENTICATION_ALGORITHM, espIntegrity.attributeValue),
                SaAttribute.tv(Phase2Attribute.KEY_LENGTH, espEncryption.keyBits),
            ),
        )
        val payloads = listOf<IkePayload>(
            SaPayload(listOf(ProposalPayload(1, ProtocolId.ESP, int32(inboundSpi), listOf(transform)))),
            NoncePayload(quickModeNi),
        )
        val mid = int32(messageId)
        val hash1 = prf.mac(skeyidA, mid, IsakmpCodec.encodeChain(payloads))
        val iv = Bytes.truncate(prf.digest(phase1Iv, mid), cipher.blockBytes)
        val ciphertext = cipher.encrypt(encryptionKey, iv, pad(chainAfterHash(hash1, payloads)))
        peerQuickModeIv = lastBlock(ciphertext)
        return IsakmpCodec.buildMessage(
            initiatorCookie, responderCookie, ExchangeType.QUICK_MODE, IsakmpFlags.ENCRYPTION,
            messageId, PayloadType.HASH, ciphertext,
        )
    }

    /** Verifies the client's HASH(2), derives the keys and returns HASH(3). */
    private fun peerQuickModeMessage3(header: IsakmpHeader, raw: ByteArray): ByteArray {
        val ciphertext = raw.copyOfRange(IsakmpCodec.HEADER_SIZE, raw.size)
        val mid = int32(header.messageId)
        val chain = IsakmpCodec.decodeBlock(
            cipher.decrypt(encryptionKey, peerQuickModeIv!!, ciphertext), header.nextPayload,
        )
        val expected = prf.mac(skeyidA, mid, quickModeNi, chain.bytesAfter(0))
        quickModeHash1Verified = chain.indexOfType(PayloadType.HASH) == 0 &&
            Bytes.constantTimeEquals(expected, chain.bodyAt(0))
        quickModeNr = chain.find<NoncePayload>()!!.data
        outboundSpi = ByteReader(chain.find<SaPayload>()!!.proposals[0].spi).i32()
        selectedEncapsulationMode = chain.find<SaPayload>()!!.proposals[0].transforms[0]
            .intAttribute(Phase2Attribute.ENCAPSULATION_MODE) ?: EncapsulationMode.TUNNEL
        deriveEspKeys()
        val hash3 = prf.mac(skeyidA, ByteArray(1), mid, quickModeNi, quickModeNr)
        val reply = cipher.encrypt(
            encryptionKey, lastBlock(ciphertext), pad(IsakmpCodec.encodeChain(listOf(HashPayload(hash3)))),
        )
        peerQuickModeAnswered = true
        return IsakmpCodec.buildMessage(
            initiatorCookie, responderCookie, ExchangeType.QUICK_MODE, IsakmpFlags.ENCRYPTION,
            header.messageId, PayloadType.HASH, reply,
        )
    }

    /**
     * RFC 2409 section 5.5. The SA carrying traffic *to* this responder is the one whose SPI this
     * responder chose, so [inboundSpi] yields the keys it decrypts with.
     */
    private fun deriveEspKeys() {
        val encryptionKeyBytes = espEncryption.keyBytes
        val needed = encryptionKeyBytes + espIntegrity.keyBytes
        val inbound = keymat(inboundSpi, needed)
        val outbound = keymat(outboundSpi, needed)
        inboundEncryptionKey = inbound.copyOfRange(0, encryptionKeyBytes)
        inboundIntegrityKey = inbound.copyOfRange(encryptionKeyBytes, needed)
        outboundEncryptionKey = outbound.copyOfRange(0, encryptionKeyBytes)
        outboundIntegrityKey = outbound.copyOfRange(encryptionKeyBytes, needed)
    }

    private fun keymat(spi: Int, length: Int): ByteArray {
        val seed = Bytes.concat(
            quickModeSecret, byteArrayOf(ProtocolId.ESP.toByte()), int32(spi), quickModeNi, quickModeNr,
        )
        val out = ByteWriter(length + prf.outputBytes)
        var block = prf.mac(skeyidD, seed)
        out.bytes(block)
        while (out.size < length) {
            block = prf.mac(skeyidD, block, seed)
            out.bytes(block)
        }
        return Bytes.truncate(out.toByteArray(), length)
    }

    // -- Informational -----------------------------------------------------------------------

    private fun informational(header: IsakmpHeader, raw: ByteArray): ByteArray? {
        informationalsReceived++
        val chain = if (header.isEncrypted) {
            val iv = Bytes.truncate(
                prf.digest(phase1Iv, int32(header.messageId)), cipher.blockBytes,
            )
            IsakmpCodec.decodeBlock(
                cipher.decrypt(
                    encryptionKey, iv, raw.copyOfRange(IsakmpCodec.HEADER_SIZE, raw.size),
                ),
                header.nextPayload,
            )
        } else {
            IsakmpCodec.decodeMessage(raw, header)
        }
        chain.all<NotifyPayload>().forEach { receivedNotifyTypes += it.notifyType }
        chain.all<DeletePayload>().forEach { receivedDeleteProtocols += it.protocolId }
        return null
    }

    /** Builds an informational the negotiator can be fed through `handleInformational`. */
    fun buildInformational(payloads: List<IkePayload>, messageId: Int = 0x0f0f0f0f): ByteArray {
        val messageIdBytes = int32(messageId)
        val hash = prf.mac(skeyidA, messageIdBytes, IsakmpCodec.encodeChain(payloads))
        val iv = Bytes.truncate(prf.digest(phase1Iv, messageIdBytes), cipher.blockBytes)
        val ciphertext = cipher.encrypt(encryptionKey, iv, pad(chainAfterHash(hash, payloads)))
        return IsakmpCodec.buildMessage(
            initiatorCookie, responderCookie, ExchangeType.INFORMATIONAL, IsakmpFlags.ENCRYPTION,
            messageId, PayloadType.HASH, ciphertext,
        )
    }

    fun buildDpdRequest(sequence: Int): ByteArray = buildInformational(
        listOf(
            NotifyPayload(
                NotifyType.DPD_R_U_THERE, ProtocolId.ISAKMP,
                Bytes.concat(initiatorCookie, responderCookie), int32(sequence),
            ),
        ),
    )

    fun buildEspDelete(spi: Int, messageId: Int = 0x0e5d0e5d): ByteArray = buildInformational(
        listOf(DeletePayload(ProtocolId.ESP, listOf(int32(spi)))),
        messageId,
    )

    fun buildIsakmpDelete(): ByteArray = buildInformational(
        listOf(
            DeletePayload(ProtocolId.ISAKMP, listOf(Bytes.concat(initiatorCookie, responderCookie))),
        ),
    )

    // -- Shared helpers ----------------------------------------------------------------------

    /** RFC 2409 section 5, written out here so it cannot inherit a bug from production code. */
    private fun derivePhase1Keys(gxy: ByteArray) {
        skeyid = prf.mac(psk, ni, nr)
        skeyidD = prf.mac(skeyid, gxy, initiatorCookie, responderCookie, byteArrayOf(0))
        skeyidA = prf.mac(skeyid, skeyidD, gxy, initiatorCookie, responderCookie, byteArrayOf(1))
        skeyidE = prf.mac(skeyid, skeyidA, gxy, initiatorCookie, responderCookie, byteArrayOf(2))
        encryptionKey = if (skeyidE.size >= encryption.keyBytes) {
            skeyidE.copyOf(encryption.keyBytes)
        } else {
            // RFC 2409 appendix B.
            val out = ByteWriter(encryption.keyBytes + prf.outputBytes)
            var block = prf.mac(skeyidE, ByteArray(1))
            out.bytes(block)
            while (out.size < encryption.keyBytes) {
                block = prf.mac(skeyidE, block)
                out.bytes(block)
            }
            Bytes.truncate(out.toByteArray(), encryption.keyBytes)
        }
    }

    private fun verifyHashI(received: ByteArray) {
        val expected = prf.mac(
            skeyid, gxi, gxr, initiatorCookie, responderCookie, initiatorSaBody, initiatorIdBody,
        )
        hashIVerified = Bytes.constantTimeEquals(expected, received)
    }

    private fun echoSa(chain: PayloadChain): SaPayload {
        val transform = chain.find<SaPayload>()!!.proposals[0].transforms[0]
        return SaPayload(listOf(ProposalPayload(1, ProtocolId.ISAKMP, ByteArray(0), listOf(transform))))
    }

    private fun responderIdPayload() =
        IdentificationPayload(IdType.IPV4_ADDR, 0, 0, responderAddress.address)

    private fun natDiscoveryPayloads(): List<IkePayload> = listOf(
        // The destination, as we see it: the initiator's address and observed port.
        NatDiscoveryPayload(natdPayloadType, natdHash(initiatorAddress, observedInitiatorPort)),
        NatDiscoveryPayload(natdPayloadType, natdHash(responderAddress, ikePort)),
    )

    private fun inspectNatDiscovery(chain: PayloadChain) {
        val received = chain.all<NatDiscoveryPayload>()
        receivedSourceNatD = received.getOrNull(1)?.hash
        val expected = natdHash(initiatorAddress, observedInitiatorPort)
        initiatorBehindNat =
            received.size < 2 || !Bytes.constantTimeEquals(received[1].hash, expected)
    }

    fun natdHash(address: InetAddress, port: Int): ByteArray = prf.digest(
        initiatorCookie, responderCookie, address.address, ByteWriter(2).u16(port).toByteArray(),
    )

    private fun chainAfterHash(hash: ByteArray, rest: List<IkePayload>): ByteArray = ByteWriter(64)
        .u8(rest.firstOrNull()?.type ?: PayloadType.NONE)
        .u8(0)
        .u16(hash.size + 4)
        .bytes(hash)
        .bytes(IsakmpCodec.encodeChain(rest))
        .toByteArray()

    private fun pad(block: ByteArray): ByteArray {
        val padding = (cipher.blockBytes - block.size % cipher.blockBytes) % cipher.blockBytes
        return if (padding == 0) block else block.copyOf(block.size + padding)
    }

    private fun lastBlock(ciphertext: ByteArray): ByteArray =
        ciphertext.copyOfRange(ciphertext.size - cipher.blockBytes, ciphertext.size)

    private fun int32(value: Int): ByteArray = ByteWriter(4).i32(value).toByteArray()
}
