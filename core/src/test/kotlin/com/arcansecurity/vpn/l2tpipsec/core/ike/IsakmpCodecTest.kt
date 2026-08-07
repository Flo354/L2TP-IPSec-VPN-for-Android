package com.arcansecurity.vpn.l2tpipsec.core.ike

import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import com.arcansecurity.vpn.l2tpipsec.core.util.ProtocolException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class IsakmpCodecTest {

    private val initiatorCookie = Bytes.fromHex("0011223344556677")
    private val responderCookie = Bytes.fromHex("8899aabbccddeeff")

    @Test
    fun `header round trip`() {
        val header = IsakmpHeader(
            initiatorCookie = initiatorCookie,
            responderCookie = responderCookie,
            nextPayload = PayloadType.SA,
            exchangeType = ExchangeType.IDENTITY_PROTECTION,
            flags = IsakmpFlags.ENCRYPTION,
            messageId = 0x11223344,
            length = 128,
        )
        val encoded = header.encode()
        assertEquals(IsakmpCodec.HEADER_SIZE, encoded.size)
        assertEquals(
            "0011223344556677" + "8899aabbccddeeff" + "01" + "10" + "02" + "01" +
                "11223344" + "00000080",
            Bytes.toHex(encoded),
        )

        val decoded = IsakmpHeader.decode(encoded)
        assertArrayEquals(initiatorCookie, decoded.initiatorCookie)
        assertArrayEquals(responderCookie, decoded.responderCookie)
        assertEquals(PayloadType.SA, decoded.nextPayload)
        assertEquals(ExchangeType.IDENTITY_PROTECTION, decoded.exchangeType)
        assertEquals(IsakmpFlags.ENCRYPTION, decoded.flags)
        assertTrue(decoded.isEncrypted)
        assertEquals(0x11223344, decoded.messageId)
        assertEquals(128, decoded.length)
        assertEquals(IsakmpCodec.VERSION, decoded.version)
    }

    @Test
    fun `every payload type survives a chain round trip`() {
        val payloads: List<IkePayload> = listOf(
            SaPayload(
                listOf(
                    ProposalPayload(
                        1, ProtocolId.ESP, Bytes.fromHex("deadbeef"),
                        listOf(
                            TransformPayload(
                                1, 12,
                                listOf(
                                    SaAttribute.tv(Phase2Attribute.KEY_LENGTH, 256),
                                    SaAttribute.tlv32(Phase2Attribute.SA_LIFE_DURATION, 3600),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
            KeyExchangePayload(ByteArray(32) { it.toByte() }),
            IdentificationPayload(IdType.IPV4_ADDR, IpProtocol.UDP, 1701, Bytes.fromHex("c0a80105")),
            HashPayload(ByteArray(20) { 0x5a }),
            SignaturePayload(ByteArray(12) { 0x33 }),
            NoncePayload(ByteArray(16) { 0x7f }),
            NotifyPayload(
                NotifyType.DPD_R_U_THERE, ProtocolId.ISAKMP,
                Bytes.concat(initiatorCookie, responderCookie), Bytes.fromHex("00000001"),
            ),
            DeletePayload(ProtocolId.ESP, listOf(Bytes.fromHex("11111111"), Bytes.fromHex("22222222"))),
            VendorIdPayload(VendorIds.RFC_3947),
            NatDiscoveryPayload(PayloadType.NAT_D, ByteArray(32) { 0x11 }),
            NatDiscoveryPayload(PayloadType.NAT_D_DRAFT, ByteArray(20) { 0x22 }),
            NatOriginalAddressPayload(PayloadType.NAT_OA, IdType.IPV4_ADDR, Bytes.fromHex("0a000001")),
            NatOriginalAddressPayload(PayloadType.NAT_OA_DRAFT, IdType.IPV4_ADDR, Bytes.fromHex("0a000002")),
            UnknownPayload(PayloadType.CERTREQ, Bytes.fromHex("04")),
        )

        val block = IsakmpCodec.encodeChain(payloads)
        val chain = IsakmpCodec.decodeBlock(block, payloads.first().type)
        assertEquals(payloads.size, chain.payloads.size)

        for ((original, roundTripped) in payloads.zip(chain.payloads)) {
            assertEquals(original.type, roundTripped.type)
            assertArrayEquals(
                "payload type ${original.type} did not round trip",
                original.encodeBody(),
                roundTripped.encodeBody(),
            )
        }

        val sa = chain.find<SaPayload>()!!
        assertEquals(Doi.IPSEC, sa.doi)
        assertEquals(1, sa.proposals.size)
        assertArrayEquals(Bytes.fromHex("deadbeef"), sa.proposals[0].spi)
        assertEquals(2, sa.proposals[0].transforms[0].attributes.size)

        val notify = chain.find<NotifyPayload>()!!
        assertEquals(NotifyType.DPD_R_U_THERE, notify.notifyType)
        assertEquals(16, notify.spi.size)

        val delete = chain.find<DeletePayload>()!!
        assertEquals(2, delete.spis.size)
        assertEquals(4, delete.spiSize)

        val natOa = chain.all<NatOriginalAddressPayload>()
        assertEquals(2, natOa.size)
        assertEquals(PayloadType.NAT_OA_DRAFT, natOa[1].type)
        assertArrayEquals(Bytes.fromHex("0a000002"), natOa[1].address)
    }

    @Test
    fun `message round trip preserves the payload chain`() {
        val payloads = listOf(NoncePayload(ByteArray(8)), VendorIdPayload(VendorIds.DPD_1_0))
        val message = IsakmpCodec.buildMessage(
            initiatorCookie, responderCookie, ExchangeType.IDENTITY_PROTECTION, 0, 0, payloads,
        )
        val header = IsakmpHeader.decode(message)
        assertEquals(PayloadType.NONCE, header.nextPayload)
        assertEquals(message.size, header.length)

        val chain = IsakmpCodec.decodeMessage(message, header)
        assertEquals(2, chain.payloads.size)
        assertArrayEquals(VendorIds.DPD_1_0, chain.find<VendorIdPayload>()!!.data)
    }

    /**
     * A hand-written phase-1 proposal, byte for byte, so that a change to the encoder is caught by
     * something other than the encoder itself.
     */
    @Test
    fun `a hand built SA proposal decodes to the expected transform attributes`() {
        val body = Bytes.fromHex(
            "00000001" + // DOI = IPSEC
                "00000001" + // situation = SIT_IDENTITY_ONLY
                "00000030" + // proposal payload: next=none, length=48
                "01010001" + // proposal 1, protocol ISAKMP, SPI size 0, one transform
                "00000028" + // transform payload: next=none, length=40
                "01010000" + // transform 1, KEY_IKE, reserved
                "80010007" + // encryption = AES-CBC
                "800e0100" + // key length = 256
                "80020004" + // hash = SHA2-256
                "80030001" + // auth method = pre-shared key
                "8004000e" + // group = MODP-2048
                "800b0001" + // life type = seconds
                "000c000400002a30", // life duration = 10800 seconds
        )

        val sa = SaPayload.decode(body)
        assertEquals(Doi.IPSEC, sa.doi)
        assertEquals(Doi.SIT_IDENTITY_ONLY, sa.situation)
        assertEquals(1, sa.proposals.size)

        val proposal = sa.proposals[0]
        assertEquals(1, proposal.number)
        assertEquals(ProtocolId.ISAKMP, proposal.protocolId)
        assertEquals(0, proposal.spi.size)
        assertEquals(1, proposal.transforms.size)

        val transform = proposal.transforms[0]
        assertEquals(TransformId.KEY_IKE, transform.transformId)
        assertEquals(7, transform.intAttribute(Phase1Attribute.ENCRYPTION))
        assertEquals(256, transform.intAttribute(Phase1Attribute.KEY_LENGTH))
        assertEquals(4, transform.intAttribute(Phase1Attribute.HASH))
        assertEquals(1, transform.intAttribute(Phase1Attribute.AUTH_METHOD))
        assertEquals(14, transform.intAttribute(Phase1Attribute.GROUP_DESCRIPTION))
        assertEquals(1, transform.intAttribute(Phase1Attribute.LIFE_TYPE))
        assertEquals(10800, transform.intAttribute(Phase1Attribute.LIFE_DURATION))
        assertEquals(null, transform.intAttribute(42))

        // The encoder must reproduce exactly these bytes.
        assertArrayEquals(body, sa.encodeBody())
    }

    @Test
    fun `bytesAfter returns the exact received bytes following a payload`() {
        val payloads = listOf(
            HashPayload(ByteArray(4) { 0x11 }),
            NoncePayload(ByteArray(4) { 0x22 }),
            VendorIdPayload(ByteArray(4) { 0x33 }),
        )
        val block = IsakmpCodec.encodeChain(payloads)
        val chain = IsakmpCodec.decodeBlock(block, PayloadType.HASH)

        assertEquals(0, chain.indexOfType(PayloadType.HASH))
        assertArrayEquals(
            IsakmpCodec.encodeChain(payloads.drop(1)),
            chain.bytesAfter(0),
        )
        assertEquals(0, chain.bytesAfter(2).size)
        assertArrayEquals(ByteArray(4) { 0x11 }, chain.bodyAt(0))
    }

    @Test
    fun `trailing CBC padding after the last payload is ignored`() {
        val payloads = listOf(HashPayload(ByteArray(20) { 0x5a }))
        val padded = Bytes.concat(IsakmpCodec.encodeChain(payloads), ByteArray(8))
        val chain = IsakmpCodec.decodeBlock(padded, PayloadType.HASH)
        assertEquals(1, chain.payloads.size)
        assertArrayEquals(ByteArray(20) { 0x5a }, chain.bodyAt(0))
    }

    @Test
    fun `malformed input raises a protocol exception`() {
        assertThrows(ProtocolException::class.java) { IsakmpHeader.decode(ByteArray(27)) }

        // Major version 2 is IKEv2, not this stack.
        val wrongVersion = IsakmpHeader(
            initiatorCookie, responderCookie, 0, 2, 0, 0, 28, version = 0x20,
        ).encode()
        assertThrows(ProtocolException::class.java) { IsakmpHeader.decode(wrongVersion) }

        // Payload length below the 4-byte generic header would loop forever.
        assertThrows(ProtocolException::class.java) {
            IsakmpCodec.decodeChain(Bytes.fromHex("00000002"), 0, PayloadType.NONCE)
        }
        // Payload that runs past the end of the block.
        assertThrows(ProtocolException::class.java) {
            IsakmpCodec.decodeChain(Bytes.fromHex("00000040aabb"), 0, PayloadType.NONCE)
        }
        // Chain that never terminates.
        assertThrows(ProtocolException::class.java) {
            IsakmpCodec.decodeChain(Bytes.fromHex("0a000004"), 0, PayloadType.NONCE)
        }
        // Proposal announcing four transforms but carrying one.
        assertThrows(ProtocolException::class.java) {
            ProposalPayload.decode(Bytes.fromHex("01030004" + "00000008010c0000"))
        }
        // Nested payload of the wrong type inside an SA payload.
        assertThrows(ProtocolException::class.java) {
            SaPayload.decode(
                Bytes.fromHex("00000001" + "00000001" + "03000008" + "01010000" + "00000004"),
            )
        }
    }
}
