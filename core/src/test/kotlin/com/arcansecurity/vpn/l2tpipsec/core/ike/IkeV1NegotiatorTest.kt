package com.arcansecurity.vpn.l2tpipsec.core.ike

import com.arcansecurity.vpn.l2tpipsec.core.crypto.CbcCipher
import com.arcansecurity.vpn.l2tpipsec.core.crypto.DhGroup
import com.arcansecurity.vpn.l2tpipsec.core.crypto.Prf
import com.arcansecurity.vpn.l2tpipsec.core.ike.IkeTestFixtures.LOCAL_PORT
import com.arcansecurity.vpn.l2tpipsec.core.ike.IkeTestFixtures.PRESHARED_KEY
import com.arcansecurity.vpn.l2tpipsec.core.ike.IkeTestFixtures.config
import com.arcansecurity.vpn.l2tpipsec.core.ike.IkeTestFixtures.localAddress
import com.arcansecurity.vpn.l2tpipsec.core.ike.IkeTestFixtures.remoteAddress
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeExchangeMode
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.Phase2Proposal
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelErrorKind
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelException
import com.arcansecurity.vpn.l2tpipsec.core.util.ByteWriter
import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

class IkeV1NegotiatorTest {

    private fun responder(
        presharedKey: String = PRESHARED_KEY,
        observedInitiatorPort: Int = LOCAL_PORT,
        natTraversalVendorId: ByteArray? = VendorIds.RFC_3947,
    ) = FakeIkeResponder(
        presharedKey, localAddress, remoteAddress, observedInitiatorPort,
        natTraversalVendorId = natTraversalVendorId,
    )

    private fun transportFor(responder: FakeIkeResponder) =
        FakeIkeTransport(localAddress, LOCAL_PORT, remoteAddress, responder)

    private fun assertSharedPhase1(responder: FakeIkeResponder, phase1: Phase1Result) {
        assertArrayEquals("SKEYID", responder.skeyid, phase1.skeyid)
        assertArrayEquals("SKEYID_d", responder.skeyidD, phase1.skeyidD)
        assertArrayEquals("SKEYID_a", responder.skeyidA, phase1.skeyidA)
        assertArrayEquals("SKEYID_e", responder.skeyidE, phase1.skeyidE)
        assertArrayEquals("cipher key", responder.encryptionKey, phase1.encryptionKey)
        assertArrayEquals("phase 1 IV", responder.phase1Iv, phase1.phase1Iv)
        assertArrayEquals(responder.initiatorCookie, phase1.initiatorCookie)
        assertArrayEquals(responder.responderCookie, phase1.responderCookie)
        assertTrue("responder must accept HASH_I", responder.hashIVerified)
    }

    private fun assertMatchingKeymat(responder: FakeIkeResponder, phase2: Phase2Result) {
        // Our outbound SA is the one the responder receives on, and vice versa.
        assertEquals(phase2.outboundSpi, responder.inboundSpi)
        assertEquals(phase2.inboundSpi, responder.outboundSpi)
        assertArrayEquals(phase2.outboundEncryptionKey, responder.inboundEncryptionKey)
        assertArrayEquals(phase2.outboundIntegrityKey, responder.inboundIntegrityKey)
        assertArrayEquals(phase2.inboundEncryptionKey, responder.outboundEncryptionKey)
        assertArrayEquals(phase2.inboundIntegrityKey, responder.outboundIntegrityKey)
        assertNotEquals(
            Bytes.toHex(phase2.inboundEncryptionKey),
            Bytes.toHex(phase2.outboundEncryptionKey),
        )
    }

    @Test
    fun `main mode then quick mode against the fake responder`() {
        val responder = responder()
        val transport = transportFor(responder)
        val negotiator = IkeV1Negotiator(config(), transport)

        val phase1 = negotiator.establishPhase1()
        assertSharedPhase1(responder, phase1)
        assertEquals(NatTraversalFlavor.RFC_3947, phase1.natTraversalFlavor)

        // forceUdpEncapsulation makes the responder see a NAT, so both sides must float to 4500.
        assertTrue(responder.initiatorBehindNat)
        assertTrue(phase1.localBehindNat)
        assertFalse(phase1.remoteBehindNat)
        assertTrue(transport.natTraversalActive)

        // Six messages exchanged, of which our three were sent by us.
        assertEquals(3, transport.sent.size)

        assertArrayEquals(
            Bytes.concat(byteArrayOf(IdType.IPV4_ADDR.toByte(), 0, 0, 0), localAddress.address),
            phase1.localIdentity,
        )
        assertArrayEquals(
            Bytes.concat(byteArrayOf(IdType.IPV4_ADDR.toByte(), 0, 0, 0), remoteAddress.address),
            phase1.remoteIdentity,
        )

        val phase2 = negotiator.establishPhase2(phase1)
        assertTrue("responder must accept HASH(1)", responder.quickModeHash1Verified)
        assertTrue("responder must accept HASH(3)", responder.quickModeHash3Verified)
        assertMatchingKeymat(responder, phase2)

        assertTrue(phase2.udpEncapsulated)
        assertEquals(EncapsulationMode.UDP_TRANSPORT, responder.selectedEncapsulationMode)
        // RFC 3947 sends both original addresses.
        assertEquals(2, responder.receivedNatOaCount)
        assertEquals(config().phase2.encryption, phase2.encryption)
        assertEquals(config().phase2.integrity, phase2.integrity)
        assertEquals(32, phase2.inboundEncryptionKey.size)
        assertEquals(32, phase2.inboundIntegrityKey.size)
        assertEquals(config().phase2.lifetimeSeconds, phase2.lifetimeSeconds)
    }

    @Test
    fun `aggressive mode happy path`() {
        val responder = responder()
        val transport = transportFor(responder)
        val negotiator =
            IkeV1Negotiator(config(exchangeMode = IkeExchangeMode.AGGRESSIVE), transport)

        val phase1 = negotiator.establishPhase1()
        assertSharedPhase1(responder, phase1)
        assertEquals(2, transport.sent.size)
        assertTrue(transport.natTraversalActive)
        assertTrue(responder.initiatorBehindNat)

        val phase2 = negotiator.establishPhase2(phase1)
        assertTrue(responder.quickModeHash1Verified)
        assertTrue(responder.quickModeHash3Verified)
        assertMatchingKeymat(responder, phase2)
        assertTrue(phase2.udpEncapsulated)
    }

    @Test
    fun `a wrong pre-shared key surfaces as an authentication failure`() {
        // Aggressive mode carries HASH_R in the clear, so a bad PSK is detected on the wire rather
        // than as an undecryptable message.
        val responder = responder(presharedKey = "not the same secret")
        val negotiator = IkeV1Negotiator(
            config(exchangeMode = IkeExchangeMode.AGGRESSIVE), transportFor(responder),
        )
        val error = assertThrows(TunnelException::class.java) { negotiator.establishPhase1() }
        assertEquals(TunnelErrorKind.IKE_AUTH_FAILED, error.kind)
    }

    @Test
    fun `a peer without nat traversal support is refused`() {
        val negotiator =
            IkeV1Negotiator(config(), transportFor(responder(natTraversalVendorId = null)))
        val error = assertThrows(TunnelException::class.java) { negotiator.establishPhase1() }
        assertEquals(TunnelErrorKind.IPSEC_SA_FAILED, error.kind)
        assertTrue(error.message!!.contains("NAT-T"))
    }

    @Test
    fun `the draft nat-t dialect uses the draft payload numbers and encapsulation mode`() {
        val responder = responder(natTraversalVendorId = VendorIds.DRAFT_03)
        val transport = transportFor(responder)
        val negotiator = IkeV1Negotiator(config(), transport)

        val phase1 = negotiator.establishPhase1()
        assertEquals(NatTraversalFlavor.DRAFT_03, phase1.natTraversalFlavor)

        val message3 = transport.firstCleartextMessageStartingWith(PayloadType.KE)!!
        assertEquals(
            listOf(PayloadType.NAT_D_DRAFT, PayloadType.NAT_D_DRAFT),
            message3.all<NatDiscoveryPayload>().map { it.type },
        )

        val phase2 = negotiator.establishPhase2(phase1)
        assertEquals(EncapsulationMode.UDP_TRANSPORT_DRAFT, responder.selectedEncapsulationMode)
        assertTrue(phase2.udpEncapsulated)
        // The drafts never defined a responder NAT-OA.
        assertEquals(1, responder.receivedNatOaCount)
    }

    @Test
    fun `plain transport mode is proposed when there is no nat`() {
        val responder = responder()
        val transport = transportFor(responder)
        val negotiator = IkeV1Negotiator(config(forceUdpEncapsulation = false), transport)

        val phase1 = negotiator.establishPhase1()
        assertFalse(transport.natTraversalActive)

        val phase2 = negotiator.establishPhase2(phase1)
        assertEquals(EncapsulationMode.TRANSPORT, responder.selectedEncapsulationMode)
        assertFalse(phase2.udpEncapsulated)
        assertEquals(0, responder.receivedNatOaCount)
        assertMatchingKeymat(responder, phase2)
    }

    /** With PFS the KEYMAT seed is prefixed by a second Diffie-Hellman secret. */
    @Test
    fun `quick mode with perfect forward secrecy agrees on keymat`() {
        val responder = responder()
        val transport = transportFor(responder)
        val negotiator = IkeV1Negotiator(
            config(phase2 = Phase2Proposal(pfsGroup = DhGroup.MODP_2048)), transport,
        )
        val phase1 = negotiator.establishPhase1()
        val phase2 = negotiator.establishPhase2(phase1)

        assertTrue(responder.quickModeHash1Verified)
        assertTrue(responder.quickModeHash3Verified)
        assertMatchingKeymat(responder, phase2)
    }

    @Test
    fun `dpd probes are answered and a delete ends the sa`() {
        val responder = responder()
        val transport = transportFor(responder)
        val negotiator = IkeV1Negotiator(config(), transport)
        val phase1 = negotiator.establishPhase1()

        val sequence = negotiator.sendDpdRequest(phase1)
        assertTrue(sequence >= 0)
        assertTrue(responder.receivedNotifyTypes.contains(NotifyType.DPD_R_U_THERE))

        // A probe from the peer is answered and leaves the SA alive.
        val probe = negotiator.handleInformational(phase1, responder.buildDpdRequest(0x2a))
        assertFalse(probe.isakmpDeleted)
        assertTrue(probe.deletedEspSpis.isEmpty())
        assertTrue(responder.receivedNotifyTypes.contains(NotifyType.DPD_R_U_THERE_ACK))

        assertTrue(negotiator.handleInformational(phase1, responder.buildIsakmpDelete()).isakmpDeleted)
    }

    @Test
    fun `an informational with a bad hash is ignored`() {
        val responder = responder()
        val negotiator = IkeV1Negotiator(config(), transportFor(responder))
        val phase1 = negotiator.establishPhase1()

        val tampered = responder.buildIsakmpDelete().copyOf()
        tampered[tampered.size - 1] = (tampered[tampered.size - 1] + 1).toByte()
        // Garbled ciphertext must never be able to tear the tunnel down.
        val result = negotiator.handleInformational(phase1, tampered)
        assertFalse(result.isakmpDeleted)
        assertTrue(result.deletedEspSpis.isEmpty())
    }

    /**
     * A payload block that decrypts to nothing but padding: the header says "next payload = none",
     * so the chain is empty and there is no HASH to authenticate it with.
     */
    @Test
    fun `an informational with an empty payload chain is dropped`() {
        val responder = responder()
        val negotiator = IkeV1Negotiator(config(), transportFor(responder))
        val phase1 = negotiator.establishPhase1()

        val cipher = CbcCipher.forIke(phase1.encryption)
        val prf = Prf(phase1.hash)
        val messageId = 0x0badc0de
        val messageIdBytes = ByteWriter(4).i32(messageId).toByteArray()
        val iv = Bytes.truncate(prf.digest(phase1.phase1Iv, messageIdBytes), cipher.blockBytes)
        val message = IsakmpCodec.buildMessage(
            phase1.initiatorCookie, phase1.responderCookie, ExchangeType.INFORMATIONAL,
            IsakmpFlags.ENCRYPTION, messageId, PayloadType.NONE,
            cipher.encrypt(phase1.encryptionKey, iv, ByteArray(cipher.blockBytes)),
        )

        val result = negotiator.handleInformational(phase1, message)
        assertFalse(result.isakmpDeleted)
        assertTrue(result.deletedEspSpis.isEmpty())
    }

    /**
     * RFC 2408 section 4.8: once the ISAKMP SA exists an informational exchange must be protected
     * by it. Acting on an unprotected delete would let anyone who has seen our cookies on the wire
     * force an endless renegotiation.
     */
    @Test
    fun `an unprotected informational is ignored once the isakmp sa exists`() {
        val responder = responder()
        val negotiator = IkeV1Negotiator(config(), transportFor(responder))
        val phase1 = negotiator.establishPhase1()

        val spoofed = IsakmpCodec.buildMessage(
            phase1.initiatorCookie, phase1.responderCookie, ExchangeType.INFORMATIONAL, 0, 0x1234,
            listOf(
                DeletePayload(
                    ProtocolId.ISAKMP,
                    listOf(Bytes.concat(phase1.initiatorCookie, phase1.responderCookie)),
                ),
            ),
        )

        assertFalse(negotiator.handleInformational(phase1, spoofed).isakmpDeleted)
    }

    /**
     * A responder that names a PFS group we never proposed would seed its KEYMAT with a second
     * Diffie-Hellman secret we do not have, and every ESP packet would then fail its integrity
     * check with nothing on the wire to explain why.
     */
    @Test
    fun `a responder that answers with an unproposed pfs group is refused`() {
        val responder = FakeIkeResponder(
            PRESHARED_KEY, localAddress, remoteAddress, LOCAL_PORT,
            rewriteEchoedTransform = { transform ->
                if (transform.transformId == TransformId.KEY_IKE) {
                    transform
                } else {
                    TransformPayload(
                        transform.number,
                        transform.transformId,
                        transform.attributes +
                            SaAttribute.tv(Phase2Attribute.GROUP_DESCRIPTION, DhGroup.MODP_2048.groupId),
                    )
                }
            },
        )
        val negotiator = IkeV1Negotiator(config(), transportFor(responder))
        val phase1 = negotiator.establishPhase1()

        val error = assertThrows(TunnelException::class.java) { negotiator.establishPhase2(phase1) }
        assertEquals(TunnelErrorKind.IKE_PROPOSAL_REJECTED, error.kind)
    }

    /** Same silent black hole, reached through a key exchange rather than a group attribute. */
    @Test
    fun `a quick mode answer carrying an unsolicited key exchange is refused`() {
        val responder = FakeIkeResponder(
            PRESHARED_KEY, localAddress, remoteAddress, LOCAL_PORT,
            unsolicitedPhase2KeyExchange = true,
        )
        val negotiator = IkeV1Negotiator(config(), transportFor(responder))
        val phase1 = negotiator.establishPhase1()

        val error = assertThrows(TunnelException::class.java) { negotiator.establishPhase2(phase1) }
        assertEquals(TunnelErrorKind.IPSEC_SA_FAILED, error.kind)
    }

    /**
     * 0xFFFFFFFF is what several stacks send for "no limit". The SA life duration is a raw 32-bit
     * attribute, so it reads back as -1, and the tunnel schedules its rekey off exactly this number.
     */
    @Test
    fun `a life duration that decodes negative falls back to the one we proposed`() {
        val responder = FakeIkeResponder(
            PRESHARED_KEY, localAddress, remoteAddress, LOCAL_PORT,
            rewriteEchoedTransform = { transform ->
                val durationType = if (transform.transformId == TransformId.KEY_IKE) {
                    Phase1Attribute.LIFE_DURATION
                } else {
                    Phase2Attribute.SA_LIFE_DURATION
                }
                TransformPayload(
                    transform.number,
                    transform.transformId,
                    transform.attributes.map {
                        if (it.type == durationType) SaAttribute.tlv32(durationType, -1) else it
                    },
                )
            },
        )
        val negotiator = IkeV1Negotiator(config(), transportFor(responder))

        val phase1 = negotiator.establishPhase1()
        assertEquals(config().phase1.lifetimeSeconds, phase1.lifetimeSeconds)
        assertEquals(config().phase2.lifetimeSeconds, negotiator.establishPhase2(phase1).lifetimeSeconds)
    }

    @Test
    fun `delete notifications are sent for both SAs`() {
        val responder = responder()
        val negotiator = IkeV1Negotiator(config(), transportFor(responder))
        val phase1 = negotiator.establishPhase1()
        val phase2 = negotiator.establishPhase2(phase1)

        negotiator.sendDeleteNotifications(phase1, phase2)
        assertEquals(listOf(ProtocolId.ESP, ProtocolId.ISAKMP), responder.receivedDeleteProtocols)
    }

    @Test
    fun `an error notify is mapped onto a typed tunnel error`() {
        assertEquals(
            TunnelErrorKind.IKE_PROPOSAL_REJECTED,
            failureFor(NotifyType.NO_PROPOSAL_CHOSEN).kind,
        )
        assertEquals(
            TunnelErrorKind.IKE_AUTH_FAILED,
            failureFor(NotifyType.AUTHENTICATION_FAILED).kind,
        )
        assertEquals(
            TunnelErrorKind.IKE_AUTH_FAILED,
            failureFor(NotifyType.INVALID_ID_INFORMATION).kind,
        )
        assertEquals(
            TunnelErrorKind.IPSEC_SA_FAILED,
            failureFor(NotifyType.PAYLOAD_MALFORMED).kind,
        )
    }

    @Test
    fun `silence eventually fails with IKE_NO_RESPONSE`() {
        val transport = SilentTransport()
        val negotiator = IkeV1Negotiator(config(), transport)
        val error = assertThrows(TunnelException::class.java) { negotiator.establishPhase1() }
        assertEquals(TunnelErrorKind.IKE_NO_RESPONSE, error.kind)
        // One initial transmission plus config.ikeMaxRetransmits retries.
        assertEquals(2, transport.attempts)
    }

    private fun failureFor(notifyType: Int): TunnelException {
        val negotiator = IkeV1Negotiator(config(), NotifyOnlyTransport(notifyType))
        return assertThrows(TunnelException::class.java) { negotiator.establishPhase1() }
    }

    /** Answers every request with a cleartext informational carrying one notify. */
    private class NotifyOnlyTransport(private val notifyType: Int) : IkeTransport {
        override val localAddress: InetAddress = IkeTestFixtures.localAddress
        override val localPort: Int = LOCAL_PORT
        override val remoteAddress: InetAddress = IkeTestFixtures.remoteAddress
        override var natTraversalActive = false
            private set

        private val inbox = ArrayDeque<ByteArray>()

        override fun enableNatTraversal() {
            natTraversalActive = true
        }

        override fun sendIsakmp(message: ByteArray) {
            val header = IsakmpHeader.decode(message)
            inbox.addLast(
                IsakmpCodec.buildMessage(
                    header.initiatorCookie, ByteArray(8), ExchangeType.INFORMATIONAL, 0, 0x1234,
                    listOf(NotifyPayload(notifyType, ProtocolId.ISAKMP)),
                ),
            )
        }

        override fun receiveIsakmp(timeoutMs: Int): ByteArray? = inbox.removeFirstOrNull()
    }

    private class SilentTransport : IkeTransport {
        var attempts = 0
            private set

        override val localAddress: InetAddress = IkeTestFixtures.localAddress
        override val localPort: Int = LOCAL_PORT
        override val remoteAddress: InetAddress = IkeTestFixtures.remoteAddress
        override val natTraversalActive: Boolean = false

        override fun enableNatTraversal() = Unit

        override fun sendIsakmp(message: ByteArray) {
            attempts++
        }

        override fun receiveIsakmp(timeoutMs: Int): ByteArray? = null
    }
}
