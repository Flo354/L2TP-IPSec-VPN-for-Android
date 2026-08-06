package com.arcan.l2tpvpn.core.ike

import com.arcan.l2tpvpn.core.crypto.DhGroup
import com.arcan.l2tpvpn.core.ike.IkeTestFixtures.LOCAL_PORT
import com.arcan.l2tpvpn.core.ike.IkeTestFixtures.PRESHARED_KEY
import com.arcan.l2tpvpn.core.ike.IkeTestFixtures.config
import com.arcan.l2tpvpn.core.ike.IkeTestFixtures.localAddress
import com.arcan.l2tpvpn.core.ike.IkeTestFixtures.remoteAddress
import com.arcan.l2tpvpn.core.tunnel.IkeExchangeMode
import com.arcan.l2tpvpn.core.tunnel.Phase2Proposal
import com.arcan.l2tpvpn.core.tunnel.TunnelErrorKind
import com.arcan.l2tpvpn.core.tunnel.TunnelException
import com.arcan.l2tpvpn.core.util.Bytes
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
        assertTrue(negotiator.handleInformational(phase1, responder.buildDpdRequest(0x2a)))
        assertTrue(responder.receivedNotifyTypes.contains(NotifyType.DPD_R_U_THERE_ACK))

        assertFalse(negotiator.handleInformational(phase1, responder.buildIsakmpDelete()))
    }

    @Test
    fun `an informational with a bad hash is ignored`() {
        val responder = responder()
        val negotiator = IkeV1Negotiator(config(), transportFor(responder))
        val phase1 = negotiator.establishPhase1()

        val tampered = responder.buildIsakmpDelete().copyOf()
        tampered[tampered.size - 1] = (tampered[tampered.size - 1] + 1).toByte()
        // Garbled ciphertext must never be able to tear the tunnel down.
        assertTrue(negotiator.handleInformational(phase1, tampered))
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
