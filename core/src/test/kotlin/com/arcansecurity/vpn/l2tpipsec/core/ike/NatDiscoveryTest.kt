package com.arcansecurity.vpn.l2tpipsec.core.ike

import com.arcansecurity.vpn.l2tpipsec.core.crypto.IkeHash
import com.arcansecurity.vpn.l2tpipsec.core.crypto.Prf
import com.arcansecurity.vpn.l2tpipsec.core.ike.IkeTestFixtures.LOCAL_PORT
import com.arcansecurity.vpn.l2tpipsec.core.ike.IkeTestFixtures.PRESHARED_KEY
import com.arcansecurity.vpn.l2tpipsec.core.ike.IkeTestFixtures.config
import com.arcansecurity.vpn.l2tpipsec.core.ike.IkeTestFixtures.localAddress
import com.arcansecurity.vpn.l2tpipsec.core.ike.IkeTestFixtures.remoteAddress
import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

class NatDiscoveryTest {

    private val initiatorCookie = Bytes.fromHex("0011223344556677")
    private val responderCookie = Bytes.fromHex("8899aabbccddeeff")

    @Test
    fun `nat-d hash is the plain digest of cookies, address and port`() {
        val manual = MessageDigest.getInstance("SHA-256").apply {
            update(initiatorCookie)
            update(responderCookie)
            update(Bytes.ipv4ToBytes("192.168.1.5"))
            update(byteArrayOf(0x11, 0x94.toByte())) // port 4500
        }.digest()

        val actual = IkeKeyDerivation.natDiscoveryHash(
            Prf(IkeHash.SHA2_256), initiatorCookie, responderCookie,
            Bytes.ipv4ToBytes("192.168.1.5"), 4500,
        )
        assertArrayEquals(manual, actual)
        assertEquals(
            "a5c0a47a007bb38e7c71356d9acedc734999c8ee284d0c727dc377cf9137fac0",
            Bytes.toHex(actual),
        )
    }

    @Test
    fun `the hash changes with the port, which is what detects a nat`() {
        val prf = Prf(IkeHash.SHA2_256)
        val address = Bytes.ipv4ToBytes("192.168.1.5")
        val real = IkeKeyDerivation.natDiscoveryHash(prf, initiatorCookie, responderCookie, address, LOCAL_PORT)
        val zero = IkeKeyDerivation.natDiscoveryHash(prf, initiatorCookie, responderCookie, address, 0)
        assertFalse(real.contentEquals(zero))
    }

    /**
     * strongSwan's `forceencaps=yes`: the source NAT-D is computed over port 0 so the responder
     * cannot reproduce it and falls back to UDP-encapsulated ESP, which is the only kind an
     * unrooted Android application can send.
     */
    @Test
    fun `forcing encapsulation emits a source nat-d over port zero`() {
        val responder = FakeIkeResponder(PRESHARED_KEY, localAddress, remoteAddress, LOCAL_PORT)
        val transport = FakeIkeTransport(localAddress, LOCAL_PORT, remoteAddress, responder)
        IkeV1Negotiator(config(forceUdpEncapsulation = true), transport).establishPhase1()

        val realPortHash = responder.natdHash(localAddress, LOCAL_PORT)
        val zeroPortHash = responder.natdHash(localAddress, 0)

        assertArrayEquals(zeroPortHash, responder.receivedSourceNatD)
        assertFalse(realPortHash.contentEquals(responder.receivedSourceNatD))
        assertTrue("responder should conclude the initiator is natted", responder.initiatorBehindNat)

        // Message 3 carries the destination NAT-D first, then the (falsified) source NAT-D.
        val message3 = transport.firstCleartextMessageStartingWith(PayloadType.KE)!!
        val natD = message3.all<NatDiscoveryPayload>()
        assertEquals(2, natD.size)
        assertEquals(PayloadType.NAT_D, natD[0].type)
        assertArrayEquals(responder.natdHash(remoteAddress, 500), natD[0].hash)
        assertArrayEquals(zeroPortHash, natD[1].hash)
    }

    @Test
    fun `without forcing, the source nat-d uses the real port and no nat is reported`() {
        val responder = FakeIkeResponder(PRESHARED_KEY, localAddress, remoteAddress, LOCAL_PORT)
        val transport = FakeIkeTransport(localAddress, LOCAL_PORT, remoteAddress, responder)
        val phase1 = IkeV1Negotiator(config(forceUdpEncapsulation = false), transport).establishPhase1()

        assertArrayEquals(responder.natdHash(localAddress, LOCAL_PORT), responder.receivedSourceNatD)
        assertFalse(responder.initiatorBehindNat)
        assertFalse(phase1.localBehindNat)
        assertFalse(phase1.remoteBehindNat)
        assertFalse(transport.natTraversalActive)
    }

    @Test
    fun `a rewritten source port is detected by both sides`() {
        val responder = FakeIkeResponder(
            PRESHARED_KEY, localAddress, remoteAddress, observedInitiatorPort = 40001,
        )
        val transport = FakeIkeTransport(localAddress, LOCAL_PORT, remoteAddress, responder)
        val phase1 = IkeV1Negotiator(config(forceUdpEncapsulation = false), transport).establishPhase1()

        assertTrue(responder.initiatorBehindNat)
        assertTrue(phase1.localBehindNat)
        assertFalse(phase1.remoteBehindNat)
        assertTrue(transport.natTraversalActive)
    }
}
