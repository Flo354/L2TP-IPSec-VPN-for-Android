package com.arcansecurity.vpn.l2tpipsec.core.ike

import com.arcansecurity.vpn.l2tpipsec.core.ike.IkeTestFixtures.LOCAL_PORT
import com.arcansecurity.vpn.l2tpipsec.core.ike.IkeTestFixtures.PRESHARED_KEY
import com.arcansecurity.vpn.l2tpipsec.core.ike.IkeTestFixtures.config
import com.arcansecurity.vpn.l2tpipsec.core.ike.IkeTestFixtures.localAddress
import com.arcansecurity.vpn.l2tpipsec.core.ike.IkeTestFixtures.remoteAddress
import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Rekeying, from both ends: we replace an expiring IPsec SA ourselves, and we answer a Quick Mode
 * the peer started. Both matter — an SA that simply expires takes the tunnel with it.
 */
class IkeRekeyTest {

    private fun responder() = FakeIkeResponder(PRESHARED_KEY, localAddress, remoteAddress, LOCAL_PORT)

    private fun transportFor(responder: FakeIkeResponder) =
        FakeIkeTransport(localAddress, LOCAL_PORT, remoteAddress, responder)

    /** Our outbound SA is the one the peer receives on, and vice versa. */
    private fun assertMatchingKeymat(responder: FakeIkeResponder, phase2: Phase2Result) {
        assertEquals(phase2.outboundSpi, responder.inboundSpi)
        assertEquals(phase2.inboundSpi, responder.outboundSpi)
        assertArrayEquals(phase2.outboundEncryptionKey, responder.inboundEncryptionKey)
        assertArrayEquals(phase2.outboundIntegrityKey, responder.inboundIntegrityKey)
        assertArrayEquals(phase2.inboundEncryptionKey, responder.outboundEncryptionKey)
        assertArrayEquals(phase2.inboundIntegrityKey, responder.outboundIntegrityKey)
    }

    @Test
    fun `rekeying phase 2 produces a completely fresh sa pair`() {
        val responder = responder()
        val negotiator = IkeV1Negotiator(config(), transportFor(responder))
        val phase1 = negotiator.establishPhase1()

        val first = negotiator.establishPhase2(phase1)
        assertMatchingKeymat(responder, first)

        val second = negotiator.establishPhase2(phase1)
        assertMatchingKeymat(responder, second)

        assertNotEquals("inbound SPI must change", first.inboundSpi, second.inboundSpi)
        assertNotEquals("outbound SPI must change", first.outboundSpi, second.outboundSpi)
        assertNotEquals(
            "keys must not be reused across a rekey",
            Bytes.toHex(first.outboundEncryptionKey),
            Bytes.toHex(second.outboundEncryptionKey),
        )
        assertTrue(responder.quickModeHash3Verified)
    }

    @Test
    fun `the isakmp sa can be renegotiated with a second negotiator`() {
        // A phase-1 rekey is a whole new ISAKMP SA: new cookies, new key schedule. The tunnel
        // therefore builds a fresh negotiator rather than reusing the old one's state.
        val firstResponder = responder()
        val firstNegotiator = IkeV1Negotiator(config(), transportFor(firstResponder))
        val firstPhase1 = firstNegotiator.establishPhase1()

        val secondResponder = responder()
        val secondNegotiator = IkeV1Negotiator(config(), transportFor(secondResponder))
        val secondPhase1 = secondNegotiator.establishPhase1()

        assertFalse(
            "cookies must differ across a phase 1 rekey",
            firstPhase1.initiatorCookie.contentEquals(secondPhase1.initiatorCookie),
        )
        assertNotEquals(Bytes.toHex(firstPhase1.skeyidD), Bytes.toHex(secondPhase1.skeyidD))
        assertNotEquals(Bytes.toHex(firstPhase1.encryptionKey), Bytes.toHex(secondPhase1.encryptionKey))

        // The new SA is immediately usable for phase 2.
        val phase2 = secondNegotiator.establishPhase2(secondPhase1)
        assertMatchingKeymat(secondResponder, phase2)
    }

    @Test
    fun `a peer initiated quick mode is answered and both sides derive the same keys`() {
        val responder = responder()
        val transport = transportFor(responder)
        val negotiator = IkeV1Negotiator(config(), transport)
        val phase1 = negotiator.establishPhase1()

        val request = responder.startQuickMode()
        val phase2 = negotiator.respondToQuickMode(phase1, request)!!

        assertTrue("the peer must accept our HASH(2)", responder.quickModeHash1Verified)
        assertTrue("we must have accepted a UDP-encapsulated mode", phase2.udpEncapsulated)
        assertMatchingKeymat(responder, phase2)
        assertNotEquals(
            Bytes.toHex(phase2.inboundEncryptionKey),
            Bytes.toHex(phase2.outboundEncryptionKey),
        )
    }

    @Test
    fun `a repeated quick mode request is re-acknowledged without creating a second sa`() {
        val responder = responder()
        val transport = transportFor(responder)
        val negotiator = IkeV1Negotiator(config(), transport)
        val phase1 = negotiator.establishPhase1()

        val request = responder.startQuickMode()
        val phase2 = negotiator.respondToQuickMode(phase1, request)!!
        val sentAfterFirst = transport.sent.size

        // A peer that lost our answer repeats message 1; negotiating a second SA for it would
        // leave one of the two unused and eventually break the tunnel.
        assertNull("a duplicate must not yield a new SA", negotiator.respondToQuickMode(phase1, request))
        assertEquals("the cached answer must be re-sent", sentAfterFirst + 1, transport.sent.size)
        assertArrayEquals(transport.sent[sentAfterFirst - 1], transport.sent[sentAfterFirst])
        // Neither side may have moved on to a different SA.
        assertEquals(phase2.outboundSpi, responder.inboundSpi)
        assertEquals(phase2.inboundSpi, responder.outboundSpi)
    }

    /**
     * A peer that rekeys retires the SA it just replaced, and that delete regularly overtakes the
     * HASH(3) that closes the rekey. Treating it as "the peer hung up" would kill a healthy tunnel
     * at the very moment it was being kept alive.
     */
    @Test
    fun `an ipsec delete arriving before HASH(3) does not abort a peer initiated rekey`() {
        val responder = responder()
        val transport = transportFor(responder)
        val negotiator = IkeV1Negotiator(config(), transport)
        val phase1 = negotiator.establishPhase1()
        val old = negotiator.establishPhase2(phase1)

        val request = responder.startQuickMode()
        transport.deliverBeforeNextReply(responder.buildEspDelete(old.outboundSpi))

        val fresh = negotiator.respondToQuickMode(phase1, request)
        assertNotNull("a delete for the superseded SA must not abort the exchange", fresh)
        assertMatchingKeymat(responder, fresh!!)
        assertNotEquals(old.inboundSpi, fresh.inboundSpi)
    }

    /**
     * The replay cache is what keeps a peer whose message 2 was lost on a single SA pair, but it
     * lives as long as the ISAKMP SA does, so it must not grow with every rekey the peer drives.
     */
    @Test
    fun `the cache of answered quick modes stays bounded`() {
        val responder = responder()
        val transport = transportFor(responder)
        val negotiator = IkeV1Negotiator(config(), transport)
        val phase1 = negotiator.establishPhase1()

        // Nothing comes back once the path is dead, so each exchange simply gives up on its HASH(3).
        transport.dropOutbound = true
        val requests = (0 until 6).map { responder.startQuickMode(0x51a10000 + it) }
        for (request in requests) assertNotNull(negotiator.respondToQuickMode(phase1, request))

        // The four most recent answers are still replayed rather than renegotiated...
        for (request in requests.drop(2)) assertNull(negotiator.respondToQuickMode(phase1, request))

        // ...while the older ones have been evicted instead of accumulating.
        assertNotNull(negotiator.respondToQuickMode(phase1, requests[1]))
        assertNotNull(negotiator.respondToQuickMode(phase1, requests[0]))

        // Evicting two did not empty the cache: the newest answer is still there.
        assertNull(negotiator.respondToQuickMode(phase1, requests[5]))
    }

    @Test
    fun `an esp delete names the spi instead of tearing the whole tunnel down`() {
        val responder = responder()
        val negotiator = IkeV1Negotiator(config(), transportFor(responder))
        val phase1 = negotiator.establishPhase1()
        val phase2 = negotiator.establishPhase2(phase1)

        val result = negotiator.handleInformational(phase1, responder.buildEspDelete(phase2.outboundSpi))

        assertFalse("an IPsec delete is not an ISAKMP delete", result.isakmpDeleted)
        assertEquals(listOf(phase2.outboundSpi), result.deletedEspSpis)
    }

    @Test
    fun `a delete for a superseded sa is reported with its own spi`() {
        val responder = responder()
        val negotiator = IkeV1Negotiator(config(), transportFor(responder))
        val phase1 = negotiator.establishPhase1()
        val old = negotiator.establishPhase2(phase1)
        val new = negotiator.establishPhase2(phase1)

        // The peer retires the SA it replaced, not the one now in use.
        val result = negotiator.handleInformational(phase1, responder.buildEspDelete(old.outboundSpi))
        assertEquals(listOf(old.outboundSpi), result.deletedEspSpis)
        assertNotEquals(new.outboundSpi, result.deletedEspSpis.single())
    }
}
