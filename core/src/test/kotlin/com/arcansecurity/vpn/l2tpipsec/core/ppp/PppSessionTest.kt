package com.arcansecurity.vpn.l2tpipsec.core.ppp

import com.arcansecurity.vpn.l2tpipsec.core.tunnel.PppAuthProtocol
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelErrorKind
import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** End-to-end negotiation against the fake LNS, plus the hand-crafted corner cases. */
class PppSessionTest {

    // ------------------------------------------------------------------ happy paths

    private fun assertConverged(harness: PppHarness, expectedAuth: PppAuthProtocol?) {
        val session = harness.session
        assertNull("unexpected failure: ${session.failure?.message}", session.failure)
        assertTrue("session is not open, phase=${session.phase}", session.isOpen)
        val result = session.result!!
        assertEquals("10.10.10.100", result.localAddress)
        assertEquals("10.10.10.1", result.remoteAddress)
        assertEquals(listOf("10.10.10.1", "8.8.8.8"), result.dnsServers)
        assertEquals(1400, result.mru)
        assertEquals(expectedAuth, result.authProtocolUsed)
    }

    @Test
    fun `full negotiation with ms-chapv2`() {
        val harness = PppHarness(FakeLns(auth = PppAuthProtocol.MSCHAP_V2))
        harness.runToCompletion()
        assertConverged(harness, PppAuthProtocol.MSCHAP_V2)
        assertTrue(harness.peer.authenticated)
    }

    @Test
    fun `full negotiation with chap md5`() {
        val harness = PppHarness(FakeLns(auth = PppAuthProtocol.CHAP_MD5))
        harness.runToCompletion()
        assertConverged(harness, PppAuthProtocol.CHAP_MD5)
        assertTrue(harness.peer.authenticated)
    }

    @Test
    fun `full negotiation with pap`() {
        val harness = PppHarness(FakeLns(auth = PppAuthProtocol.PAP))
        harness.runToCompletion()
        assertConverged(harness, PppAuthProtocol.PAP)
        assertTrue(harness.peer.authenticated)
    }

    @Test
    fun `a peer that does not authenticate goes straight to the network phase`() {
        val harness = PppHarness(FakeLns(auth = null))
        harness.runToCompletion()
        assertConverged(harness, null)
        assertTrue(harness.clientSent().none { it.protocol == PppProtocol.CHAP || it.protocol == PppProtocol.PAP })
    }

    @Test
    fun `authentication ends in the network phase before ipcp converges`() {
        val harness = PppHarness(FakeLns(auth = PppAuthProtocol.MSCHAP_V2, answerIpcp = false))
        harness.runToCompletion()
        assertEquals(PppSession.Phase.NETWORK, harness.session.phase)
        assertTrue(harness.peer.authenticated)
        // We must have asked for an address and both DNS servers (RFC 1332 + RFC 1877).
        val request = harness.clientSent().last { it.protocol == PppProtocol.IPCP }.packet
        assertEquals(PppCode.CONFIGURE_REQUEST, request.code)
        assertEquals(
            listOf(IpcpOption.IP_ADDRESS, IpcpOption.PRIMARY_DNS, IpcpOption.SECONDARY_DNS),
            request.options().map { it.type },
        )
        assertTrue(request.options().all { it.value.contentEquals(ByteArray(4)) })
    }

    @Test
    fun `a rejected dns option is not fatal`() {
        val harness = PppHarness(FakeLns(auth = PppAuthProtocol.PAP, rejectDnsOptions = true))
        harness.runToCompletion()
        assertTrue(harness.session.isOpen)
        assertEquals("10.10.10.100", harness.session.result!!.localAddress)
        assertEquals(emptyList<String>(), harness.session.result!!.dnsServers)
    }

    @Test
    fun `the negotiated mru is the smaller of both directions`() {
        val harness = PppHarness(FakeLns(auth = null, mru = 1380), requestedMru = 1400)
        harness.runToCompletion()
        assertEquals(1380, harness.session.result!!.mru)
    }

    // ------------------------------------------------------------------ LCP option handling

    @Test
    fun `our configure request asks for an mru and a non zero magic number`() {
        val client = RecordingSession(requestedMru = 1400)
        client.start()
        val request = client.last(PppProtocol.LCP, PppCode.CONFIGURE_REQUEST)
        val options = request.options()
        assertEquals(listOf(LcpOption.MRU, LcpOption.MAGIC_NUMBER), options.map { it.type })
        assertEquals("0578", Bytes.toHex(options[0].value))
        assertFalse(options[1].value.all { it.toInt() == 0 })
        // ACFC and PFC are never requested: the tunnel always emits canonical frames.
        assertTrue(options.none { it.type == LcpOption.ACFC || it.type == LcpOption.PFC })
    }

    @Test
    fun `unknown and unimplemented lcp options are configure rejected`() {
        val client = RecordingSession()
        client.start()
        client.deliverOptions(
            PppProtocol.LCP, PppCode.CONFIGURE_REQUEST, 9,
            listOf(
                PppOption(LcpOption.MRU, Bytes.fromHex("05dc")),
                PppOption(LcpOption.QUALITY_PROTOCOL, Bytes.fromHex("c025000003e8")),
                PppOption(LcpOption.ACFC, ByteArray(0)),
                PppOption(LcpOption.PFC, ByteArray(0)),
                PppOption(0x42, Bytes.fromHex("cafe")),
            ),
        )
        val reply = client.last(PppProtocol.LCP, PppCode.CONFIGURE_REJECT)
        assertEquals(9, reply.identifier)
        assertEquals(
            listOf(LcpOption.QUALITY_PROTOCOL, LcpOption.ACFC, LcpOption.PFC, 0x42),
            reply.options().map { it.type },
        )
    }

    @Test
    fun `an unsupported chap algorithm is configure naked with one we allow`() {
        val client = RecordingSession(
            allowedAuth = listOf(PppAuthProtocol.MSCHAP_V2, PppAuthProtocol.PAP),
        )
        client.start()
        // 0x80 is MS-CHAPv1, which this client does not implement.
        client.deliverOptions(
            PppProtocol.LCP, PppCode.CONFIGURE_REQUEST, 4,
            listOf(PppOption(LcpOption.AUTH_PROTOCOL, Bytes.fromHex("c22380"))),
        )
        val reply = client.last(PppProtocol.LCP, PppCode.CONFIGURE_NAK)
        assertEquals(4, reply.identifier)
        assertEquals(
            listOf(PppOption(LcpOption.AUTH_PROTOCOL, Bytes.fromHex("c22381"))),
            reply.options(),
        )
    }

    @Test
    fun `an auth protocol we do not allow is naked with our preferred one`() {
        val client = RecordingSession(allowedAuth = listOf(PppAuthProtocol.PAP))
        client.start()
        client.deliverOptions(
            PppProtocol.LCP, PppCode.CONFIGURE_REQUEST, 4,
            listOf(PppOption(LcpOption.AUTH_PROTOCOL, Bytes.fromHex("c22305"))),
        )
        assertEquals(
            listOf(PppOption(LcpOption.AUTH_PROTOCOL, Bytes.fromHex("c023"))),
            client.last(PppProtocol.LCP, PppCode.CONFIGURE_NAK).options(),
        )
    }

    @Test
    fun `a peer that naks our chap algorithm still reaches the network phase`() {
        // The LNS opens with MS-CHAPv1; the client naks, the LNS falls back to MS-CHAPv2.
        val peer = FakeLns(auth = null, authOption = Bytes.fromHex("c22380"), answerIpcp = false)
        val harness = PppHarness(peer)
        harness.runToCompletion()
        assertEquals(PppSession.Phase.NETWORK, harness.session.phase)
        assertTrue(peer.authenticated)
    }

    @Test
    fun `a naked mru is adopted and re-requested`() {
        val client = RecordingSession(requestedMru = 1400)
        client.start()
        val first = client.last(PppProtocol.LCP, PppCode.CONFIGURE_REQUEST)
        client.deliverOptions(
            PppProtocol.LCP, PppCode.CONFIGURE_NAK, first.identifier,
            listOf(PppOption(LcpOption.MRU, Bytes.fromHex("0500"))),
        )
        val second = client.last(PppProtocol.LCP, PppCode.CONFIGURE_REQUEST)
        assertEquals("0500", Bytes.toHex(second.options().first { it.type == LcpOption.MRU }.value))
        // A retransmission must not reuse the identifier of a request the peer already answered.
        assertTrue(second.identifier != first.identifier)
    }

    @Test
    fun `rejected lcp options are dropped from the next request`() {
        val client = RecordingSession()
        client.start()
        val first = client.last(PppProtocol.LCP, PppCode.CONFIGURE_REQUEST)
        client.deliverOptions(
            PppProtocol.LCP, PppCode.CONFIGURE_REJECT, first.identifier,
            listOf(
                PppOption(LcpOption.MRU, first.options()[0].value),
                PppOption(LcpOption.MAGIC_NUMBER, first.options()[1].value),
            ),
        )
        assertTrue(client.last(PppProtocol.LCP, PppCode.CONFIGURE_REQUEST).options().isEmpty())
    }

    @Test
    fun `an echo request is answered with an echo reply carrying our magic`() {
        val client = RecordingSession()
        client.openLcp()
        val ourMagic = client.of(PppProtocol.LCP, PppCode.CONFIGURE_REQUEST)
            .last().options().first { it.type == LcpOption.MAGIC_NUMBER }.value
        client.deliver(
            PppProtocol.LCP,
            PppControlPacket(PppCode.ECHO_REQUEST, 77, Bytes.concat(Bytes.fromHex("0badf00d"), "hi".toByteArray())),
        )
        val reply = client.last(PppProtocol.LCP, PppCode.ECHO_REPLY)
        assertEquals(77, reply.identifier)
        assertArrayEquals(ourMagic, reply.data.copyOfRange(0, 4))
        assertEquals("hi", String(reply.data, 4, reply.data.size - 4))
    }

    @Test
    fun `a magic number loopback is fatal`() {
        val client = RecordingSession()
        client.start()
        val ourMagic = client.last(PppProtocol.LCP, PppCode.CONFIGURE_REQUEST)
            .options().first { it.type == LcpOption.MAGIC_NUMBER }.value
        client.deliverOptions(
            PppProtocol.LCP, PppCode.CONFIGURE_REQUEST, 1,
            listOf(PppOption(LcpOption.MAGIC_NUMBER, ourMagic)),
        )
        assertEquals(PppSession.Phase.FAILED, client.phase)
        assertEquals(TunnelErrorKind.PPP_FAILED, client.session.failure!!.kind)
        assertTrue(client.session.failure!!.message!!.contains("loopback"))
    }

    @Test
    fun `an unrun protocol is protocol rejected once lcp is open`() {
        val client = RecordingSession()
        client.openLcp()
        client.session.onFrame(PppProtocol.IPV6CP, Bytes.fromHex("0101000401"))
        val reject = client.last(PppProtocol.LCP, PppCode.PROTOCOL_REJECT)
        assertEquals("8057", Bytes.toHex(reject.data.copyOfRange(0, 2)))
        assertEquals("0101000401", Bytes.toHex(reject.data.copyOfRange(2, reject.data.size)))
    }

    @Test
    fun `a protocol reject of ipcp is fatal`() {
        val client = RecordingSession()
        client.openLcp()
        client.deliver(PppProtocol.LCP, PppControlPacket(PppCode.PROTOCOL_REJECT, 5, Bytes.fromHex("8021")))
        assertEquals(PppSession.Phase.FAILED, client.phase)
        assertEquals(TunnelErrorKind.PPP_FAILED, client.session.failure!!.kind)
    }

    @Test
    fun `an unknown lcp code is code rejected`() {
        val client = RecordingSession()
        client.openLcp()
        val bogus = PppControlPacket(200, 3, Bytes.fromHex("aabb"))
        client.deliver(PppProtocol.LCP, bogus)
        val reject = client.last(PppProtocol.LCP, PppCode.CODE_REJECT)
        assertArrayEquals(bogus.encode(), reject.data)
    }

    // ------------------------------------------------------------------ authentication wire format

    @Test
    fun `pap request encoding is byte exact`() {
        val client = RecordingSession(username = "alice", password = "s3cr3t")
        client.openLcp(PppAuthProtocol.PAP)
        val request = client.lastOf(PppProtocol.PAP)
        assertEquals(PapCode.AUTHENTICATE_REQUEST, request.code)
        // peer-id length, "alice", passwd length, "s3cr3t"
        assertEquals("05616c69636506733363723374", Bytes.toHex(request.data))
        // code 01, identifier 01, length 0x0011, then the body above.
        assertEquals("0101001105616c69636506733363723374", Bytes.toHex(request.encode()))
    }

    @Test
    fun `chap md5 response is md5 of identifier password and challenge`() {
        val client = RecordingSession(username = "alice", password = "s3cr3t")
        client.openLcp(PppAuthProtocol.CHAP_MD5)
        val challenge = Bytes.fromHex("00112233445566778899aabbccddeeff")
        client.deliver(
            PppProtocol.CHAP,
            PppControlPacket(ChapCode.CHALLENGE, 0x5A, ChapPacket.encode(challenge, "lns")),
        )
        val response = client.lastOf(PppProtocol.CHAP)
        assertEquals(ChapCode.RESPONSE, response.code)
        assertEquals(0x5A, response.identifier)

        val md5 = java.security.MessageDigest.getInstance("MD5")
        md5.update(0x5A.toByte())
        md5.update("s3cr3t".toByteArray())
        md5.update(challenge)
        val expected = md5.digest()
        assertEquals(16, response.data[0].toInt())
        assertArrayEquals(expected, response.data.copyOfRange(1, 17))
        assertEquals("alice", String(response.data, 17, response.data.size - 17))
    }

    @Test
    fun `ms-chapv2 response is 49 bytes with the rfc 2759 layout`() {
        val client = RecordingSession(username = "User", password = "clientPass")
        client.openLcp(PppAuthProtocol.MSCHAP_V2)
        val challenge = Bytes.fromHex("5b5d7c7d7b3f2f3e3c2c602132262628")
        client.deliver(
            PppProtocol.CHAP,
            PppControlPacket(ChapCode.CHALLENGE, 1, ChapPacket.encode(challenge, "lns")),
        )
        val response = client.lastOf(PppProtocol.CHAP)
        val value = response.data.copyOfRange(1, 1 + MsChapV2.RESPONSE_SIZE)
        assertEquals(MsChapV2.RESPONSE_SIZE, response.data[0].toInt())
        assertEquals("User", String(response.data, 1 + MsChapV2.RESPONSE_SIZE, response.data.size - 50))
        // peer challenge(16) | reserved zeros(8) | NT-Response(24) | flags(1)
        assertArrayEquals(ByteArray(8), value.copyOfRange(16, 24))
        assertEquals(0, value[48].toInt())
        assertArrayEquals(
            MsChapV2.generateNtResponse(challenge, value.copyOfRange(0, 16), "User", "clientPass"),
            value.copyOfRange(24, 48),
        )
    }

    // ------------------------------------------------------------------ authentication failures

    @Test
    fun `a pap nak fails the session with an auth error`() {
        val harness = PppHarness(FakeLns(auth = PppAuthProtocol.PAP, refuseCredentials = true))
        harness.runToCompletion()
        assertEquals(PppSession.Phase.FAILED, harness.session.phase)
        assertEquals(TunnelErrorKind.PPP_AUTH_FAILED, harness.session.failure!!.kind)
    }

    @Test
    fun `a chap failure fails the session with an auth error`() {
        val harness = PppHarness(FakeLns(auth = PppAuthProtocol.CHAP_MD5, refuseCredentials = true))
        harness.runToCompletion()
        assertEquals(PppSession.Phase.FAILED, harness.session.phase)
        assertEquals(TunnelErrorKind.PPP_AUTH_FAILED, harness.session.failure!!.kind)
    }

    @Test
    fun `an ms-chapv2 failure reports the meaning of the error code`() {
        val harness = PppHarness(FakeLns(auth = PppAuthProtocol.MSCHAP_V2, refuseCredentials = true))
        harness.runToCompletion()
        assertEquals(PppSession.Phase.FAILED, harness.session.phase)
        assertEquals(TunnelErrorKind.PPP_AUTH_FAILED, harness.session.failure!!.kind)
        val message = harness.session.failure!!.message!!
        assertTrue(message, message.contains("E=691"))
        assertTrue(message, message.contains("wrong username or password"))
    }

    @Test
    fun `an ms-chapv2 success with a wrong authenticator response is refused`() {
        val harness = PppHarness(FakeLns(auth = PppAuthProtocol.MSCHAP_V2, corruptAuthenticatorResponse = true))
        harness.runToCompletion()
        assertEquals(PppSession.Phase.FAILED, harness.session.phase)
        assertEquals(TunnelErrorKind.PPP_AUTH_FAILED, harness.session.failure!!.kind)
        assertTrue(harness.session.failure!!.message!!.contains("authenticator response"))
        assertFalse(harness.session.isOpen)
    }

    @Test
    fun `an ms-chapv2 success without an s value is refused`() {
        val client = RecordingSession(username = "User", password = "clientPass")
        client.openLcp(PppAuthProtocol.MSCHAP_V2)
        client.deliver(
            PppProtocol.CHAP,
            PppControlPacket(
                ChapCode.CHALLENGE, 1,
                ChapPacket.encode(Bytes.fromHex("5b5d7c7d7b3f2f3e3c2c602132262628"), "lns"),
            ),
        )
        client.deliver(
            PppProtocol.CHAP,
            PppControlPacket(ChapCode.SUCCESS, 1, "M=Welcome".toByteArray()),
        )
        assertEquals(PppSession.Phase.FAILED, client.phase)
        assertEquals(TunnelErrorKind.PPP_AUTH_FAILED, client.session.failure!!.kind)
    }

    // ------------------------------------------------------------------ timers

    @Test
    fun `an unanswered configure request is retransmitted and eventually fails`() {
        val client = RecordingSession()
        client.start()
        val first = client.last(PppProtocol.LCP, PppCode.CONFIGURE_REQUEST)
        assertEquals(1, client.of(PppProtocol.LCP, PppCode.CONFIGURE_REQUEST).size)

        // Nothing happens before the 3 s restart timer expires.
        client.clock.advance(2_000)
        client.session.tick()
        assertEquals(1, client.of(PppProtocol.LCP, PppCode.CONFIGURE_REQUEST).size)

        client.clock.advance(1_000)
        client.session.tick()
        val retransmission = client.of(PppProtocol.LCP, PppCode.CONFIGURE_REQUEST)
        assertEquals(2, retransmission.size)
        // RFC 1661 section 4.6: a retransmission repeats the packet, identifier included.
        assertEquals(first, retransmission.last())

        repeat(20) {
            client.clock.advance(3_000)
            client.session.tick()
        }
        assertEquals(10, client.of(PppProtocol.LCP, PppCode.CONFIGURE_REQUEST).size)
        assertEquals(PppSession.Phase.FAILED, client.phase)
        assertEquals(TunnelErrorKind.PPP_FAILED, client.session.failure!!.kind)
    }

    @Test
    fun `an unanswered pap request is retransmitted five times`() {
        val client = RecordingSession(allowedAuth = listOf(PppAuthProtocol.PAP))
        client.openLcp(PppAuthProtocol.PAP)
        repeat(20) {
            client.clock.advance(3_000)
            client.session.tick()
        }
        assertEquals(5, client.of(PppProtocol.PAP, PapCode.AUTHENTICATE_REQUEST).size)
        assertEquals(PppSession.Phase.FAILED, client.phase)
        assertEquals(TunnelErrorKind.PPP_AUTH_FAILED, client.session.failure!!.kind)
    }

    @Test
    fun `echo keepalives are sent every twenty seconds and answered`() {
        val harness = PppHarness(FakeLns(auth = PppAuthProtocol.MSCHAP_V2))
        harness.runToCompletion()
        assertTrue(harness.session.isOpen)
        harness.advance(100_000)
        assertEquals(5, harness.peer.echoRepliesSent)
        assertTrue(harness.session.isOpen)
    }

    @Test
    fun `five unanswered echo requests fail the session`() {
        val harness = PppHarness(FakeLns(auth = PppAuthProtocol.MSCHAP_V2, answerEchoes = false))
        harness.runToCompletion()
        assertTrue(harness.session.isOpen)

        harness.advance(100_000)
        assertEquals(5, harness.clientSent().count { it.protocol == PppProtocol.LCP && it.packet.code == PppCode.ECHO_REQUEST })
        assertEquals(PppSession.Phase.OPEN, harness.session.phase)

        harness.advance(20_000)
        assertEquals(PppSession.Phase.FAILED, harness.session.phase)
        assertEquals(TunnelErrorKind.PPP_FAILED, harness.session.failure!!.kind)
    }

    @Test
    fun `a peer that goes silent mid negotiation times out`() {
        val client = RecordingSession()
        client.openLcp(PppAuthProtocol.MSCHAP_V2)
        assertEquals(PppSession.Phase.AUTHENTICATE, client.phase)
        repeat(40) {
            client.clock.advance(3_000)
            client.session.tick()
        }
        assertEquals(PppSession.Phase.FAILED, client.phase)
        assertNotNull(client.session.failure)
    }

    // ------------------------------------------------------------------ shutdown

    @Test
    fun `a peer terminate request is answered with a terminate ack`() {
        val harness = PppHarness(FakeLns(auth = PppAuthProtocol.PAP))
        harness.runToCompletion()
        assertTrue(harness.session.isOpen)

        harness.session.onFrame(
            PppProtocol.LCP,
            PppControlPacket(PppCode.TERMINATE_REQUEST, 0x33, "bye".toByteArray()).encode(),
        )
        harness.pump()
        val ack = harness.clientSent().last { it.protocol == PppProtocol.LCP }.packet
        assertEquals(PppCode.TERMINATE_ACK, ack.code)
        assertEquals(0x33, ack.identifier)
        assertEquals("bye", String(ack.data))
        assertTrue(harness.peer.terminateAckSeen)
        assertEquals(PppSession.Phase.TERMINATE, harness.session.phase)
        assertFalse(harness.session.isOpen)
    }

    @Test
    fun `terminate sends a terminate request and stops once acknowledged`() {
        val harness = PppHarness(FakeLns(auth = PppAuthProtocol.PAP))
        harness.runToCompletion()
        harness.session.terminate("user requested")
        harness.pump()
        assertEquals(PppSession.Phase.TERMINATE, harness.session.phase)
        val request = harness.clientSent().last { it.protocol == PppProtocol.LCP }.packet
        assertEquals(PppCode.TERMINATE_REQUEST, request.code)
        assertEquals("user requested", String(request.data))

        harness.advance(60_000)
        assertEquals(
            1,
            harness.clientSent().count {
                it.protocol == PppProtocol.LCP && it.packet.code == PppCode.TERMINATE_REQUEST
            },
        )
    }

    @Test
    fun `an unacknowledged terminate request is retransmitted three times`() {
        val client = RecordingSession()
        client.openLcp()
        client.session.terminate("bye")
        repeat(10) {
            client.clock.advance(3_000)
            client.session.tick()
        }
        assertEquals(3, client.of(PppProtocol.LCP, PppCode.TERMINATE_REQUEST).size)
        assertEquals(PppSession.Phase.TERMINATE, client.phase)
    }

    @Test
    fun `frames received before start are ignored`() {
        val client = RecordingSession()
        client.deliver(PppProtocol.LCP, PppControlPacket(PppCode.ECHO_REQUEST, 1, ByteArray(4)))
        assertTrue(client.sent.isEmpty())
        assertEquals(PppSession.Phase.DEAD, client.phase)
    }

    @Test
    fun `a malformed control packet is discarded without failing the session`() {
        val client = RecordingSession()
        client.start()
        val before = client.sent.size
        client.session.onFrame(PppProtocol.LCP, Bytes.fromHex("0102ffff"))
        assertEquals(before, client.sent.size)
        assertEquals(PppSession.Phase.ESTABLISH, client.phase)
    }

    // ------------------------------------------------------------------ IPCP option handling

    @Test
    fun `van jacobson compression is configure rejected`() {
        val client = RecordingSession()
        client.openLcp()
        client.deliverOptions(
            PppProtocol.IPCP, PppCode.CONFIGURE_REQUEST, 2,
            listOf(
                PppOption(IpcpOption.IP_ADDRESS, Bytes.ipv4ToBytes("10.10.10.1")),
                PppOption(IpcpOption.IP_COMPRESSION_PROTOCOL, Bytes.fromHex("002d0f01")),
            ),
        )
        val reject = client.last(PppProtocol.IPCP, PppCode.CONFIGURE_REJECT)
        assertEquals(listOf(IpcpOption.IP_COMPRESSION_PROTOCOL), reject.options().map { it.type })
    }

    @Test
    fun `an ipcp configure request carrying the peer address is acknowledged`() {
        val client = RecordingSession()
        client.openLcp()
        client.deliverOptions(
            PppProtocol.IPCP, PppCode.CONFIGURE_REQUEST, 2,
            listOf(PppOption(IpcpOption.IP_ADDRESS, Bytes.ipv4ToBytes("10.10.10.1"))),
        )
        val ack = client.last(PppProtocol.IPCP, PppCode.CONFIGURE_ACK)
        assertEquals(2, ack.identifier)
        assertEquals(
            listOf(PppOption(IpcpOption.IP_ADDRESS, Bytes.ipv4ToBytes("10.10.10.1"))),
            ack.options(),
        )
    }

    @Test
    fun `a peer that acknowledges our zero address fails instead of opening`() {
        val client = RecordingSession()
        client.openLcp()
        val request = client.last(PppProtocol.IPCP, PppCode.CONFIGURE_REQUEST)
        client.deliverOptions(
            PppProtocol.IPCP, PppCode.CONFIGURE_REQUEST, 2,
            listOf(PppOption(IpcpOption.IP_ADDRESS, Bytes.ipv4ToBytes("10.10.10.1"))),
        )
        client.deliver(PppProtocol.IPCP, PppControlPacket(PppCode.CONFIGURE_ACK, request.identifier, request.data))
        assertEquals(PppSession.Phase.FAILED, client.phase)
        assertEquals(TunnelErrorKind.PPP_FAILED, client.session.failure!!.kind)
    }
}
