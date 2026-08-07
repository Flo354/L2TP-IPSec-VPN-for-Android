package com.arcansecurity.vpn.l2tpipsec.core.l2tp

import com.arcansecurity.vpn.l2tpipsec.core.tunnel.Clock
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelErrorKind
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelException
import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import com.arcansecurity.vpn.l2tpipsec.core.util.VpnLogger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/** Virtual clock: every wait advances it, so the tests exercise timeouts without ever sleeping. */
internal class FakeClock(private var now: Long = 1_000_000L) : Clock {
    override fun nowMs(): Long = now

    override fun sleep(millis: Long) {
        now += millis
    }

    fun advance(millis: Long) {
        now += millis
    }
}

/**
 * Just enough LNS to drive [L2tpTunnel] through a full establishment: it answers SCCRQ with
 * SCCRP and ICRQ with ICRP, acknowledges HELLOs, and asserts the sequencing and the AVPs of
 * everything the client sends.
 */
internal class FakeLns(
    private val clock: FakeClock,
    val tunnelId: Int = 0x4321,
    val sessionId: Int = 0x8765,
    val hostName: String = "livebox",
    val challenge: ByteArray? = null,
    val secret: String? = null,
    /** Control messages to swallow before the LNS starts answering, to simulate packet loss. */
    var dropFirst: Int = 0,
) : L2tpTransport {

    class Message(val header: L2tpHeader, val type: L2tpMessageType?, val avps: List<L2tpAvp>) {
        val isZlb: Boolean get() = avps.isEmpty()
    }

    var ns = 0
        private set
    var nr = 0
        private set
    var clientTunnelId = 0
        private set
    var clientSessionId = 0
        private set
    var challengeResponse: ByteArray? = null
        private set

    val received = mutableListOf<Message>()
    val dataReceived = mutableListOf<ByteArray>()

    private val outbound = ArrayDeque<ByteArray>()
    private var dropped = 0

    fun count(type: L2tpMessageType): Int = received.count { it.type == type }

    fun types(): List<L2tpMessageType?> = received.filterNot { it.isZlb }.map { it.type }

    fun last(): Message = received.last()

    override fun send(packet: ByteArray, offset: Int, length: Int) {
        val (header, payloadOffset) = L2tpCodec.parseHeader(packet, offset, length)
        if (!header.isControl) {
            dataReceived += packet.copyOfRange(payloadOffset, payloadOffset + header.payloadLength)
            return
        }

        val avps = L2tpCodec.parseAvps(packet, payloadOffset, header.payloadLength)
        val type = avps.find(L2tpAvpType.MessageType)?.let { L2tpMessageType.of(it.asU16()) }
        received += Message(header, type, avps)

        assertEquals("the client must acknowledge everything the LNS sent", ns, header.nr)
        if (type == L2tpMessageType.SCCRQ) {
            assertEquals("the peer tunnel id is unknown until SCCRP", 0, header.tunnelId)
        } else {
            assertEquals("messages must be addressed to the LNS tunnel id", tunnelId, header.tunnelId)
        }
        if (avps.isNotEmpty()) {
            assertEquals("the Message Type AVP must come first", L2tpAvpType.MessageType, avps.first().avpType)
        }

        if (dropped < dropFirst) {
            dropped++
            return
        }
        // A ZLB only carries Nr; it consumes no sequence number.
        if (avps.isEmpty()) return
        if (header.ns != nr) {
            outbound += zlb()
            return
        }
        nr = (nr + 1) and 0xFFFF

        when (type) {
            L2tpMessageType.SCCRQ -> {
                validateSccrq(avps)
                outbound += emit(L2tpMessageType.SCCRP, sccrpAvps())
            }

            L2tpMessageType.SCCCN -> validateSccn(avps)

            L2tpMessageType.ICRQ -> {
                validateIcrq(avps)
                outbound += emit(
                    L2tpMessageType.ICRP,
                    listOf(L2tpAvp.u16(L2tpAvpType.AssignedSessionId, sessionId)),
                    sessionId = clientSessionId,
                )
            }

            L2tpMessageType.ICCN -> {
                assertEquals("ICCN must be addressed to the LNS session id", sessionId, header.sessionId)
                assertEquals(100_000_000L, avps.requireAvp(L2tpAvpType.TxConnectSpeed, "ICCN").asU32())
                assertEquals(1L, avps.requireAvp(L2tpAvpType.FramingType, "ICCN").asU32())
            }

            L2tpMessageType.HELLO -> outbound += zlb()

            else -> Unit
        }
    }

    override fun receive(timeoutMs: Int): ByteArray? {
        val next = outbound.removeFirstOrNull()
        if (next != null) return next
        clock.advance(timeoutMs.toLong())
        return null
    }

    // ------------------------------------------------------------------- messages the test injects

    /** A control message with an arbitrary Ns, for duplicate and out-of-order tests. */
    fun forge(
        type: L2tpMessageType,
        ns: Int,
        avps: List<L2tpAvp> = emptyList(),
        sessionId: Int = 0,
    ): ByteArray = L2tpCodec.encodeControl(
        clientTunnelId,
        sessionId,
        ns,
        nr,
        listOf(L2tpAvp.u16(L2tpAvpType.MessageType, type.code)) + avps,
    )

    fun zlb(): ByteArray = L2tpCodec.encodeControl(clientTunnelId, 0, ns, nr, emptyList())

    fun hello(): ByteArray = emit(L2tpMessageType.HELLO, emptyList())

    fun stopCcn(result: Int, error: Int = 0, message: String = ""): ByteArray = emit(
        L2tpMessageType.StopCCN,
        listOf(
            L2tpAvp.u16(L2tpAvpType.AssignedTunnelId, tunnelId),
            L2tpAvp.raw(L2tpAvpType.ResultCode, resultCodeValue(result, error, message)),
        ),
    )

    fun cdn(result: Int): ByteArray = emit(
        L2tpMessageType.CDN,
        listOf(
            L2tpAvp.raw(L2tpAvpType.ResultCode, resultCodeValue(result, 0, "")),
            L2tpAvp.u16(L2tpAvpType.AssignedSessionId, sessionId),
        ),
        sessionId = clientSessionId,
    )

    /** Echoes a data message back with the tunnel and session ids swapped, like a real LNS would. */
    fun reflect(dataPacket: ByteArray): ByteArray {
        val (header, payloadOffset) = L2tpCodec.parseHeader(dataPacket)
        assertFalse("PPP travels in data messages", header.isControl)
        assertEquals(tunnelId, header.tunnelId)
        assertEquals(sessionId, header.sessionId)
        return L2tpCodec.encodeData(
            clientTunnelId,
            clientSessionId,
            dataPacket,
            payloadOffset,
            header.payloadLength,
        )
    }

    // ------------------------------------------------------------------------------- internals

    private fun emit(type: L2tpMessageType, avps: List<L2tpAvp>, sessionId: Int = 0): ByteArray {
        val packet = forge(type, ns, avps, sessionId)
        ns = (ns + 1) and 0xFFFF
        return packet
    }

    private fun sccrpAvps(): List<L2tpAvp> = buildList {
        add(L2tpAvp.u16(L2tpAvpType.ProtocolVersion, 0x0100))
        add(L2tpAvp.u32(L2tpAvpType.FramingCapabilities, 3))
        add(L2tpAvp.u32(L2tpAvpType.BearerCapabilities, 3))
        add(L2tpAvp.text(L2tpAvpType.HostName, hostName))
        add(L2tpAvp.u16(L2tpAvpType.AssignedTunnelId, tunnelId))
        add(L2tpAvp.u16(L2tpAvpType.ReceiveWindowSize, 8))
        if (challenge != null) add(L2tpAvp.raw(L2tpAvpType.Challenge, challenge))
    }

    private fun validateSccrq(avps: List<L2tpAvp>) {
        assertEquals(0x0100, avps.requireAvp(L2tpAvpType.ProtocolVersion, "SCCRQ").asU16())
        assertEquals(3L, avps.requireAvp(L2tpAvpType.FramingCapabilities, "SCCRQ").asU32())
        assertEquals(3L, avps.requireAvp(L2tpAvpType.BearerCapabilities, "SCCRQ").asU32())
        assertEquals(8, avps.requireAvp(L2tpAvpType.ReceiveWindowSize, "SCCRQ").asU16())
        assertEquals(1, avps.requireAvp(L2tpAvpType.FirmwareRevision, "SCCRQ").asU16())
        assertTrue(avps.requireAvp(L2tpAvpType.HostName, "SCCRQ").asText().isNotEmpty())
        val assigned = avps.requireAvp(L2tpAvpType.AssignedTunnelId, "SCCRQ").asU16()
        assertNotEquals(0, assigned)
        if (clientTunnelId != 0) {
            assertEquals("a retransmitted SCCRQ must keep the same tunnel id", clientTunnelId, assigned)
        }
        clientTunnelId = assigned
    }

    private fun validateSccn(avps: List<L2tpAvp>) {
        val response = avps.find(L2tpAvpType.ChallengeResponse)
        if (challenge == null) {
            assertNull("no challenge was issued, so no response is expected", response)
            return
        }
        assertNotNull("the LNS challenged the client", response)
        // MD5(message type | secret | challenge), RFC 2661 section 5.1.1, computed independently.
        val md5 = MessageDigest.getInstance("MD5")
        md5.update(byteArrayOf(L2tpMessageType.SCCCN.code.toByte()))
        md5.update(secret!!.toByteArray(Charsets.UTF_8))
        md5.update(challenge)
        assertArrayEquals(md5.digest(), response!!.value)
        challengeResponse = response.value
    }

    private fun validateIcrq(avps: List<L2tpAvp>) {
        val assigned = avps.requireAvp(L2tpAvpType.AssignedSessionId, "ICRQ").asU16()
        assertNotEquals(0, assigned)
        avps.requireAvp(L2tpAvpType.CallSerialNumber, "ICRQ").asU32()
        clientSessionId = assigned
    }

    private fun resultCodeValue(result: Int, error: Int, message: String): ByteArray {
        val text = message.toByteArray(Charsets.UTF_8)
        val out = ByteArray(4 + text.size)
        out[0] = (result ushr 8).toByte()
        out[1] = result.toByte()
        out[2] = (error ushr 8).toByte()
        out[3] = error.toByte()
        System.arraycopy(text, 0, out, 4, text.size)
        return out
    }
}

class L2tpTunnelTest {

    private val clock = FakeClock()

    private fun tunnel(
        lns: FakeLns,
        secret: String? = null,
        retransmitTimeoutMs: Int = 100,
        maxRetransmits: Int = 3,
        helloIntervalMs: Int = 5_000,
    ) = L2tpTunnel(
        transport = lns,
        hostName = "android",
        clock = clock,
        logger = VpnLogger.NONE,
        tunnelSecret = secret,
        retransmitTimeoutMs = retransmitTimeoutMs,
        maxRetransmits = maxRetransmits,
        helloIntervalMs = helloIntervalMs,
    )

    // ---------------------------------------------------------------------------- establishment

    @Test
    fun `establishes the control connection and the session`() {
        val lns = FakeLns(clock)
        val tunnel = tunnel(lns)

        val info = tunnel.connect(timeoutMs = 10_000)

        assertEquals(lns.tunnelId, info.remoteTunnelId)
        assertEquals(lns.sessionId, info.remoteSessionId)
        assertEquals(lns.clientTunnelId, info.localTunnelId)
        assertEquals(lns.clientSessionId, info.localSessionId)
        assertNotEquals(0, info.localTunnelId)
        assertNotEquals(0, info.localSessionId)
        assertEquals("livebox", info.peerHostName)
        assertEquals(info, tunnel.info)

        assertEquals(
            listOf(
                L2tpMessageType.SCCRQ,
                L2tpMessageType.SCCCN,
                L2tpMessageType.ICRQ,
                L2tpMessageType.ICCN,
            ),
            lns.types(),
        )
        // Ns is consecutive and the replies are acknowledged by the next message, so no ZLB is needed.
        assertEquals(listOf(0, 1, 2, 3), lns.received.map { it.header.ns })
        assertTrue(lns.received.none { it.isZlb })
    }

    @Test
    fun `the data path is unavailable until the session is up`() {
        val lns = FakeLns(clock)
        val tunnel = tunnel(lns)

        assertNull(tunnel.info)
        assertThrows(IllegalStateException::class.java) { tunnel.encodePppFrame(ByteArray(4)) }

        tunnel.connect(timeoutMs = 10_000)
        assertNotNull(tunnel.info)
        assertThrows(IllegalStateException::class.java) { tunnel.connect(timeoutMs = 10_000) }
    }

    @Test
    fun `challenge from the lns is answered in SCCCN`() {
        val challenge = Bytes.fromHex("00112233445566778899aabbccddeeff")
        val lns = FakeLns(clock, challenge = challenge, secret = "s3cret")
        val tunnel = tunnel(lns, secret = "s3cret")

        tunnel.connect(timeoutMs = 10_000)

        // The LNS verified the digest itself; this only proves a response was actually sent.
        assertNotNull(lns.challengeResponse)
        assertEquals(16, lns.challengeResponse!!.size)
    }

    @Test
    fun `challenge without a configured secret fails with a clear message`() {
        val lns = FakeLns(clock, challenge = Bytes.fromHex("00112233"), secret = "s3cret")
        val tunnel = tunnel(lns, secret = null)

        val e = assertThrows(TunnelException::class.java) { tunnel.connect(timeoutMs = 10_000) }
        assertEquals(TunnelErrorKind.L2TP_FAILED, e.kind)
        assertTrue(e.message!!.contains("tunnel secret"))
    }

    @Test
    fun `SCCRP without an assigned tunnel id fails the connection`() {
        // An LNS that answers SCCRQ with an SCCRP carrying nothing but its Message Type AVP.
        val transport = object : L2tpTransport {
            private var pending: ByteArray? = null

            override fun send(packet: ByteArray, offset: Int, length: Int) {
                val (header, payloadOffset) = L2tpCodec.parseHeader(packet, offset, length)
                val avps = L2tpCodec.parseAvps(packet, payloadOffset, header.payloadLength)
                pending = L2tpCodec.encodeControl(
                    avps.requireAvp(L2tpAvpType.AssignedTunnelId, "SCCRQ").asU16(),
                    0,
                    0,
                    1,
                    listOf(L2tpAvp.u16(L2tpAvpType.MessageType, L2tpMessageType.SCCRP.code)),
                )
            }

            override fun receive(timeoutMs: Int): ByteArray? {
                val next = pending
                pending = null
                if (next == null) clock.advance(timeoutMs.toLong())
                return next
            }
        }

        val tunnel = L2tpTunnel(transport, "android", clock, VpnLogger.NONE)
        val e = assertThrows(TunnelException::class.java) { tunnel.connect(timeoutMs = 10_000) }

        assertEquals(TunnelErrorKind.L2TP_FAILED, e.kind)
        assertTrue(e.message!!.contains("AssignedTunnelId"))
    }

    // ------------------------------------------------------------------------------- data path

    @Test
    fun `ppp frames survive the round trip`() {
        val lns = FakeLns(clock)
        val tunnel = tunnel(lns)
        tunnel.connect(timeoutMs = 10_000)
        val ppp = Bytes.fromHex("c021 0101 0010 0104 05dc 0206 0000 0000 0506 1a2b 3c4d")

        val outbound = tunnel.encodePppFrame(ppp)

        val (header, payloadOffset) = L2tpCodec.parseHeader(outbound)
        assertFalse(header.isControl)
        assertTrue(header.hasLength)
        assertFalse(header.hasSequence)
        assertEquals(lns.tunnelId, header.tunnelId)
        assertEquals(lns.sessionId, header.sessionId)
        assertArrayEquals(ppp, outbound.copyOfRange(payloadOffset, payloadOffset + header.payloadLength))

        val inbound = lns.reflect(outbound)
        val received = tunnel.onPacket(inbound)

        assertTrue(received is L2tpTunnel.Received.Data)
        val data = received as L2tpTunnel.Received.Data
        assertArrayEquals(ppp, inbound.copyOfRange(data.offset, data.offset + data.length))
    }

    @Test
    fun `ppp frames are found inside a larger buffer`() {
        val lns = FakeLns(clock)
        val tunnel = tunnel(lns)
        tunnel.connect(timeoutMs = 10_000)
        val ppp = Bytes.random(96)

        val inbound = lns.reflect(tunnel.encodePppFrame(ppp))
        // The ESP layer hands over a decrypted buffer with the payload somewhere in the middle.
        val buffer = Bytes.concat(ByteArray(48), inbound, ByteArray(19))

        val received = tunnel.onPacket(buffer, 48, inbound.size)

        assertTrue(received is L2tpTunnel.Received.Data)
        val data = received as L2tpTunnel.Received.Data
        assertArrayEquals(ppp, buffer.copyOfRange(data.offset, data.offset + data.length))
    }

    @Test
    fun `encodePppFrameInto matches encodePppFrame`() {
        val lns = FakeLns(clock)
        val tunnel = tunnel(lns)
        tunnel.connect(timeoutMs = 10_000)
        val ppp = Bytes.random(200)

        val expected = tunnel.encodePppFrame(ppp, 16, 100)
        val scratch = ByteArray(expected.size + 40)
        val written = tunnel.encodePppFrameInto(scratch, 24, ppp, 16, 100)

        assertEquals(expected.size, written)
        assertArrayEquals(expected, scratch.copyOfRange(24, 24 + written))
    }

    @Test
    fun `data messages for another tunnel or session are ignored`() {
        val lns = FakeLns(clock)
        val tunnel = tunnel(lns)
        val info = tunnel.connect(timeoutMs = 10_000)
        val ppp = Bytes.fromHex("c02101010004")

        val wrongSession = L2tpCodec.encodeData(info.localTunnelId, info.localSessionId xor 1, ppp)
        val wrongTunnel = L2tpCodec.encodeData(info.localTunnelId xor 1, info.localSessionId, ppp)

        assertEquals(L2tpTunnel.Received.Ignored, tunnel.onPacket(wrongSession))
        assertEquals(L2tpTunnel.Received.Ignored, tunnel.onPacket(wrongTunnel))
    }

    @Test
    fun `malformed packets are ignored rather than thrown`() {
        val lns = FakeLns(clock)
        val tunnel = tunnel(lns)
        tunnel.connect(timeoutMs = 10_000)

        assertEquals(L2tpTunnel.Received.Ignored, tunnel.onPacket(Bytes.fromHex("c803 000c 1234 0000 0001 0002")))
        assertEquals(L2tpTunnel.Received.Ignored, tunnel.onPacket(ByteArray(3)))
    }

    @Test
    fun `maxPppFrameFor matches what the encoder produces`() {
        val lns = FakeLns(clock)
        val tunnel = tunnel(lns)
        tunnel.connect(timeoutMs = 10_000)

        for (budget in listOf(9, 64, 1400, 1500)) {
            val max = tunnel.maxPppFrameFor(budget)
            assertEquals(budget - L2tpCodec.dataHeaderSize(true), max)
            assertEquals(budget, tunnel.encodePppFrame(ByteArray(max)).size)
        }
        // A budget that cannot even hold the header leaves no room for PPP.
        assertEquals(0, tunnel.maxPppFrameFor(4))
    }

    // -------------------------------------------------------------------------- retransmission

    @Test
    fun `retransmits until the lns answers`() {
        val lns = FakeLns(clock, dropFirst = 2)
        val tunnel = tunnel(lns, retransmitTimeoutMs = 100, maxRetransmits = 3)

        val info = tunnel.connect(timeoutMs = 60_000)

        assertEquals(3, lns.count(L2tpMessageType.SCCRQ))
        assertEquals(lns.tunnelId, info.remoteTunnelId)
        assertEquals(lns.sessionId, info.remoteSessionId)
        // Every copy carries the same Ns and the same assigned tunnel id.
        val sccrqs = lns.received.filter { it.type == L2tpMessageType.SCCRQ }
        assertTrue(sccrqs.all { it.header.ns == 0 })
    }

    @Test
    fun `gives up after maxRetransmits`() {
        val lns = FakeLns(clock, dropFirst = Int.MAX_VALUE)
        val tunnel = tunnel(lns, retransmitTimeoutMs = 100, maxRetransmits = 3)
        val startedAt = clock.nowMs()

        val e = assertThrows(TunnelException::class.java) { tunnel.connect(timeoutMs = 60_000) }

        assertEquals(TunnelErrorKind.L2TP_FAILED, e.kind)
        assertTrue(e.message!!.contains("SCCRQ"))
        // One original plus maxRetransmits copies, backing off 100, 200, 400 and 800 ms.
        assertEquals(4, lns.count(L2tpMessageType.SCCRQ))
        assertEquals(1_500L, clock.nowMs() - startedAt)
    }

    @Test
    fun `connect gives up when the deadline passes`() {
        val lns = FakeLns(clock, dropFirst = Int.MAX_VALUE)
        val tunnel = tunnel(lns, retransmitTimeoutMs = 10_000, maxRetransmits = 50)

        val e = assertThrows(TunnelException::class.java) { tunnel.connect(timeoutMs = 2_000) }

        assertEquals(TunnelErrorKind.L2TP_FAILED, e.kind)
        assertTrue(e.message!!.contains("timed out"))
    }

    @Test
    fun `tick retransmits an unacknowledged message and eventually gives up`() {
        val lns = FakeLns(clock)
        val tunnel = tunnel(lns, retransmitTimeoutMs = 100, maxRetransmits = 2)
        tunnel.connect(timeoutMs = 10_000)
        // ICCN is never acknowledged by this LNS, so it stays in the retransmit queue.
        assertEquals(1, lns.count(L2tpMessageType.ICCN))

        clock.advance(100)
        tunnel.tick()
        assertEquals(2, lns.count(L2tpMessageType.ICCN))

        clock.advance(200)
        tunnel.tick()
        assertEquals(3, lns.count(L2tpMessageType.ICCN))

        clock.advance(400)
        val e = assertThrows(TunnelException::class.java) { tunnel.tick() }
        assertEquals(TunnelErrorKind.L2TP_FAILED, e.kind)
    }

    // -------------------------------------------------------------------------------- sequencing

    @Test
    fun `duplicate control message is re-acknowledged without advancing nr`() {
        val lns = FakeLns(clock)
        val tunnel = tunnel(lns)
        tunnel.connect(timeoutMs = 10_000)
        tunnel.onPacket(lns.zlb())
        val before = lns.received.size

        // The ICRP the client already consumed, replayed.
        val duplicate = lns.forge(
            L2tpMessageType.ICRP,
            ns = 1,
            avps = listOf(L2tpAvp.u16(L2tpAvpType.AssignedSessionId, lns.sessionId)),
            sessionId = lns.clientSessionId,
        )
        val outcome = tunnel.onPacket(duplicate)

        assertEquals(L2tpTunnel.Received.Handled, outcome)
        assertEquals(before + 1, lns.received.size)
        assertTrue("a duplicate must be re-acknowledged with a ZLB", lns.last().isZlb)
        assertEquals("Nr must not advance for a duplicate", 2, lns.last().header.nr)
    }

    @Test
    fun `out of order control message is re-acknowledged without advancing nr`() {
        val lns = FakeLns(clock)
        val tunnel = tunnel(lns)
        tunnel.connect(timeoutMs = 10_000)
        tunnel.onPacket(lns.zlb())

        val ahead = lns.forge(L2tpMessageType.HELLO, ns = 9)
        assertEquals(L2tpTunnel.Received.Handled, tunnel.onPacket(ahead))

        assertTrue(lns.last().isZlb)
        assertEquals(2, lns.last().header.nr)

        // The in-order message that follows is still accepted and advances Nr by exactly one.
        assertEquals(L2tpTunnel.Received.Handled, tunnel.onPacket(lns.hello()))
        assertTrue(lns.last().isZlb)
        assertEquals(3, lns.last().header.nr)
    }

    @Test
    fun `hello from the peer is acknowledged with a zlb`() {
        val lns = FakeLns(clock)
        val tunnel = tunnel(lns)
        tunnel.connect(timeoutMs = 10_000)
        tunnel.onPacket(lns.zlb())
        val before = lns.received.size

        assertEquals(L2tpTunnel.Received.Handled, tunnel.onPacket(lns.hello()))

        assertEquals(before + 1, lns.received.size)
        assertTrue(lns.last().isZlb)
        assertEquals(3, lns.last().header.nr)
    }

    @Test
    fun `tick sends a hello when it is due`() {
        val lns = FakeLns(clock)
        val tunnel = tunnel(lns, helloIntervalMs = 5_000)
        tunnel.connect(timeoutMs = 10_000)
        tunnel.onPacket(lns.zlb())

        tunnel.tick()
        assertEquals(0, lns.count(L2tpMessageType.HELLO))

        clock.advance(5_000)
        tunnel.tick()
        assertEquals(1, lns.count(L2tpMessageType.HELLO))

        // A second HELLO must not pile up while the first is still unacknowledged.
        tunnel.tick()
        assertEquals(1, lns.count(L2tpMessageType.HELLO))
    }

    // ------------------------------------------------------------------------------ termination

    @Test
    fun `StopCCN closes the tunnel with a decoded reason`() {
        val lns = FakeLns(clock)
        val tunnel = tunnel(lns)
        tunnel.connect(timeoutMs = 10_000)

        val outcome = tunnel.onPacket(lns.stopCcn(result = 4, error = 6, message = "account disabled"))

        assertTrue(outcome is L2tpTunnel.Received.Closed)
        val reason = (outcome as L2tpTunnel.Received.Closed).reason
        assertTrue(reason, reason.contains("not authorized"))
        assertTrue(reason, reason.contains("vendor-specific"))
        assertTrue(reason, reason.contains("account disabled"))
    }

    @Test
    fun `StopCCN silences the teardown because the peer is already gone`() {
        val lns = FakeLns(clock)
        val tunnel = tunnel(lns)
        tunnel.connect(timeoutMs = 10_000)
        tunnel.onPacket(lns.stopCcn(result = 6))
        val after = lns.received.size

        tunnel.close("done")

        assertEquals(after, lns.received.size)
    }

    @Test
    fun `CDN closes the session with a decoded reason`() {
        val lns = FakeLns(clock)
        val tunnel = tunnel(lns)
        tunnel.connect(timeoutMs = 10_000)

        val outcome = tunnel.onPacket(lns.cdn(result = 3))

        assertTrue(outcome is L2tpTunnel.Received.Closed)
        assertTrue((outcome as L2tpTunnel.Received.Closed).reason.contains("administrative"))
        // The control connection is still up, so the CDN still has to be acknowledged.
        assertTrue(lns.last().isZlb)
    }

    @Test
    fun `close sends CDN then StopCCN`() {
        val lns = FakeLns(clock)
        val tunnel = tunnel(lns)
        val info = tunnel.connect(timeoutMs = 10_000)

        tunnel.close("user disconnected")

        val teardown = lns.received.filterNot { it.isZlb }.takeLast(2)
        assertEquals(listOf(L2tpMessageType.CDN, L2tpMessageType.StopCCN), teardown.map { it.type })
        assertEquals(lns.sessionId, teardown[0].header.sessionId)
        assertEquals(info.localSessionId, teardown[0].avps.requireAvp(L2tpAvpType.AssignedSessionId, "CDN").asU16())
        assertEquals(3, teardown[0].avps.requireAvp(L2tpAvpType.ResultCode, "CDN").asU16())
        assertEquals(0, teardown[1].header.sessionId)
        assertEquals(info.localTunnelId, teardown[1].avps.requireAvp(L2tpAvpType.AssignedTunnelId, "StopCCN").asU16())
        assertEquals(1, teardown[1].avps.requireAvp(L2tpAvpType.ResultCode, "StopCCN").asU16())

        // Closing twice must not put a second teardown on the wire.
        val sent = lns.received.size
        tunnel.close("again")
        assertEquals(sent, lns.received.size)
    }
}
