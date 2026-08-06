package com.arcan.l2tpvpn.core.ppp

import com.arcan.l2tpvpn.core.tunnel.Clock
import com.arcan.l2tpvpn.core.tunnel.PppAuthProtocol
import com.arcan.l2tpvpn.core.util.Bytes
import com.arcan.l2tpvpn.core.util.VpnLogger

/** A clock the tests move by hand so retransmissions and timeouts are deterministic. */
class FakeClock(var now: Long = 100_000L) : Clock {
    override fun nowMs(): Long = now
    override fun sleep(millis: Long) {
        now += millis
    }

    fun advance(millis: Long) {
        now += millis
    }
}

/** One frame in flight between the session and the fake peer. */
data class TestFrame(val protocol: Int, val payload: ByteArray) {
    val packet: PppControlPacket get() = PppControlPacket.parse(payload)

    override fun equals(other: Any?): Boolean = this === other ||
        (other is TestFrame && protocol == other.protocol && payload.contentEquals(other.payload))

    override fun hashCode(): Int = 31 * protocol + payload.contentHashCode()

    override fun toString(): String =
        "${PppProtocol.name(protocol)} ${runCatching { packet.toString() }.getOrElse { Bytes.toHex(payload) }}"
}

/**
 * The LNS half of a PPP conversation: enough of RFC 1661/1334/1994/2759/1332 to negotiate against
 * [PppSession] the way a real server would, plus knobs for the failure cases the tests need.
 */
class FakeLns(
    /** Authentication demanded in the LCP Configure-Request; null means "no authentication". */
    val auth: PppAuthProtocol? = PppAuthProtocol.MSCHAP_V2,
    /** Raw Authentication-Protocol option value, for proposing algorithms the client will refuse. */
    private var authOption: ByteArray? = auth?.authOptionValue(),
    val username: String = "user",
    val password: String = "secret",
    val assignedAddress: String = "10.10.10.100",
    val ownAddress: String = "10.10.10.1",
    val primaryDns: String? = "10.10.10.1",
    val secondaryDns: String? = "8.8.8.8",
    val mru: Int = 1400,
    /** Answer the credentials with a Nak/Failure instead of an Ack/Success. */
    val refuseCredentials: Boolean = false,
    /** Send an MS-CHAPv2 Success whose S= value does not match, i.e. a server that faked it. */
    val corruptAuthenticatorResponse: Boolean = false,
    /** Configure-Reject the RFC 1877 DNS options instead of naking them with real values. */
    val rejectDnsOptions: Boolean = false,
    val answerEchoes: Boolean = true,
    /** Ignore IPCP entirely, which leaves the session parked in [PppSession.Phase.NETWORK]. */
    val answerIpcp: Boolean = true,
) {
    /** Installed by the harness. */
    lateinit var send: (protocol: Int, payload: ByteArray) -> Unit

    val received = ArrayList<TestFrame>()

    var magic = 0x0BADF00D
    private var identifier = 0
    private var lcpRequestSent = false
    private var lcpLocalOpen = false
    private var lcpRemoteOpen = false
    private var ipcpRequestSent = false
    private var challengeSent = false

    var authenticatorChallenge: ByteArray = Bytes.fromHex("5b5d7c7d7b3f2f3e3c2c602132262628")
    var chapIdentifier = 0
    var lastNtResponse: ByteArray? = null
    var lastPeerChallenge: ByteArray? = null
    var authenticated = false
    var terminateAckSeen = false
    var echoRepliesSent = 0

    private fun nextId(): Int {
        identifier = (identifier + 1) and 0xFF
        return identifier
    }

    private fun sendControl(protocol: Int, code: Int, id: Int, data: ByteArray) {
        send(protocol, PppControlPacket(code, id, data).encode())
    }

    private fun sendOptions(protocol: Int, code: Int, id: Int, options: List<PppOption>) {
        send(protocol, PppControlPacket.ofOptions(code, id, options).encode())
    }

    fun onFrame(protocol: Int, payload: ByteArray) {
        received += TestFrame(protocol, payload)
        val packet = PppControlPacket.parse(payload)
        when (protocol) {
            PppProtocol.LCP -> onLcp(packet)
            PppProtocol.PAP -> onPap(packet)
            PppProtocol.CHAP -> onChap(packet)
            PppProtocol.IPCP -> onIpcp(packet)
        }
    }

    // ------------------------------------------------------------------ LCP

    private fun lcpOptions(): List<PppOption> {
        val options = ArrayList<PppOption>(3)
        options += PppOption(LcpOption.MRU, byteArrayOf((mru ushr 8).toByte(), mru.toByte()))
        authOption?.let { options += PppOption(LcpOption.AUTH_PROTOCOL, it) }
        options += PppOption(
            LcpOption.MAGIC_NUMBER,
            byteArrayOf((magic ushr 24).toByte(), (magic ushr 16).toByte(), (magic ushr 8).toByte(), magic.toByte()),
        )
        return options
    }

    private fun sendLcpRequest() {
        lcpRequestSent = true
        lcpLocalOpen = false
        sendOptions(PppProtocol.LCP, PppCode.CONFIGURE_REQUEST, nextId(), lcpOptions())
    }

    private fun onLcp(packet: PppControlPacket) {
        when (packet.code) {
            PppCode.CONFIGURE_REQUEST -> {
                val reject = packet.options().filter { it.type != LcpOption.MRU && it.type != LcpOption.MAGIC_NUMBER }
                if (reject.isNotEmpty()) {
                    lcpRemoteOpen = false
                    sendOptions(PppProtocol.LCP, PppCode.CONFIGURE_REJECT, packet.identifier, reject)
                } else {
                    lcpRemoteOpen = true
                    sendOptions(PppProtocol.LCP, PppCode.CONFIGURE_ACK, packet.identifier, packet.options())
                }
                if (!lcpRequestSent) sendLcpRequest()
                maybeStartAuth()
            }

            PppCode.CONFIGURE_ACK -> {
                lcpLocalOpen = true
                maybeStartAuth()
            }

            PppCode.CONFIGURE_NAK -> {
                // The client counter-proposed; a real LNS usually accepts a protocol it also supports.
                packet.options().firstOrNull { it.type == LcpOption.AUTH_PROTOCOL }?.let { authOption = it.value }
                sendLcpRequest()
            }

            PppCode.CONFIGURE_REJECT -> {
                val rejected = packet.options().map { it.type }.toSet()
                if (LcpOption.AUTH_PROTOCOL in rejected) authOption = null
                sendLcpRequest()
            }

            PppCode.ECHO_REQUEST -> if (answerEchoes) {
                echoRepliesSent++
                val body = byteArrayOf(
                    (magic ushr 24).toByte(), (magic ushr 16).toByte(), (magic ushr 8).toByte(), magic.toByte(),
                )
                sendControl(PppProtocol.LCP, PppCode.ECHO_REPLY, packet.identifier, body)
            }

            PppCode.TERMINATE_REQUEST ->
                sendControl(PppProtocol.LCP, PppCode.TERMINATE_ACK, packet.identifier, ByteArray(0))

            PppCode.TERMINATE_ACK -> terminateAckSeen = true
        }
    }

    private fun maybeStartAuth() {
        if (!lcpLocalOpen || !lcpRemoteOpen || challengeSent) return
        val kind = decodeAuthOption()
        when (kind) {
            null -> startIpcp()
            PppAuthProtocol.PAP -> challengeSent = true // PAP is client-initiated; just wait.
            else -> {
                challengeSent = true
                chapIdentifier = nextId()
                val value = if (kind == PppAuthProtocol.MSCHAP_V2) authenticatorChallenge else CHAP_MD5_CHALLENGE
                sendControl(
                    PppProtocol.CHAP,
                    ChapCode.CHALLENGE,
                    chapIdentifier,
                    ChapPacket.encode(value, "lns"),
                )
            }
        }
    }

    private fun decodeAuthOption(): PppAuthProtocol? {
        val option = authOption ?: return null
        val protocol = ((option[0].toInt() and 0xFF) shl 8) or (option[1].toInt() and 0xFF)
        val algorithm = if (option.size >= 3) option[2].toInt() and 0xFF else -1
        return when {
            protocol == PppProtocol.PAP -> PppAuthProtocol.PAP
            protocol == PppProtocol.CHAP && algorithm == ChapAlgorithm.MD5 -> PppAuthProtocol.CHAP_MD5
            protocol == PppProtocol.CHAP && algorithm == ChapAlgorithm.MS_CHAP_V2 -> PppAuthProtocol.MSCHAP_V2
            else -> null
        }
    }

    // ------------------------------------------------------------------ authentication

    private fun onPap(packet: PppControlPacket) {
        if (packet.code != PapCode.AUTHENTICATE_REQUEST) return
        val idLength = packet.data[0].toInt() and 0xFF
        val user = String(packet.data, 1, idLength, Charsets.UTF_8)
        val pwLength = packet.data[1 + idLength].toInt() and 0xFF
        val pw = String(packet.data, 2 + idLength, pwLength, Charsets.UTF_8)
        val ok = !refuseCredentials && user == username && pw == password
        val message = if (ok) "welcome" else "invalid credentials"
        val body = ByteArray(1 + message.length).also {
            it[0] = message.length.toByte()
            System.arraycopy(message.toByteArray(Charsets.UTF_8), 0, it, 1, message.length)
        }
        authenticated = ok
        sendControl(
            PppProtocol.PAP,
            if (ok) PapCode.AUTHENTICATE_ACK else PapCode.AUTHENTICATE_NAK,
            packet.identifier,
            body,
        )
        if (ok) startIpcp()
    }

    private fun onChap(packet: PppControlPacket) {
        if (packet.code != ChapCode.RESPONSE) return
        val response = ChapValue.parse(packet.data)
        val ok = when (decodeAuthOption()) {
            PppAuthProtocol.CHAP_MD5 -> !refuseCredentials && response.name == username &&
                response.value.contentEquals(ChapPacket.md5Response(packet.identifier, password, CHAP_MD5_CHALLENGE))

            PppAuthProtocol.MSCHAP_V2 -> {
                val peerChallenge = response.value.copyOfRange(0, 16)
                val ntResponse = response.value.copyOfRange(24, 48)
                lastPeerChallenge = peerChallenge
                lastNtResponse = ntResponse
                val expected = MsChapV2.generateNtResponse(
                    authenticatorChallenge, peerChallenge, response.name, password,
                )
                !refuseCredentials && response.name == username && ntResponse.contentEquals(expected)
            }

            else -> false
        }
        authenticated = ok
        if (!ok) {
            val message = if (decodeAuthOption() == PppAuthProtocol.MSCHAP_V2) {
                "E=691 R=1 C=${Bytes.toHex(authenticatorChallenge).uppercase()} V=3 M=Authentication failure"
            } else {
                "Authentication failure"
            }
            sendControl(PppProtocol.CHAP, ChapCode.FAILURE, packet.identifier, message.toByteArray(Charsets.UTF_8))
            return
        }
        val message = if (decodeAuthOption() == PppAuthProtocol.MSCHAP_V2) {
            val authenticatorResponse = if (corruptAuthenticatorResponse) {
                "S=" + "0".repeat(40)
            } else {
                MsChapV2.generateAuthenticatorResponse(
                    password, lastNtResponse!!, lastPeerChallenge!!, authenticatorChallenge, response.name,
                )
            }
            "$authenticatorResponse M=Welcome"
        } else {
            "Welcome"
        }
        sendControl(PppProtocol.CHAP, ChapCode.SUCCESS, packet.identifier, message.toByteArray(Charsets.UTF_8))
        startIpcp()
    }

    // ------------------------------------------------------------------ IPCP

    private fun startIpcp() {
        if (ipcpRequestSent || !answerIpcp) return
        ipcpRequestSent = true
        sendOptions(
            PppProtocol.IPCP,
            PppCode.CONFIGURE_REQUEST,
            nextId(),
            listOf(PppOption(IpcpOption.IP_ADDRESS, Bytes.ipv4ToBytes(ownAddress))),
        )
    }

    private fun onIpcp(packet: PppControlPacket) {
        if (!answerIpcp) return
        when (packet.code) {
            PppCode.CONFIGURE_REQUEST -> {
                startIpcp()
                val nak = ArrayList<PppOption>()
                val reject = ArrayList<PppOption>()
                for (option in packet.options()) {
                    when (option.type) {
                        IpcpOption.IP_ADDRESS -> {
                            val wanted = Bytes.ipv4ToBytes(assignedAddress)
                            if (!option.value.contentEquals(wanted)) nak += PppOption(option.type, wanted)
                        }

                        IpcpOption.PRIMARY_DNS, IpcpOption.SECONDARY_DNS -> {
                            val wanted = if (option.type == IpcpOption.PRIMARY_DNS) primaryDns else secondaryDns
                            when {
                                rejectDnsOptions || wanted == null -> reject += option
                                !option.value.contentEquals(Bytes.ipv4ToBytes(wanted)) ->
                                    nak += PppOption(option.type, Bytes.ipv4ToBytes(wanted))
                            }
                        }

                        else -> reject += option
                    }
                }
                when {
                    reject.isNotEmpty() ->
                        sendOptions(PppProtocol.IPCP, PppCode.CONFIGURE_REJECT, packet.identifier, reject)

                    nak.isNotEmpty() ->
                        sendOptions(PppProtocol.IPCP, PppCode.CONFIGURE_NAK, packet.identifier, nak)

                    else ->
                        sendOptions(PppProtocol.IPCP, PppCode.CONFIGURE_ACK, packet.identifier, packet.options())
                }
            }

            PppCode.CONFIGURE_REJECT, PppCode.CONFIGURE_NAK ->
                // The only option the LNS asks for is its own address, which the client always takes.
                throw AssertionError("client refused the LNS IPCP options: $packet")
        }
    }

    companion object {
        val CHAP_MD5_CHALLENGE: ByteArray = Bytes.fromHex("0123456789abcdef0011223344556677")
    }
}

/**
 * Runs a [PppSession] head to head with a [FakeLns]. Frames are queued rather than delivered
 * re-entrantly so that each side sees a realistic, ordered stream.
 */
class PppHarness(
    val peer: FakeLns = FakeLns(),
    username: String = "user",
    password: String = "secret",
    allowedAuth: List<PppAuthProtocol> = listOf(
        PppAuthProtocol.MSCHAP_V2, PppAuthProtocol.CHAP_MD5, PppAuthProtocol.PAP,
    ),
    requestedMru: Int = 1400,
    val clock: FakeClock = FakeClock(),
    logger: VpnLogger = VpnLogger.NONE,
) {
    val fromClient = ArrayDeque<TestFrame>()
    val fromPeer = ArrayDeque<TestFrame>()

    val session = PppSession(
        username = username,
        password = password,
        allowedAuth = allowedAuth,
        requestedMru = requestedMru,
        send = { protocol, payload -> fromClient.addLast(TestFrame(protocol, payload)) },
        clock = clock,
        logger = logger,
    )

    init {
        peer.send = { protocol, payload -> fromPeer.addLast(TestFrame(protocol, payload)) }
    }

    /** Delivers everything both sides have queued, until the conversation goes quiet. */
    fun pump(maxRounds: Int = 200) {
        var rounds = 0
        while (fromClient.isNotEmpty() || fromPeer.isNotEmpty()) {
            if (rounds++ > maxRounds) throw AssertionError("PPP negotiation did not settle")
            while (fromClient.isNotEmpty()) {
                val frame = fromClient.removeFirst()
                peer.onFrame(frame.protocol, frame.payload)
            }
            while (fromPeer.isNotEmpty()) {
                val frame = fromPeer.removeFirst()
                session.onFrame(frame.protocol, frame.payload)
            }
        }
    }

    fun runToCompletion(): PppSession {
        session.start()
        pump()
        return session
    }

    /** Advances the clock in [stepMs] slices, ticking the session and delivering what it emits. */
    fun advance(totalMs: Long, stepMs: Long = 1_000L) {
        var elapsed = 0L
        while (elapsed < totalMs) {
            clock.advance(stepMs)
            elapsed += stepMs
            session.tick()
            pump()
        }
    }

    /** Every frame the session sent, in order. */
    fun clientSent(): List<TestFrame> = peer.received
}

/**
 * A [PppSession] wired to a recorder instead of a peer, for the tests that hand-craft packets and
 * inspect the exact reply.
 */
class RecordingSession(
    val username: String = "user",
    val password: String = "secret",
    allowedAuth: List<PppAuthProtocol> = listOf(
        PppAuthProtocol.MSCHAP_V2, PppAuthProtocol.CHAP_MD5, PppAuthProtocol.PAP,
    ),
    requestedMru: Int = 1400,
    val clock: FakeClock = FakeClock(),
) {
    val sent = ArrayList<TestFrame>()

    val session = PppSession(
        username = username,
        password = password,
        allowedAuth = allowedAuth,
        requestedMru = requestedMru,
        send = { protocol, payload -> sent += TestFrame(protocol, payload) },
        clock = clock,
    )

    val phase: PppSession.Phase get() = session.phase

    fun start() = session.start()

    fun deliver(protocol: Int, packet: PppControlPacket) = session.onFrame(protocol, packet.encode())

    fun deliverOptions(protocol: Int, code: Int, identifier: Int, options: List<PppOption>) =
        deliver(protocol, PppControlPacket.ofOptions(code, identifier, options))

    fun of(protocol: Int, code: Int): List<PppControlPacket> =
        sent.filter { it.protocol == protocol && it.packet.code == code }.map { it.packet }

    fun last(protocol: Int, code: Int): PppControlPacket =
        of(protocol, code).lastOrNull() ?: throw AssertionError(
            "no ${PppProtocol.name(protocol)} ${PppCode.name(code)} was sent, only $sent",
        )

    fun lastOf(protocol: Int): PppControlPacket =
        sent.lastOrNull { it.protocol == protocol }?.packet
            ?: throw AssertionError("nothing was sent for ${PppProtocol.name(protocol)}, only $sent")

    /** Drives LCP to Opened: acknowledges our request and sends the peer's, with [auth] if given. */
    fun openLcp(auth: PppAuthProtocol? = null, peerMru: Int = 1400) {
        start()
        val request = last(PppProtocol.LCP, PppCode.CONFIGURE_REQUEST)
        deliver(PppProtocol.LCP, PppControlPacket(PppCode.CONFIGURE_ACK, request.identifier, request.data))
        val options = ArrayList<PppOption>(3)
        options += PppOption(LcpOption.MRU, byteArrayOf((peerMru ushr 8).toByte(), peerMru.toByte()))
        auth?.let { options += PppOption(LcpOption.AUTH_PROTOCOL, it.authOptionValue()) }
        options += PppOption(LcpOption.MAGIC_NUMBER, Bytes.fromHex("0badf00d"))
        deliverOptions(PppProtocol.LCP, PppCode.CONFIGURE_REQUEST, 1, options)
    }
}
