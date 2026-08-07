package com.arcansecurity.vpn.l2tpipsec.core.ppp

import com.arcansecurity.vpn.l2tpipsec.core.tunnel.Clock
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.PppAuthProtocol
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelErrorKind
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelException
import com.arcansecurity.vpn.l2tpipsec.core.util.ByteReader
import com.arcansecurity.vpn.l2tpipsec.core.util.ByteWriter
import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import com.arcansecurity.vpn.l2tpipsec.core.util.Log
import com.arcansecurity.vpn.l2tpipsec.core.util.ProtocolException
import com.arcansecurity.vpn.l2tpipsec.core.util.VpnLogger

/** Everything the tunnel needs once IPCP has converged. */
data class PppResult(
    val localAddress: String,
    val remoteAddress: String,
    val dnsServers: List<String>,
    val mru: Int,
    val authProtocolUsed: PppAuthProtocol?,
)

/**
 * The PPP state machine. It is driven by the tunnel: feed it received frames with [onFrame] and
 * pump [tick]; it emits frames through [send]. It never does I/O itself so tests can run it
 * head-to-head against a fake peer.
 *
 * The negotiation automaton is the one from RFC 1661 section 4 reduced to what a client needs: it
 * tracks, per control protocol, whether our Configure-Request has been acknowledged and whether we
 * have acknowledged the peer's, and considers the protocol opened when both are true.
 *
 * Not thread-safe: [onFrame] and [tick] must be called from the same thread, which is how the
 * tunnel's single packet loop uses it.
 */
class PppSession(
    private val username: String,
    private val password: String,
    private val allowedAuth: List<PppAuthProtocol>,
    private val requestedMru: Int,
    private val send: (protocol: Int, payload: ByteArray) -> Unit,
    private val clock: Clock = Clock.SYSTEM,
    private val logger: VpnLogger = VpnLogger.NONE,
) {

    enum class Phase { DEAD, ESTABLISH, AUTHENTICATE, NETWORK, OPEN, TERMINATE, FAILED }

    private val log = Log("ppp", logger)

    var phase: Phase = Phase.DEAD
        private set

    var result: PppResult? = null
        private set

    var failure: TunnelException? = null
        private set

    /** True when [phase] is OPEN and [result] is populated. */
    val isOpen: Boolean get() = phase == Phase.OPEN && result != null

    // ---------------------------------------------------------------- negotiation bookkeeping

    /** Per-control-protocol half of the RFC 1661 option negotiation automaton. */
    private class Negotiation(val protocol: Int) {
        var identifier = 0
        var pendingId = -1
        var pendingPacket: ByteArray? = null
        var tries = 0
        var nextSendAtMs = 0L

        /** Our Configure-Request has been acknowledged. */
        var localOpen = false

        /** We have acknowledged the peer's Configure-Request. */
        var remoteOpen = false

        val opened: Boolean get() = localOpen && remoteOpen

        fun nextId(): Int {
            identifier = (identifier + 1) and 0xFF
            return identifier
        }

        fun clearPending() {
            pendingId = -1
            pendingPacket = null
        }
    }

    private val lcp = Negotiation(PppProtocol.LCP)
    private val ipcp = Negotiation(PppProtocol.IPCP)

    // LCP options we ask for.
    private var wantMru = true
    private var localMru = requestedMru
    private var wantMagic = true
    private var magic = randomMagic()

    /** RFC 1661 section 6.1: 1500 until the peer says otherwise. */
    private var peerMru = DEFAULT_MRU
    private var lcpWasOpen = false

    // IPCP options we ask for; all start as 0.0.0.0 so the peer fills them in with a Configure-Nak.
    private var localAddress = ByteArray(4)
    private var remoteAddress = ByteArray(4)
    private var wantPrimaryDns = true
    private var primaryDns = ByteArray(4)
    private var wantSecondaryDns = true
    private var secondaryDns = ByteArray(4)

    // Authentication.
    private var negotiatedAuth: PppAuthProtocol? = null
    private var authProtocolUsed: PppAuthProtocol? = null
    private var authDeadlineMs = 0L
    private var papPacket: ByteArray? = null
    private var papIdentifier = 0
    private var papTries = 0
    private var papNextSendAtMs = 0L
    private var msChapAuthenticatorChallenge: ByteArray? = null
    private var msChapPeerChallenge: ByteArray? = null
    private var msChapNtResponse: ByteArray? = null

    // Keepalives and shutdown.
    private var echoesEnabled = true
    private var lastEchoAtMs = 0L
    private var echoOutstanding = 0
    private var echoIdentifier = 0
    private var terminatePacket: ByteArray? = null
    private var terminateTries = 0
    private var terminateNextSendAtMs = 0L
    private var deadlineMs = 0L

    // ---------------------------------------------------------------- public entry points

    /** Kicks off LCP by sending the first Configure-Request. */
    fun start() {
        if (phase != Phase.DEAD) return
        phase = Phase.ESTABLISH
        deadlineMs = clock.nowMs() + NEGOTIATION_TIMEOUT_MS
        log.i("starting LCP negotiation (mru=$requestedMru, auth=${allowedAuth.joinToString()})")
        sendConfigureRequest(lcp, lcpOptions())
    }

    /** Feeds one received PPP frame (protocol + payload as produced by PppFrame.parse). */
    fun onFrame(protocol: Int, payload: ByteArray, offset: Int = 0, length: Int = payload.size - offset) {
        if (phase == Phase.DEAD || phase == Phase.FAILED) return
        try {
            when (protocol) {
                PppProtocol.LCP -> handleLcp(PppControlPacket.parse(payload, offset, length))
                PppProtocol.PAP -> handlePap(PppControlPacket.parse(payload, offset, length))
                PppProtocol.CHAP -> handleChap(PppControlPacket.parse(payload, offset, length))
                PppProtocol.IPCP -> handleIpcp(PppControlPacket.parse(payload, offset, length))
                PppProtocol.IPV4, PppProtocol.IPV6 ->
                    log.d { "ignoring a data frame received during negotiation" }
                // RFC 1661 section 5.7: anything we do not implement gets a Protocol-Reject.
                else -> sendProtocolReject(protocol, payload, offset, length)
            }
        } catch (e: ProtocolException) {
            // A malformed control packet is the peer's problem: discard it and keep negotiating.
            log.w("discarding malformed ${PppProtocol.name(protocol)} packet: ${e.message}")
        }
    }

    /** Retransmissions, LCP echo keepalives, and timeouts. Call a few times a second. */
    fun tick() {
        if (phase == Phase.DEAD || phase == Phase.FAILED) return
        val now = clock.nowMs()

        if (phase == Phase.TERMINATE) {
            tickTerminate(now)
            return
        }
        if (phase != Phase.OPEN && now >= deadlineMs) {
            fail(TunnelErrorKind.PPP_FAILED, "PPP negotiation did not complete within ${NEGOTIATION_TIMEOUT_MS / 1000}s")
            return
        }

        if (!tickConfigureRequest(lcp, now, "LCP")) return
        if (!tickConfigureRequest(ipcp, now, "IPCP")) return
        if (!tickAuth(now)) return
        tickEcho(now)
    }

    /** Sends an LCP Terminate-Request and moves to [Phase.TERMINATE]. */
    fun terminate(reason: String = "") {
        if (phase == Phase.DEAD || phase == Phase.FAILED || phase == Phase.TERMINATE) return
        phase = Phase.TERMINATE
        lcp.clearPending()
        ipcp.clearPending()
        val packet = PppControlPacket(
            PppCode.TERMINATE_REQUEST,
            lcp.nextId(),
            reason.toByteArray(Charsets.UTF_8),
        ).encode()
        terminatePacket = packet
        terminateTries = 1
        terminateNextSendAtMs = clock.nowMs() + RESTART_TIMER_MS
        log.i("sending LCP Terminate-Request${if (reason.isEmpty()) "" else " ($reason)"}")
        send(PppProtocol.LCP, packet)
    }

    // ---------------------------------------------------------------- LCP

    private fun lcpOptions(): List<PppOption> {
        val options = ArrayList<PppOption>(2)
        if (wantMru) options += PppOption(LcpOption.MRU, u16Value(localMru))
        if (wantMagic) options += PppOption(LcpOption.MAGIC_NUMBER, i32Value(magic))
        return options
    }

    private fun handleLcp(packet: PppControlPacket) {
        when (packet.code) {
            PppCode.CONFIGURE_REQUEST -> onLcpConfigureRequest(packet)

            PppCode.CONFIGURE_ACK -> if (packet.identifier == lcp.pendingId) {
                lcp.clearPending()
                lcp.localOpen = true
                checkLcpOpened()
            }

            PppCode.CONFIGURE_NAK -> if (packet.identifier == lcp.pendingId) onLcpConfigureNak(packet)

            PppCode.CONFIGURE_REJECT -> if (packet.identifier == lcp.pendingId) onLcpConfigureReject(packet)

            PppCode.TERMINATE_REQUEST -> onPeerTerminateRequest(packet)

            // RFC 1661 section 4.2: an acknowledged Terminate-Request ends the link at once, so
            // there is nothing left to retransmit.
            PppCode.TERMINATE_ACK -> if (phase == Phase.TERMINATE) {
                log.i("peer acknowledged our LCP Terminate-Request")
                terminatePacket = null
            }

            PppCode.CODE_REJECT -> onLcpCodeReject(packet)

            PppCode.PROTOCOL_REJECT -> onProtocolReject(packet)

            PppCode.ECHO_REQUEST -> onEchoRequest(packet)

            PppCode.ECHO_REPLY -> {
                echoOutstanding = 0
                log.d { "LCP Echo-Reply id=${packet.identifier}" }
            }

            PppCode.DISCARD_REQUEST -> log.d { "LCP Discard-Request" }

            else -> sendCodeReject(lcp, packet)
        }
    }

    private fun onLcpConfigureRequest(packet: PppControlPacket) {
        val review = OptionReview()
        var auth: PppAuthProtocol? = null

        for (option in packet.options()) {
            when (option.type) {
                LcpOption.MRU -> if (option.value.size == 2) {
                    peerMru = readU16(option.value)
                    review.ack += option
                } else {
                    review.reject += option
                }

                LcpOption.MAGIC_NUMBER -> if (option.value.size == 4) {
                    if (wantMagic && readI32(option.value) == magic) {
                        // RFC 1661 section 6.4: identical magic numbers mean the line is looped back.
                        fail(TunnelErrorKind.PPP_FAILED, "loopback detected: the peer echoed our magic number")
                        return
                    }
                    review.ack += option
                } else {
                    review.reject += option
                }

                LcpOption.AUTH_PROTOCOL -> {
                    val chosen = decodeAuthOption(option.value)
                    if (chosen != null && chosen in allowedAuth) {
                        auth = chosen
                        review.ack += option
                    } else {
                        val proposed = preferredAuth(peerProposedChap = isChapOption(option.value))
                        log.i("peer asked for an unsupported authentication protocol, proposing $proposed")
                        review.nak += PppOption(LcpOption.AUTH_PROTOCOL, proposed.authOptionValue())
                    }
                }

                // Quality-Protocol, ACFC, PFC and anything unknown are not implemented. Rejecting
                // ACFC/PFC also keeps the frames we parse and emit in their canonical form.
                else -> review.reject += option
            }
        }

        val acked = respond(lcp, packet, review)
        if (acked) negotiatedAuth = auth
        checkLcpOpened()
    }

    private fun onLcpConfigureNak(packet: PppControlPacket) {
        for (option in packet.options()) {
            when (option.type) {
                LcpOption.MRU -> if (option.value.size == 2) {
                    // Only ever shrink: our receive buffers are sized for requestedMru.
                    localMru = readU16(option.value).coerceIn(MIN_MRU, requestedMru)
                    log.d { "peer naked our MRU, using $localMru" }
                }

                LcpOption.MAGIC_NUMBER -> {
                    magic = if (option.value.size == 4 && readI32(option.value) != 0) readI32(option.value) else randomMagic()
                }

                else -> log.d { "ignoring LCP Configure-Nak for option ${option.type}" }
            }
        }
        sendConfigureRequest(lcp, lcpOptions())
    }

    private fun onLcpConfigureReject(packet: PppControlPacket) {
        for (option in packet.options()) {
            when (option.type) {
                LcpOption.MRU -> {
                    wantMru = false
                    localMru = DEFAULT_MRU
                }

                LcpOption.MAGIC_NUMBER -> {
                    // Without a magic number there is no loopback detection, but the link still works.
                    wantMagic = false
                    magic = 0
                }

                else -> log.d { "ignoring LCP Configure-Reject for option ${option.type}" }
            }
        }
        sendConfigureRequest(lcp, lcpOptions())
    }

    private fun onLcpCodeReject(packet: PppControlPacket) {
        val rejected = if (packet.data.isNotEmpty()) packet.data[0].toInt() and 0xFF else -1
        when {
            rejected == PppCode.ECHO_REQUEST -> {
                log.w("peer rejected LCP Echo-Request, disabling keepalives")
                echoesEnabled = false
            }
            // RFC 1661 section 5.6: rejecting a basic code is unrecoverable.
            rejected in PppCode.CONFIGURE_REQUEST..PppCode.PROTOCOL_REJECT ->
                fail(TunnelErrorKind.PPP_FAILED, "peer rejected LCP ${PppCode.name(rejected)}")

            else -> log.w("peer sent an LCP Code-Reject for code $rejected")
        }
    }

    private fun onProtocolReject(packet: PppControlPacket) {
        if (packet.data.size < 2) return
        val rejected = readU16(packet.data)
        if (rejected == PppProtocol.IPCP) {
            fail(TunnelErrorKind.PPP_FAILED, "peer rejected IPCP, no IPv4 connectivity is possible")
        } else {
            log.w("peer rejected protocol ${PppProtocol.name(rejected)}")
        }
    }

    private fun onEchoRequest(packet: PppControlPacket) {
        if (packet.data.size >= 4 && wantMagic && readI32(packet.data) == magic) {
            fail(TunnelErrorKind.PPP_FAILED, "loopback detected: an Echo-Request carried our magic number")
            return
        }
        // RFC 1661 section 5.8: the reply repeats the request's data with our own magic number.
        val body = ByteWriter(packet.data.size.coerceAtLeast(4))
            .i32(magic)
            .bytes(packet.data, 4.coerceAtMost(packet.data.size), (packet.data.size - 4).coerceAtLeast(0))
            .toByteArray()
        send(PppProtocol.LCP, PppControlPacket(PppCode.ECHO_REPLY, packet.identifier, body).encode())
    }

    private fun onPeerTerminateRequest(packet: PppControlPacket) {
        val reason = String(packet.data, Charsets.UTF_8)
        log.i("peer sent LCP Terminate-Request${if (reason.isBlank()) "" else " ($reason)"}")
        send(PppProtocol.LCP, PppControlPacket(PppCode.TERMINATE_ACK, packet.identifier, packet.data).encode())
        phase = Phase.TERMINATE
        // We are answering, not initiating: nothing left to retransmit.
        terminatePacket = null
        lcp.clearPending()
        ipcp.clearPending()
    }

    private fun checkLcpOpened() {
        if (lcpWasOpen || !lcp.opened || phase == Phase.FAILED) return
        lcpWasOpen = true
        lastEchoAtMs = clock.nowMs()
        echoOutstanding = 0
        log.i("LCP opened (peer mru=$peerMru, auth=${negotiatedAuth ?: "none"})")
        val auth = negotiatedAuth
        if (auth == null) {
            // RFC 1661 section 3.5: authentication is optional, go straight to the network phase.
            startNetworkPhase()
            return
        }
        phase = Phase.AUTHENTICATE
        authDeadlineMs = clock.nowMs() + AUTH_TIMEOUT_MS
        // Only PAP is client-initiated; both CHAP flavours wait for the peer's Challenge.
        if (auth == PppAuthProtocol.PAP) sendPapRequest()
    }

    // ---------------------------------------------------------------- authentication

    private fun decodeAuthOption(value: ByteArray): PppAuthProtocol? {
        if (value.size < 2) return null
        val protocol = readU16(value)
        val algorithm = if (value.size >= 3) value[2].toInt() and 0xFF else -1
        return when {
            protocol == PppProtocol.PAP && value.size == 2 -> PppAuthProtocol.PAP
            protocol == PppProtocol.CHAP && algorithm == ChapAlgorithm.MD5 -> PppAuthProtocol.CHAP_MD5
            protocol == PppProtocol.CHAP && algorithm == ChapAlgorithm.MS_CHAP_V2 -> PppAuthProtocol.MSCHAP_V2
            else -> null
        }
    }

    private fun isChapOption(value: ByteArray): Boolean =
        value.size >= 2 && readU16(value) == PppProtocol.CHAP

    /**
     * [allowedAuth] is ordered by preference. When the peer already asked for CHAP we counter with a
     * CHAP flavour if we have one, so that a server which only speaks CHAP is not pushed to PAP.
     */
    private fun preferredAuth(peerProposedChap: Boolean): PppAuthProtocol {
        if (peerProposedChap) {
            allowedAuth.firstOrNull { it != PppAuthProtocol.PAP }?.let { return it }
        }
        return allowedAuth.first()
    }

    private fun sendPapRequest() {
        val body = PapPacket.encodeRequest(username, password)
        // PAP has its own identifier space (RFC 1334 section 2.2); retransmissions reuse this one.
        papIdentifier = (papIdentifier + 1) and 0xFF
        val packet = PppControlPacket(PapCode.AUTHENTICATE_REQUEST, papIdentifier, body).encode()
        papPacket = packet
        papTries = 1
        papNextSendAtMs = clock.nowMs() + RESTART_TIMER_MS
        log.i("sending PAP Authenticate-Request for '$username'")
        send(PppProtocol.PAP, packet)
    }

    private fun handlePap(packet: PppControlPacket) {
        if (negotiatedAuth != PppAuthProtocol.PAP) {
            log.w("ignoring a PAP packet: PAP was not negotiated")
            return
        }
        when (packet.code) {
            PapCode.AUTHENTICATE_ACK -> {
                papPacket = null
                onAuthenticated()
            }

            PapCode.AUTHENTICATE_NAK -> {
                papPacket = null
                val message = PapPacket.message(packet.data)
                failAuth("PAP authentication failed${if (message.isBlank()) "" else ": $message"}")
            }

            else -> log.w("unexpected PAP code ${packet.code}")
        }
    }

    private fun handleChap(packet: PppControlPacket) {
        when (packet.code) {
            ChapCode.CHALLENGE -> onChapChallenge(packet)
            ChapCode.SUCCESS -> onChapSuccess(packet)
            ChapCode.FAILURE -> onChapFailure(packet)
            else -> log.w("unexpected CHAP code ${packet.code}")
        }
    }

    private fun onChapChallenge(packet: PppControlPacket) {
        val challenge = ChapValue.parse(packet.data)
        when (negotiatedAuth) {
            PppAuthProtocol.CHAP_MD5 -> {
                val response = ChapPacket.md5Response(packet.identifier, password, challenge.value)
                log.i("answering CHAP-MD5 challenge from '${challenge.name}'")
                send(
                    PppProtocol.CHAP,
                    PppControlPacket(
                        ChapCode.RESPONSE,
                        packet.identifier,
                        ChapPacket.encode(response, username),
                    ).encode(),
                )
            }

            PppAuthProtocol.MSCHAP_V2 -> {
                if (challenge.value.size != MsChapV2.CHALLENGE_SIZE) {
                    failAuth("MS-CHAPv2 challenge is ${challenge.value.size} bytes, expected ${MsChapV2.CHALLENGE_SIZE}")
                    return
                }
                val peerChallenge = Bytes.random(MsChapV2.CHALLENGE_SIZE)
                val ntResponse =
                    MsChapV2.generateNtResponse(challenge.value, peerChallenge, username, password)
                msChapAuthenticatorChallenge = challenge.value
                msChapPeerChallenge = peerChallenge
                msChapNtResponse = ntResponse
                // RFC 2759 section 4: peer challenge, 8 reserved zero bytes, NT-Response, flags.
                val value = ByteWriter(MsChapV2.RESPONSE_SIZE)
                    .bytes(peerChallenge)
                    .zeros(8)
                    .bytes(ntResponse)
                    .u8(0)
                    .toByteArray()
                log.i("answering MS-CHAPv2 challenge from '${challenge.name}'")
                send(
                    PppProtocol.CHAP,
                    PppControlPacket(
                        ChapCode.RESPONSE,
                        packet.identifier,
                        ChapPacket.encode(value, username),
                    ).encode(),
                )
            }

            else -> log.w("ignoring a CHAP challenge: CHAP was not negotiated")
        }
    }

    private fun onChapSuccess(packet: PppControlPacket) {
        if (negotiatedAuth == PppAuthProtocol.MSCHAP_V2 && !verifyMsChapSuccess(String(packet.data, Charsets.UTF_8))) {
            return
        }
        onAuthenticated()
    }

    /**
     * Checks the authenticator's `S=` response (RFC 2759 section 5). This is the half of MS-CHAPv2
     * that authenticates the *server* to us; accepting a Success without it would let anything on
     * the path claim the tunnel is authenticated.
     */
    private fun verifyMsChapSuccess(message: String): Boolean {
        val challenge = msChapAuthenticatorChallenge
        val peerChallenge = msChapPeerChallenge
        val ntResponse = msChapNtResponse
        if (challenge == null || peerChallenge == null || ntResponse == null) {
            failAuth("received an MS-CHAPv2 Success without having answered a challenge")
            return false
        }
        val received = parseMsChapAuthenticatorResponse(message)
        if (received == null) {
            failAuth("MS-CHAPv2 Success message has no valid S= authenticator response")
            return false
        }
        val expected = MsChapV2.generateAuthenticatorResponse(
            password, ntResponse, peerChallenge, challenge, username,
        )
        if (!Bytes.constantTimeEquals(Bytes.fromHex(received), Bytes.fromHex(expected.substring(2)))) {
            failAuth("MS-CHAPv2 server authenticator response mismatch, the server does not know the password")
            return false
        }
        log.i("MS-CHAPv2 server authenticator verified")
        return true
    }

    private fun onChapFailure(packet: PppControlPacket) {
        val message = String(packet.data, Charsets.UTF_8)
        if (negotiatedAuth == PppAuthProtocol.MSCHAP_V2) {
            val code = parseMsChapErrorCode(message)
            if (code >= 0) {
                failAuth("MS-CHAPv2 authentication failed: ${msChapErrorDescription(code)} (E=$code)")
                return
            }
        }
        failAuth("CHAP authentication failed${if (message.isBlank()) "" else ": $message"}")
    }

    private fun onAuthenticated() {
        if (phase != Phase.AUTHENTICATE) return
        authProtocolUsed = negotiatedAuth
        log.i("authenticated with $authProtocolUsed")
        startNetworkPhase()
    }

    // ---------------------------------------------------------------- IPCP

    private fun startNetworkPhase() {
        phase = Phase.NETWORK
        sendConfigureRequest(ipcp, ipcpOptions())
    }

    private fun ipcpOptions(): List<PppOption> {
        val options = ArrayList<PppOption>(3)
        options += PppOption(IpcpOption.IP_ADDRESS, localAddress.copyOf())
        if (wantPrimaryDns) options += PppOption(IpcpOption.PRIMARY_DNS, primaryDns.copyOf())
        if (wantSecondaryDns) options += PppOption(IpcpOption.SECONDARY_DNS, secondaryDns.copyOf())
        return options
    }

    private fun handleIpcp(packet: PppControlPacket) {
        when (packet.code) {
            PppCode.CONFIGURE_REQUEST -> onIpcpConfigureRequest(packet)

            PppCode.CONFIGURE_ACK -> if (packet.identifier == ipcp.pendingId) {
                ipcp.clearPending()
                ipcp.localOpen = true
                checkIpcpOpened()
            }

            PppCode.CONFIGURE_NAK -> if (packet.identifier == ipcp.pendingId) onIpcpConfigureNak(packet)

            PppCode.CONFIGURE_REJECT -> if (packet.identifier == ipcp.pendingId) onIpcpConfigureReject(packet)

            PppCode.TERMINATE_REQUEST -> {
                send(
                    PppProtocol.IPCP,
                    PppControlPacket(PppCode.TERMINATE_ACK, packet.identifier, ByteArray(0)).encode(),
                )
                fail(TunnelErrorKind.PPP_FAILED, "peer terminated IPCP")
            }

            PppCode.CODE_REJECT -> log.w("peer sent an IPCP Code-Reject")

            else -> sendCodeReject(ipcp, packet)
        }
    }

    private fun onIpcpConfigureRequest(packet: PppControlPacket) {
        val review = OptionReview()
        for (option in packet.options()) {
            when (option.type) {
                IpcpOption.IP_ADDRESS -> if (option.value.size == 4) {
                    remoteAddress = option.value.copyOf()
                    review.ack += option
                } else {
                    review.reject += option
                }

                // Van Jacobson header compression is not implemented, and IPCP is happy without it.
                else -> review.reject += option
            }
        }
        respond(ipcp, packet, review)
        checkIpcpOpened()
    }

    private fun onIpcpConfigureNak(packet: PppControlPacket) {
        for (option in packet.options()) {
            if (option.value.size != 4) continue
            when (option.type) {
                IpcpOption.IP_ADDRESS -> localAddress = option.value.copyOf()
                IpcpOption.PRIMARY_DNS -> primaryDns = option.value.copyOf()
                IpcpOption.SECONDARY_DNS -> secondaryDns = option.value.copyOf()
                else -> log.d { "ignoring IPCP Configure-Nak for option ${option.type}" }
            }
        }
        log.i("IPCP Configure-Nak: address=${Bytes.ipv4ToString(localAddress)} dns=${dnsServers()}")
        sendConfigureRequest(ipcp, ipcpOptions())
    }

    private fun onIpcpConfigureReject(packet: PppControlPacket) {
        for (option in packet.options()) {
            when (option.type) {
                IpcpOption.IP_ADDRESS -> {
                    fail(TunnelErrorKind.PPP_FAILED, "peer rejected the IPCP IP-Address option")
                    return
                }
                // RFC 1877 options are an extension; losing them only costs us the DNS servers.
                IpcpOption.PRIMARY_DNS -> wantPrimaryDns = false
                IpcpOption.SECONDARY_DNS -> wantSecondaryDns = false
                else -> log.d { "ignoring IPCP Configure-Reject for option ${option.type}" }
            }
        }
        log.i("peer rejected the IPCP DNS options, continuing without them")
        sendConfigureRequest(ipcp, ipcpOptions())
    }

    private fun checkIpcpOpened() {
        if (phase != Phase.NETWORK || !ipcp.opened) return
        if (isZero(localAddress)) {
            fail(TunnelErrorKind.PPP_FAILED, "IPCP completed without the peer assigning us an address")
            return
        }
        result = PppResult(
            localAddress = Bytes.ipv4ToString(localAddress),
            remoteAddress = Bytes.ipv4ToString(remoteAddress),
            dnsServers = dnsServers(),
            // What we may transmit is bounded by the peer's MRU; what we may receive by ours.
            mru = minOf(localMru, peerMru),
            authProtocolUsed = authProtocolUsed,
        )
        phase = Phase.OPEN
        log.i("PPP is up: $result")
    }

    private fun dnsServers(): List<String> {
        val out = ArrayList<String>(2)
        if (!isZero(primaryDns)) out += Bytes.ipv4ToString(primaryDns)
        if (!isZero(secondaryDns)) out += Bytes.ipv4ToString(secondaryDns)
        return out
    }

    // ---------------------------------------------------------------- shared plumbing

    private class OptionReview {
        val ack = ArrayList<PppOption>(4)
        val nak = ArrayList<PppOption>(2)
        val reject = ArrayList<PppOption>(2)
    }

    /**
     * RFC 1661 section 5.1: options we cannot recognise take precedence and produce a
     * Configure-Reject, otherwise unacceptable values produce a Configure-Nak, otherwise we
     * acknowledge the request verbatim.
     *
     * @return true when the request was acknowledged.
     */
    private fun respond(n: Negotiation, packet: PppControlPacket, review: OptionReview): Boolean {
        val code: Int
        val options: List<PppOption>
        when {
            review.reject.isNotEmpty() -> {
                code = PppCode.CONFIGURE_REJECT
                options = review.reject
            }

            review.nak.isNotEmpty() -> {
                code = PppCode.CONFIGURE_NAK
                options = review.nak
            }

            else -> {
                code = PppCode.CONFIGURE_ACK
                options = review.ack
            }
        }
        n.remoteOpen = code == PppCode.CONFIGURE_ACK
        send(n.protocol, PppControlPacket.ofOptions(code, packet.identifier, options).encode())
        return n.remoteOpen
    }

    private fun sendConfigureRequest(n: Negotiation, options: List<PppOption>) {
        n.localOpen = false
        n.pendingId = n.nextId()
        val packet = PppControlPacket.ofOptions(PppCode.CONFIGURE_REQUEST, n.pendingId, options).encode()
        n.pendingPacket = packet
        n.tries = 1
        n.nextSendAtMs = clock.nowMs() + RESTART_TIMER_MS
        send(n.protocol, packet)
    }

    /** @return false when the session has failed and the rest of [tick] must be skipped. */
    private fun tickConfigureRequest(n: Negotiation, now: Long, name: String): Boolean {
        val packet = n.pendingPacket ?: return true
        if (now < n.nextSendAtMs) return true
        if (n.tries >= MAX_CONFIGURE_REQUESTS) {
            fail(TunnelErrorKind.PPP_FAILED, "$name did not answer $MAX_CONFIGURE_REQUESTS Configure-Requests")
            return false
        }
        n.tries++
        n.nextSendAtMs = now + RESTART_TIMER_MS
        log.d { "retransmitting the $name Configure-Request (try ${n.tries})" }
        send(n.protocol, packet)
        return true
    }

    private fun tickAuth(now: Long): Boolean {
        if (phase != Phase.AUTHENTICATE) return true
        val packet = papPacket
        if (packet != null && now >= papNextSendAtMs) {
            if (papTries >= MAX_PAP_REQUESTS) {
                failAuth("PAP peer did not answer $MAX_PAP_REQUESTS Authenticate-Requests")
                return false
            }
            papTries++
            papNextSendAtMs = now + RESTART_TIMER_MS
            log.d { "retransmitting the PAP Authenticate-Request (try $papTries)" }
            send(PppProtocol.PAP, packet)
            return true
        }
        if (now >= authDeadlineMs) {
            fail(TunnelErrorKind.PPP_FAILED, "authentication with $negotiatedAuth timed out")
            return false
        }
        return true
    }

    private fun tickEcho(now: Long) {
        if (!echoesEnabled || !lcp.opened) return
        if (now - lastEchoAtMs < ECHO_INTERVAL_MS) return
        if (echoOutstanding >= MAX_UNANSWERED_ECHOES) {
            fail(TunnelErrorKind.PPP_FAILED, "the peer stopped answering LCP Echo-Requests")
            return
        }
        lastEchoAtMs = now
        echoOutstanding++
        echoIdentifier = (echoIdentifier + 1) and 0xFF
        val body = ByteWriter(4).i32(magic).toByteArray()
        send(PppProtocol.LCP, PppControlPacket(PppCode.ECHO_REQUEST, echoIdentifier, body).encode())
    }

    private fun tickTerminate(now: Long) {
        val packet = terminatePacket ?: return
        if (now < terminateNextSendAtMs) return
        if (terminateTries >= MAX_TERMINATE_REQUESTS) {
            terminatePacket = null
            return
        }
        terminateTries++
        terminateNextSendAtMs = now + RESTART_TIMER_MS
        send(PppProtocol.LCP, packet)
    }

    private fun sendCodeReject(n: Negotiation, packet: PppControlPacket) {
        log.w("rejecting unknown ${PppProtocol.name(n.protocol)} code ${packet.code}")
        // RFC 1661 section 5.6: the Rejected-Packet field is the offending packet, MRU permitting.
        val rejected = packet.encode()
        val kept = rejected.size.coerceAtMost((localMru - PppControlPacket.HEADER_SIZE).coerceAtLeast(0))
        send(
            n.protocol,
            PppControlPacket(PppCode.CODE_REJECT, n.nextId(), rejected.copyOf(kept)).encode(),
        )
    }

    private fun sendProtocolReject(protocol: Int, payload: ByteArray, offset: Int, length: Int) {
        // RFC 1661 section 5.7: Protocol-Reject may only be sent once LCP is opened.
        if (!lcp.opened) {
            log.d { "dropping ${PppProtocol.name(protocol)} frame received before LCP opened" }
            return
        }
        log.i("rejecting protocol ${PppProtocol.name(protocol)}")
        val room = (localMru - PppControlPacket.HEADER_SIZE - 2).coerceAtLeast(0)
        val kept = length.coerceAtMost(room)
        val body = ByteWriter(2 + kept).u16(protocol).bytes(payload, offset, kept).toByteArray()
        send(PppProtocol.LCP, PppControlPacket(PppCode.PROTOCOL_REJECT, lcp.nextId(), body).encode())
    }

    private fun failAuth(message: String) = fail(TunnelErrorKind.PPP_AUTH_FAILED, message)

    private fun fail(kind: TunnelErrorKind, message: String) {
        if (phase == Phase.FAILED) return
        phase = Phase.FAILED
        failure = TunnelException(kind, message)
        log.e(message)
    }

    private fun randomMagic(): Int = ByteReader(Bytes.randomNonZero(4)).i32()

    private fun u16Value(v: Int) = byteArrayOf((v ushr 8).toByte(), v.toByte())

    private fun i32Value(v: Int) =
        byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    private fun readU16(b: ByteArray) = ((b[0].toInt() and 0xFF) shl 8) or (b[1].toInt() and 0xFF)

    private fun readI32(b: ByteArray) = (readU16(b) shl 16) or
        ((b[2].toInt() and 0xFF) shl 8) or (b[3].toInt() and 0xFF)

    private fun isZero(b: ByteArray) = b.all { it.toInt() == 0 }

    companion object {
        /** RFC 1661 section 6.1 default MRU, also the value used when the option is rejected. */
        const val DEFAULT_MRU = 1500

        private const val MIN_MRU = 128

        /** RFC 1661 "Restart timer". */
        private const val RESTART_TIMER_MS = 3_000L
        private const val MAX_CONFIGURE_REQUESTS = 10
        private const val MAX_TERMINATE_REQUESTS = 3
        private const val MAX_PAP_REQUESTS = 5
        private const val ECHO_INTERVAL_MS = 20_000L
        private const val MAX_UNANSWERED_ECHOES = 5
        private const val AUTH_TIMEOUT_MS = 30_000L

        /** Safety net for a peer that simply stops talking mid-negotiation. */
        private const val NEGOTIATION_TIMEOUT_MS = 60_000L
    }
}
