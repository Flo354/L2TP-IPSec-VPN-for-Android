package com.arcansecurity.vpn.l2tpipsec.core.e2e

import com.arcansecurity.vpn.l2tpipsec.core.tunnel.Datagram
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunInterface
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunParameters
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunProvider
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.UdpSocketChannel
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.UdpSocketFactory
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * JVM stand-ins for the two things the Android layer normally provides. They let the real
 * [com.arcansecurity.vpn.l2tpipsec.core.tunnel.L2tpIpsecTunnel] talk to a real L2TP/IPsec server from a plain
 * unit test: sockets are ordinary UDP sockets (nothing to protect, there is no VPN routing here)
 * and the TUN is an in-memory pair of queues we can inject packets into and read replies from.
 */
class TestUdpSocketFactory(private val serverAddress: InetAddress) : UdpSocketFactory {
    override fun open(): UdpSocketChannel = TestUdpSocketChannel(serverAddress)
}

class TestUdpSocketChannel(serverAddress: InetAddress) : UdpSocketChannel {
    private val socket = DatagramSocket()

    override val localAddress: InetAddress = probeLocalAddress(serverAddress)
    override val localPort: Int get() = socket.localPort

    override fun send(data: ByteArray, offset: Int, length: Int, destination: InetSocketAddress) {
        socket.send(DatagramPacket(data, offset, length, destination))
    }

    override fun receive(buffer: ByteArray, timeoutMs: Int): Datagram? {
        socket.soTimeout = timeoutMs
        val packet = DatagramPacket(buffer, buffer.size)
        return try {
            socket.receive(packet)
            Datagram(packet.length, InetSocketAddress(packet.address, packet.port))
        } catch (e: SocketTimeoutException) {
            null
        }
    }

    override fun close() = socket.close()

    private companion object {
        /**
         * The address the OS would actually source packets to the server from. Connecting an
         * unbound UDP socket costs nothing and, unlike `InetAddress.getLocalHost()`, gives the
         * right answer on a multi-homed host — which matters because IKE identities and NAT-D
         * hashes are computed over it.
         */
        fun probeLocalAddress(serverAddress: InetAddress): InetAddress =
            DatagramSocket().use { probe ->
                probe.connect(serverAddress, 4500)
                probe.localAddress
            }
    }
}

/** Captures everything the tunnel writes toward the OS and lets a test inject outbound packets. */
class FakeTun(val params: TunParameters) : TunInterface {
    /** Packets the tunnel delivered to us, i.e. traffic arriving from the VPN. */
    val inbound = LinkedBlockingQueue<ByteArray>()

    /** Packets a test wants to send through the VPN. */
    private val outbound = LinkedBlockingQueue<ByteArray>()

    @Volatile private var closed = false

    fun inject(packet: ByteArray) {
        outbound.put(packet)
    }

    fun awaitInbound(timeoutMs: Long): ByteArray? = inbound.poll(timeoutMs, TimeUnit.MILLISECONDS)

    override fun readPacket(buffer: ByteArray): Int {
        while (!closed) {
            val packet = outbound.poll(200, TimeUnit.MILLISECONDS) ?: continue
            System.arraycopy(packet, 0, buffer, 0, packet.size)
            return packet.size
        }
        return -1
    }

    override fun writePacket(buffer: ByteArray, offset: Int, length: Int) {
        inbound.put(buffer.copyOfRange(offset, offset + length))
    }

    override fun close() {
        closed = true
    }
}

class FakeTunProvider : TunProvider {
    @Volatile var established: FakeTun? = null
        private set

    override fun establish(params: TunParameters): TunInterface =
        FakeTun(params).also { established = it }
}
