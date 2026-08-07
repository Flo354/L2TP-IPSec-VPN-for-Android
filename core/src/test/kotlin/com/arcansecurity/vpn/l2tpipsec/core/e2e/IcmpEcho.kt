package com.arcansecurity.vpn.l2tpipsec.core.e2e

import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes

/**
 * A self-contained IPv4/ICMP echo builder for the end-to-end test. It deliberately does not use
 * the production `net` package: the point of the end-to-end test is to check the stack against a
 * real server, so the probe it sends should be built independently of the code under test.
 */
object IcmpEcho {

    fun request(sourceIp: String, destinationIp: String, identifier: Int, sequence: Int, payload: ByteArray): ByteArray {
        val icmp = ByteArray(8 + payload.size)
        icmp[0] = 8 // echo request
        icmp[1] = 0
        icmp[4] = (identifier ushr 8).toByte()
        icmp[5] = identifier.toByte()
        icmp[6] = (sequence ushr 8).toByte()
        icmp[7] = sequence.toByte()
        payload.copyInto(icmp, 8)
        val icmpChecksum = checksum(icmp, 0, icmp.size)
        icmp[2] = (icmpChecksum ushr 8).toByte()
        icmp[3] = icmpChecksum.toByte()

        val total = 20 + icmp.size
        val packet = ByteArray(total)
        packet[0] = 0x45
        packet[2] = (total ushr 8).toByte()
        packet[3] = total.toByte()
        packet[4] = 0x12
        packet[5] = 0x34
        packet[8] = 64 // TTL
        packet[9] = 1 // ICMP
        Bytes.ipv4ToBytes(sourceIp).copyInto(packet, 12)
        Bytes.ipv4ToBytes(destinationIp).copyInto(packet, 16)
        val ipChecksum = checksum(packet, 0, 20)
        packet[10] = (ipChecksum ushr 8).toByte()
        packet[11] = ipChecksum.toByte()
        icmp.copyInto(packet, 20)
        return packet
    }

    data class Reply(val sourceIp: String, val destinationIp: String, val identifier: Int, val sequence: Int, val payload: ByteArray)

    /** Returns null when [packet] is not an ICMP echo reply. */
    fun parseReply(packet: ByteArray, offset: Int = 0, length: Int = packet.size - offset): Reply? {
        if (length < 28) return null
        if ((packet[offset].toInt() and 0xF0) != 0x40) return null
        val ihl = (packet[offset].toInt() and 0x0F) * 4
        if (packet[offset + 9].toInt() != 1) return null
        val icmp = offset + ihl
        if (packet[icmp].toInt() != 0) return null // echo reply
        val identifier = ((packet[icmp + 4].toInt() and 0xFF) shl 8) or (packet[icmp + 5].toInt() and 0xFF)
        val sequence = ((packet[icmp + 6].toInt() and 0xFF) shl 8) or (packet[icmp + 7].toInt() and 0xFF)
        return Reply(
            sourceIp = Bytes.ipv4ToString(packet, offset + 12),
            destinationIp = Bytes.ipv4ToString(packet, offset + 16),
            identifier = identifier,
            sequence = sequence,
            payload = packet.copyOfRange(icmp + 8, offset + length),
        )
    }

    private fun checksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) sum += (data[i].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }
}
