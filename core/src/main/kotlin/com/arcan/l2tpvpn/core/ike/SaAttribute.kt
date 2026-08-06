package com.arcan.l2tpvpn.core.ike

import com.arcan.l2tpvpn.core.util.ByteReader
import com.arcan.l2tpvpn.core.util.ByteWriter
import com.arcan.l2tpvpn.core.util.Bytes
import com.arcan.l2tpvpn.core.util.ProtocolException

/**
 * One SA attribute of a transform payload (RFC 2408 section 3.3).
 *
 * The top bit of the 16-bit type field selects the encoding: set means "basic", a fixed 2-byte
 * value carried in the length slot (TV); clear means "variable", a length followed by that many
 * bytes (TLV). The type itself is always the low 15 bits.
 */
class SaAttribute private constructor(
    val type: Int,
    /** `true` for the TV form. */
    val basic: Boolean,
    val value: ByteArray,
) {

    /** The value read as a big-endian unsigned integer; only defined for values of 1..4 bytes. */
    val intValue: Int
        get() {
            if (value.isEmpty() || value.size > 4) {
                throw ProtocolException("attribute $type has a ${value.size}-byte value, not an integer")
            }
            var v = 0
            for (b in value) v = (v shl 8) or (b.toInt() and 0xFF)
            return v
        }

    override fun equals(other: Any?): Boolean =
        other is SaAttribute && other.type == type && other.basic == basic && other.value.contentEquals(value)

    override fun hashCode(): Int = (type * 31 + if (basic) 1 else 0) * 31 + value.contentHashCode()

    override fun toString(): String =
        "SaAttribute(type=$type, ${if (basic) "TV" else "TLV"}, value=${Bytes.toHex(value)})"

    companion object {
        private const val BASIC_FLAG = 0x8000
        private const val TYPE_MASK = 0x7FFF

        /** Type/value form: a 16-bit value inlined in the header. */
        fun tv(type: Int, value: Int): SaAttribute {
            require(type and TYPE_MASK.inv() == 0) { "attribute type $type does not fit in 15 bits" }
            require(value in 0..0xFFFF) { "basic attribute value $value does not fit in 16 bits" }
            return SaAttribute(type, true, byteArrayOf((value ushr 8).toByte(), value.toByte()))
        }

        /** Type/length/value form; the only way to carry a 4-byte lifetime. */
        fun tlv(type: Int, value: ByteArray): SaAttribute {
            require(type and TYPE_MASK.inv() == 0) { "attribute type $type does not fit in 15 bits" }
            return SaAttribute(type, false, value)
        }

        /** TLV holding a 32-bit big-endian value, the usual shape of SA life durations. */
        fun tlv32(type: Int, value: Int): SaAttribute =
            tlv(type, ByteWriter(4).i32(value).toByteArray())

        fun encodeAll(attributes: List<SaAttribute>): ByteArray {
            val w = ByteWriter(attributes.size * 8)
            for (a in attributes) {
                if (a.basic) {
                    w.u16(BASIC_FLAG or a.type).bytes(a.value)
                } else {
                    w.u16(a.type).u16(a.value.size).bytes(a.value)
                }
            }
            return w.toByteArray()
        }

        fun decodeAll(reader: ByteReader): List<SaAttribute> {
            val out = ArrayList<SaAttribute>(4)
            while (reader.hasRemaining) {
                val header = reader.u16()
                val type = header and TYPE_MASK
                out += if (header and BASIC_FLAG != 0) {
                    SaAttribute(type, true, reader.bytes(2))
                } else {
                    SaAttribute(type, false, reader.bytes(reader.u16()))
                }
            }
            return out
        }

        fun decodeAll(body: ByteArray): List<SaAttribute> = decodeAll(ByteReader(body))
    }
}
