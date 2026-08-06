package com.arcan.l2tpvpn.core.util

/**
 * Growable big-endian byte buffer. Length fields in ISAKMP, L2TP and PPP are only known after the
 * nested payloads have been emitted, so [patchU16]/[patchU32] let callers reserve a slot and fill
 * it in afterwards.
 */
class ByteWriter(initialCapacity: Int = 128) {
    private var buf = ByteArray(initialCapacity.coerceAtLeast(16))
    private var len = 0

    val size: Int get() = len

    private fun ensure(extra: Int) {
        if (len + extra <= buf.size) return
        var cap = buf.size
        while (cap < len + extra) cap = cap shl 1
        buf = buf.copyOf(cap)
    }

    fun u8(v: Int) = apply {
        ensure(1)
        buf[len++] = v.toByte()
    }

    fun u16(v: Int) = apply {
        ensure(2)
        buf[len++] = (v ushr 8).toByte()
        buf[len++] = v.toByte()
    }

    fun u24(v: Int) = apply {
        ensure(3)
        buf[len++] = (v ushr 16).toByte()
        buf[len++] = (v ushr 8).toByte()
        buf[len++] = v.toByte()
    }

    fun u32(v: Long) = apply {
        ensure(4)
        buf[len++] = (v ushr 24).toByte()
        buf[len++] = (v ushr 16).toByte()
        buf[len++] = (v ushr 8).toByte()
        buf[len++] = v.toByte()
    }

    fun i32(v: Int) = u32(v.toLong() and 0xFFFFFFFFL)

    fun bytes(b: ByteArray) = bytes(b, 0, b.size)

    fun bytes(b: ByteArray, off: Int, count: Int) = apply {
        ensure(count)
        System.arraycopy(b, off, buf, len, count)
        len += count
    }

    fun zeros(n: Int) = apply {
        ensure(n)
        java.util.Arrays.fill(buf, len, len + n, 0)
        len += n
    }

    /** Reserves [n] zero bytes and returns the offset so it can be patched later. */
    fun reserve(n: Int): Int {
        val at = len
        zeros(n)
        return at
    }

    fun patchU16(offset: Int, v: Int) {
        checkPatch(offset, 2)
        buf[offset] = (v ushr 8).toByte()
        buf[offset + 1] = v.toByte()
    }

    fun patchU32(offset: Int, v: Long) {
        checkPatch(offset, 4)
        buf[offset] = (v ushr 24).toByte()
        buf[offset + 1] = (v ushr 16).toByte()
        buf[offset + 2] = (v ushr 8).toByte()
        buf[offset + 3] = v.toByte()
    }

    fun patchU8(offset: Int, v: Int) {
        checkPatch(offset, 1)
        buf[offset] = v.toByte()
    }

    private fun checkPatch(offset: Int, n: Int) {
        require(offset >= 0 && offset + n <= len) { "patch out of range at $offset" }
    }

    fun toByteArray(): ByteArray = buf.copyOf(len)
}
