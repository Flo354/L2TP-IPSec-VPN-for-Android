package com.arcansecurity.vpn.l2tpipsec.core.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Test

class RedactionTest {

    @Test
    fun `a secret is replaced, never abbreviated`() {
        val rendered = redacted("hunter2")

        assertEquals("<redacted>", rendered)
        assertFalse(rendered.contains("hunter"))
    }

    /**
     * The property that matters: the output is a constant. A redaction that kept a length, a first
     * character or a hash would still be handing an attacker who reads the shared trace a shortcut.
     */
    @Test
    fun `the output does not vary with the secret`() {
        assertEquals(redacted("a"), redacted("a considerably longer pre-shared key"))
    }

    @Test
    fun `an absent secret stays distinguishable from a set one`() {
        assertEquals("<unset>", redacted(""))
        assertEquals("<unset>", redacted(null))
        assertNotEquals(redacted(null), redacted("x"))
    }
}
