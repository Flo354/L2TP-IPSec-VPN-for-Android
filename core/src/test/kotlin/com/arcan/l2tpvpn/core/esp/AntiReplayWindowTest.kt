package com.arcan.l2tpvpn.core.esp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AntiReplayWindowTest {

    @Test
    fun acceptsAnInOrderSequence() {
        val w = AntiReplayWindow(64)
        for (seq in 1L..1000L) assertTrue("seq $seq", w.accept(seq))
        assertEquals(1000L, w.highest)
    }

    @Test
    fun rejectsDuplicates() {
        val w = AntiReplayWindow(64)
        assertTrue(w.accept(1))
        assertFalse(w.accept(1))
        assertTrue(w.accept(2))
        assertFalse(w.accept(2))
        assertFalse(w.accept(1))
        assertEquals(2L, w.highest)
    }

    @Test
    fun acceptsOutOfOrderInsideTheWindowExactlyOnce() {
        val w = AntiReplayWindow(64)
        assertTrue(w.accept(10))
        // Everything from 1 to 9 is still inside the 64-packet window and arrives late.
        for (seq in 1L..9L) assertTrue("seq $seq", w.accept(seq))
        for (seq in 1L..9L) assertFalse("replay of $seq", w.accept(seq))
        assertEquals(10L, w.highest)
    }

    @Test
    fun rejectsSequencesLeftOfTheWindow() {
        val w = AntiReplayWindow(64)
        assertTrue(w.accept(100))
        assertTrue(w.accept(100 - 63)) // the left edge, still inside
        assertFalse(w.accept(100 - 64)) // one past it
        assertFalse(w.accept(1))
    }

    @Test
    fun windowSlidesOnABigJump() {
        val w = AntiReplayWindow(64)
        assertTrue(w.accept(1))
        assertTrue(w.accept(1_000_000))
        assertEquals(1_000_000L, w.highest)
        // The old bitmap is gone: 1 is now far in the past, and so is everything near it.
        assertFalse(w.accept(1))
        assertFalse(w.accept(999_936)) // highest - 64
        assertTrue(w.accept(999_937)) // highest - 63, the left edge
        assertFalse(w.accept(1_000_000)) // the jump itself was recorded
    }

    @Test
    fun windowSlidesByLessThanItsWidth() {
        val w = AntiReplayWindow(64)
        assertTrue(w.accept(1))
        assertTrue(w.accept(2))
        assertTrue(w.accept(40))
        // 1 and 2 must still be remembered after the 38-packet slide.
        assertFalse(w.accept(1))
        assertFalse(w.accept(2))
        assertTrue(w.accept(3))
        assertFalse(w.accept(40))
    }

    /** RFC 4303 section 3.3.3: the first packet on an SA carries sequence number 1, never 0. */
    @Test
    fun sequenceZeroIsNeverAccepted() {
        val w = AntiReplayWindow(64)
        assertFalse(w.accept(0))
        assertTrue(w.isReplay(0))
        assertEquals(0L, w.highest)
        assertTrue(w.accept(1))
        assertFalse(w.accept(0))
    }

    @Test
    fun rejectsBeyondTheThirtyTwoBitSpace() {
        val w = AntiReplayWindow(64)
        assertTrue(w.accept(AntiReplayWindow.MAX_SEQ))
        assertFalse(w.accept(AntiReplayWindow.MAX_SEQ + 1))
    }

    @Test
    fun isReplayDoesNotMutate() {
        val w = AntiReplayWindow(64)
        assertTrue(w.accept(5))
        assertTrue(w.isReplay(5))
        assertFalse(w.isReplay(4))
        assertFalse(w.isReplay(6))
        assertEquals(5L, w.highest)
        // The probe recorded nothing, so both still get in.
        assertTrue(w.accept(4))
        assertTrue(w.accept(6))
    }

    @Test
    fun worksWithAWindowWiderThanOneWord() {
        val w = AntiReplayWindow(128)
        assertTrue(w.accept(200))
        for (seq in 200L - 127 until 200L) assertTrue("seq $seq", w.accept(seq))
        assertFalse(w.accept(200 - 128))
        for (seq in 200L - 127..200L) assertFalse("replay of $seq", w.accept(seq))
    }

    @Test
    fun singlePacketWindowOnlyRemembersTheLatest() {
        val w = AntiReplayWindow(1)
        assertTrue(w.accept(5))
        assertFalse(w.accept(5))
        assertFalse(w.accept(4))
        assertTrue(w.accept(6))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsAnAbsurdWindowSize() {
        AntiReplayWindow(0)
    }
}
