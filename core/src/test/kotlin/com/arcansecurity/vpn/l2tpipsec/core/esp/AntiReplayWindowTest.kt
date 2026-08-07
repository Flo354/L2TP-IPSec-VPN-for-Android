package com.arcansecurity.vpn.l2tpipsec.core.esp

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

    /**
     * The last stretch before 2^32, where every difference has to stay in [Long]: an `Int` would
     * wrap and turn an ancient sequence number into one that looks like it is inside the window.
     */
    @Test
    fun worksAgainstTheTopOfTheSequenceSpace() {
        val w = AntiReplayWindow(64)
        val top = AntiReplayWindow.MAX_SEQ
        assertTrue(w.accept(top - 10))
        assertTrue(w.accept(top))
        assertFalse(w.accept(top))
        assertFalse(w.accept(top - 10))
        assertTrue(w.accept(top - 63)) // the left edge of the window
        assertFalse(w.accept(top - 64)) // one past it
        // 1 is 2^32 - 1 packets in the past; the difference must not wrap into the window.
        assertFalse(w.accept(1))
        assertFalse(w.accept(top - 0x7FFFFFFFL)) // exactly Int.MAX_VALUE behind
        assertFalse(w.accept(top - 0x80000000L)) // and exactly Int.MIN_VALUE behind
    }

    /**
     * Differential test against a naive set-plus-highest model, over window sizes that are not
     * whole 64-bit words and starting both at the bottom and at the top of the sequence space.
     */
    @Test
    fun matchesANaiveModel() {
        val rnd = java.util.Random(20260807)
        for (windowSize in listOf(1, 2, 7, 63, 64, 65, 100, 128, 129, 1024)) {
            for (origin in listOf(1L, AntiReplayWindow.MAX_SEQ - 4000L)) {
                val w = AntiReplayWindow(windowSize)
                val seen = HashSet<Long>()
                var highest = 0L
                repeat(3000) {
                    // A mix of in-order, slightly late, far-past and far-future arrivals.
                    val seq = when (rnd.nextInt(8)) {
                        0 -> origin + rnd.nextInt(4000)
                        1 -> highest + 1 + rnd.nextInt(2 * windowSize + 2)
                        2 -> highest - rnd.nextInt(4 * windowSize + 4)
                        else -> highest + 1 - rnd.nextInt(windowSize + 2)
                    }.coerceIn(0L, AntiReplayWindow.MAX_SEQ)

                    val expected = seq > 0 && seq !in seen &&
                        (seq > highest || highest - seq < windowSize)
                    val where = "size=$windowSize origin=$origin seq=$seq highest=$highest"
                    assertEquals(where, expected, w.isReplay(seq).not())
                    assertEquals(where, expected, w.accept(seq))
                    if (expected) {
                        seen.add(seq)
                        if (seq > highest) highest = seq
                    }
                    assertEquals(where, highest, w.highest)
                }
            }
        }
    }
}
