package com.beamio.app

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Same cases as the PWA's voicePeerVideoGate.test.ts and iOS PeerVideoGateTests. */
class BeamioPeerVideoGateTest {
    @Test
    fun dropsFramesFromBeforeOffShowsLaterOnes() {
        val g = BeamioPeerVideoGate()
        assertTrue(g.accept(1000))
        assertTrue(g.apply(enable = false, timestamp = 2000))
        assertTrue(g.off)
        assertFalse(g.accept(1900))
        assertFalse(g.accept(2000))
        assertTrue(g.accept(2600))
        assertFalse(g.off)
        assertFalse(g.accept(1950))
    }

    @Test
    fun onOffOn() {
        val g = BeamioPeerVideoGate()
        g.apply(enable = false, timestamp = 2000)
        assertTrue(g.apply(enable = true, timestamp = 5000))
        assertFalse(g.off)
        assertTrue(g.accept(5100))
        assertFalse(g.accept(1990))
    }

    @Test
    fun repeatedOffAfterOnIsIgnored() {
        val g = BeamioPeerVideoGate()
        g.apply(enable = false, timestamp = 2000)
        g.apply(enable = true, timestamp = 3000)
        assertFalse(g.apply(enable = false, timestamp = 2000))
        assertFalse(g.off)
        val k = BeamioPeerVideoGate()
        k.apply(enable = false, timestamp = 2000)
        assertTrue(k.apply(enable = false, timestamp = 2000))
        assertTrue(k.off)
        assertEquals(2000L, k.offAt)
    }

    @Test
    fun framesWithoutTimeOnlyWhileOn() {
        val g = BeamioPeerVideoGate()
        assertTrue(g.accept(0))
        g.apply(enable = false, timestamp = 2000)
        assertFalse(g.accept(0))
        g.apply(enable = true, timestamp = 3000)
        assertTrue(g.accept(0))
    }

    @Test
    fun queuedFrameGoesStaleWhenOffLands() {
        val g = BeamioPeerVideoGate()
        assertTrue(g.accept(1800))
        g.apply(enable = false, timestamp = 2000)
        assertTrue(g.isStale(1800))
    }

    @Test
    fun missingTimestampStillAppliesAndOffAtNeverMovesBack() {
        val g = BeamioPeerVideoGate()
        g.apply(enable = false, timestamp = 4000)
        assertTrue(g.apply(enable = true, timestamp = 0))
        assertFalse(g.off)
        assertTrue(g.apply(enable = false, timestamp = 0))
        assertTrue(g.off)
        assertEquals(4000L, g.offAt)
    }

    @Test
    fun resetAndRepeats() {
        val g = BeamioPeerVideoGate()
        g.apply(enable = false, timestamp = 2000)
        g.reset()
        assertFalse(g.off)
        assertTrue(g.accept(1000))
        assertArrayEquals(longArrayOf(0L, 1_500L, 4_000L), BeamioPeerVideoGate.OFF_REPEAT_MS)
    }
}
