package com.beamio.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Frames only on a call's entries within 50 ms of the fastest, still a random
 * entry each frame (2026-11-05: mixing 300 ms and 700 ms entries put a third of
 * the frames out of order). Same cases as the TS SDK and iOS tests.
 */
class BeamioEntryLatencyBandTest {
    private val b = BeamioEntryLatencyBand
    private val entries = listOf("a", "b", "c", "d", "e", "f")
    private val five = entries.associateWith { 5 }

    @Test
    fun warmUpUsesEveryEntry() {
        assertEquals(entries, b.band(entries, emptyMap(), emptyMap(), 0, 6))
        assertEquals(entries, b.band(entries, mapOf("a" to 300.0), mapOf("a" to 3), 17, 6))
    }

    @Test
    fun keepsOnlyEntriesCloseToTheFastest() {
        val ewma = mapOf("a" to 300.0, "b" to 320.0, "c" to 345.0, "d" to 395.0, "e" to 600.0, "f" to 700.0)
        assertEquals(listOf("a", "b", "c"), b.band(entries, ewma, five, 18, 6).sorted())
        // A lone fast entry does not pull a slow partner in: the fastest close pair wins.
        val lone = mapOf("a" to 200.0, "b" to 500.0, "c" to 520.0, "d" to 560.0, "e" to 600.0, "f" to 700.0)
        assertEquals(listOf("b", "c"), b.band(entries, lone, five, 18, 6))
        assertEquals(listOf("b", "c"), b.closeToFastest(entries, lone, five))
        // No two entries close at all: the fastest two.
        val spread = mapOf("a" to 200.0, "b" to 300.0, "c" to 400.0, "d" to 500.0, "e" to 600.0, "f" to 700.0)
        assertEquals(listOf("a", "b"), b.band(entries, spread, five, 18, 6))
    }

    @Test
    fun onlyUnmeasuredCandidatesAreProbed() {
        val ewma = mapOf("a" to 300.0, "b" to 320.0, "c" to 345.0, "d" to 395.0, "e" to 600.0, "f" to 700.0)
        assertEquals(listOf("a", "b", "c"), b.band(entries, ewma, five, 23, 6).sorted())
        val grown = entries + "g"
        assertEquals(listOf("g"), b.band(grown, ewma, five, 23, 6))
        assertEquals(listOf("a", "b", "c"), b.band(grown, ewma, five, 24, 6).sorted())
    }

    @Test
    fun picksRandomlyButNeverTheSameEntryTwiceInARow() {
        var r = 1L
        var last: String? = null
        val seen = HashSet<String>()
        repeat(200) {
            val pick = b.pick(listOf("a", "b", "c"), last) { n ->
                r = r * 6_364_136_223_846_793_005L + 1
                ((r ushr 33) % n).toInt()
            }
            assertNotEquals(last, pick)
            if (pick != null) seen.add(pick)
            last = pick
        }
        assertEquals(setOf("a", "b", "c"), seen)
        assertEquals("a", b.pick(listOf("a"), "a"))
        assertNull(b.pick(emptyList(), null))
    }
}
