package com.beamio.app

/**
 * Which of a call's entries may carry the next frame (same rules as the TS SDK
 * `voice-entry-pool.ts` and iOS `BeamioEntryLatencyBand.swift`).
 *
 * Every frame still goes through a random entry, but only among this call's
 * fastest group of entries whose post times are within 50 ms of each other.
 * Mixing a 300 ms entry with a 700 ms one put a third of the frames out of
 * order at the peer (2026-11-05). A call measures its candidates first (warm-up), then keeps the
 * close ones; a new call picks new candidates.
 */
object BeamioEntryLatencyBand {
    /** Post-time samples an entry needs before it is judged. */
    const val MIN_SAMPLES = 3
    /** Kept: average ≤ fastest × ratio + slack (narrower than an 80 ms frame). */
    const val RATIO = 1.0
    const val SLACK_MS = 50.0
    /** Never fewer than this many entries in the band. */
    const val MIN_KEEP = 2
    /** Look for more candidates until this many are close to the fastest. */
    const val WANT = 3
    /** One pick in this many measures a not-yet-measured candidate. */
    const val PROBE_EVERY = 8
    /** Candidates tried per call at most while looking for close entries. */
    const val MAX_TRIED = 12

    /**
     * Entries allowed to carry the next frame. [pickIndex] counts picks in this
     * call; warm-up (first `poolTarget × MIN_SAMPLES` picks, or fewer than two
     * measured) uses all entries.
     */
    fun band(
        entries: List<String>,
        ewma: Map<String, Double>,
        samples: Map<String, Int>,
        pickIndex: Int,
        poolTarget: Int,
    ): List<String> {
        if (entries.size <= MIN_KEEP) return entries
        val measured = entries.filter { (samples[it] ?: 0) >= MIN_SAMPLES }
        if (pickIndex < poolTarget * MIN_SAMPLES || measured.size < MIN_KEEP) return entries
        val group = closeGroup(measured, ewma)
        val keep = if (group.size >= MIN_KEEP) group else measured.sortedBy { ewma[it] ?: Double.MAX_VALUE }.take(MIN_KEEP)
        val unmeasured = entries.filter { (samples[it] ?: 0) < MIN_SAMPLES }
        if (unmeasured.isNotEmpty() && pickIndex % PROBE_EVERY == PROBE_EVERY - 1) {
            return listOf(unmeasured[(pickIndex / PROBE_EVERY) % unmeasured.size])
        }
        return keep
    }

    /** Measured entries in the band (the close group; one entry when none pairs up). */
    fun closeToFastest(entries: List<String>, ewma: Map<String, Double>, samples: Map<String, Int>): List<String> {
        val measured = entries.filter { (samples[it] ?: 0) >= MIN_SAMPLES }
        if (measured.isEmpty()) return emptyList()
        return closeGroup(measured, ewma)
    }

    /**
     * The fastest group whose times lie within the band of its first (fastest)
     * member and that has at least two members; else the fastest alone. A lone
     * fast entry does not pull a much slower partner into the band.
     */
    private fun closeGroup(measured: List<String>, ewma: Map<String, Double>): List<String> {
        val sorted = measured.sortedBy { ewma[it] ?: Double.MAX_VALUE }
        for (i in sorted.indices) {
            val limit = (ewma[sorted[i]] ?: Double.MAX_VALUE) * RATIO + SLACK_MS
            val group = sorted.drop(i).filter { (ewma[it] ?: Double.MAX_VALUE) <= limit }
            if (group.size >= MIN_KEEP) return group
        }
        return sorted.take(1)
    }

    /** Random member of [band], not [last] when there is a choice. */
    fun pick(band: List<String>, last: String?, random: (Int) -> Int = { (0 until it).random() }): String? {
        if (band.isEmpty()) return null
        val choices = (if (band.size > 1 && last != null) band.filter { it != last } else band).ifEmpty { band }
        return choices[random(choices.size).coerceIn(0, choices.size - 1)]
    }
}
