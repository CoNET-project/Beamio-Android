package com.beamio.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Downlink buffer driven by the playout clock: wait for a missing frame only
 * while the track still has audio, then conceal and go on (2026-11-05: frames
 * through random entries arrive 25–35 % out of order, up to ~0.3 s apart, and
 * the old buffer drained the track waiting for them). Same cases as iOS
 * `VoicePlayoutPlannerTests.swift`.
 */
class BeamioVoicePlayoutPlannerTest {
    private val frame = 2_560 // 160 ms at 16 kHz
    private fun planner(maxPending: Int = 48, frameSamples: Int = 2_560) =
        BeamioVoicePlayoutPlanner<Int>(
            BeamioVoicePlayoutPlanner.Config(maxPending = maxPending, defaultFrameSamples = frameSamples),
        )

    private fun plays(a: List<BeamioVoicePlayoutPlanner.Action<Int>>) =
        a.filterIsInstance<BeamioVoicePlayoutPlanner.Action.Play<Int>>().map { it.seq }

    private fun conceals(a: List<BeamioVoicePlayoutPlanner.Action<Int>>) =
        a.filterIsInstance<BeamioVoicePlayoutPlanner.Action.Conceal>().map { it.seq }

    @Test
    fun inOrderFramesPlayStraightThrough() {
        val p = planner()
        val out = ArrayList<BeamioVoicePlayoutPlanner.Action<Int>>()
        for (seq in 1..5) {
            p.push(seq, seq, frame, 0)
            out += p.pump(0, true, 0)
        }
        assertEquals(listOf(1, 2, 3, 4, 5), plays(out))
        assertEquals(0, p.counters.concealed)
    }

    @Test
    fun waitsForAMissingFrameWhileThePlayerHasAudio() {
        val p = planner()
        p.push(1, 1, frame, 0)
        p.pump(0, true, 0)
        p.push(3, 3, frame, 0)
        assertTrue(p.pump(2 * frame, true, 0).isEmpty())
        p.push(2, 2, frame, 0)
        assertEquals(listOf(2, 3), plays(p.pump(2 * frame, true, 0)))
        assertEquals(0, p.counters.concealed)
    }

    @Test
    fun concealsWhenItsTurnComesAndKeepsPlaying() {
        val p = planner()
        p.push(1, 1, frame, 0)
        p.pump(0, true, 0)
        p.push(3, 3, frame, 0)
        p.push(4, 4, frame, 0)
        val out = p.pump(frame, true, 0)
        assertEquals(listOf(2), conceals(out))
        assertEquals(listOf(3, 4), plays(out))
    }

    @Test
    fun lateFrameRaisesTheDepthWithAStretch() {
        val p = planner()
        p.push(1, 1, frame, 0)
        p.pump(0, true, 0)
        p.push(3, 3, frame, 0)
        p.pump(0, true, 0) // conceals 2
        assertEquals(BeamioVoicePlayoutPlanner.PushResult.LATE, p.push(2, 2, frame, 100))
        assertEquals(5_120 + 1_280, p.targetSamples)
        p.push(5, 5, frame, 100)
        val out = p.pump(0, true, 100)
        assertEquals(BeamioVoicePlayoutPlanner.Action.Stretch(1_280), out.first())
        assertEquals(listOf(4), conceals(out))
        assertEquals(listOf(5), plays(out))
    }

    @Test
    fun staleAndDuplicateFramesAreIgnored() {
        val p = planner()
        p.push(1, 1, frame, 0)
        p.pump(0, true, 0)
        assertEquals(BeamioVoicePlayoutPlanner.PushResult.STALE, p.push(1, 1, frame, 0))
        assertEquals(BeamioVoicePlayoutPlanner.PushResult.ACCEPTED, p.push(3, 3, frame, 0))
        assertEquals(BeamioVoicePlayoutPlanner.PushResult.DUPLICATE, p.push(3, 3, frame, 0))
    }

    @Test
    fun aHoleBeforePlayoutStartsIsSkippedOnceEnoughAudioWaits() {
        val p = planner()
        p.push(10, 10, frame, 0)
        p.pump(0, false, 0)
        p.push(12, 12, frame, 0)
        assertTrue(p.pump(frame, false, 0).isEmpty())
        p.push(13, 13, frame, 0)
        val out = p.pump(frame, false, 0)
        assertEquals(BeamioVoicePlayoutPlanner.Action.Skip(11, 12), out.first())
        assertEquals(listOf(12, 13), plays(out))
    }

    @Test
    fun zeroSampleItemsMoveTheSequenceOn() {
        val p = planner()
        p.push(1, 1, frame, 0)
        p.push(2, 2, 0, 0)
        p.push(3, 3, frame, 0)
        assertEquals(listOf(1, 2, 3), plays(p.pump(0, true, 0)))
    }

    @Test
    fun underrunGrowsTheDepthUpToOneSecondAndStableDecays() {
        val p = planner()
        for (i in 0 until 10) p.noteUnderrun(i.toLong())
        assertEquals(16_000, p.targetSamples)
        p.push(1, 1, frame, 0)
        p.pump(0, true, 10_009)
        assertEquals(16_000 - 1_280, p.targetSamples)
        p.pump(0, true, 15_000)
        assertEquals(16_000 - 1_280, p.targetSamples)
    }

    @Test
    fun overflowSkipsToTheOldestWaitingFrame() {
        val p = planner(maxPending = 4)
        p.push(1, 1, frame, 0)
        p.pump(0, true, 0)
        for (seq in 5..9) p.push(seq, seq, frame, 0)
        val out = p.pump(10 * frame, true, 0)
        assertEquals(listOf(5, 6, 7, 8, 9), plays(out))
        assertEquals(3, p.counters.skipped)
    }

    /**
     * Live-like runs: 0.5 s base delay plus 0–300 ms jitter, 1 % lost and a
     * slow-entry tail; the track drains in real time. The old rule ran the track
     * dry 2–6 times a minute (0.6–1 s of silence); the new one at most once.
     */
    @Test
    fun jitteryLinkPlaysWithFewGaps() {
        for (frameMs in listOf(80, 160)) {
            val r = simulate(frameMs, 300, 60, oldBuffer = false)
            val old = simulate(frameMs, 300, 60, oldBuffer = true)
            assertTrue("ooo ${r.outOfOrder}", r.outOfOrder > 0.10)
            assertTrue("new gaps ${r.gapRatio} old ${old.gapRatio}", r.gapRatio < 0.04)
            assertTrue("new underruns ${r.underruns} old ${old.underruns}", r.underruns <= 1)
            assertTrue("old underruns ${old.underruns}", old.underruns >= 2)
            assertTrue("new silent ${r.silentMs} old ${old.silentMs}", r.silentMs * 3 < old.silentMs)
        }
    }

    data class SimResult(val gapRatio: Double, val underruns: Int, val outOfOrder: Double, val silentMs: Int)

    /** Same model and seed as the iOS test. */
    private fun simulate(
        frameMs: Int,
        jitterMs: Int,
        seconds: Int,
        oldBuffer: Boolean,
        lossPerMille: Int = 10,
        tailPercent: Int = 8,
        seed: Long = 7,
    ): SimResult {
        var rng = seed.toULong()
        fun rand(n: Int): Int {
            rng = rng * 6_364_136_223_846_793_005uL + 1_442_695_040_888_963_407uL
            return ((rng shr 33) % maxOf(1, n).toULong()).toInt()
        }
        val samples = frameMs * 16
        val arrivals = ArrayList<Pair<Int, Int>>()
        for (i in 0 until seconds * 1000 / frameMs) {
            if (lossPerMille > 0 && rand(1000) < lossPerMille) continue
            val tail = if (tailPercent > 0 && rand(100) < tailPercent) 300 + rand(401) else 0
            arrivals.add(Pair(i * frameMs + 500 + rand(jitterMs + 1) + tail, i + 1))
        }
        arrivals.sortWith(compareBy({ it.first }))
        var ooo = 0
        var maxSeen = 0
        for (a in arrivals) {
            if (a.second < maxSeen) ooo += 1
            maxSeen = maxOf(maxSeen, a.second)
        }
        val p = planner(frameSamples = samples)
        var oldNext: Int? = null
        val oldPending = HashSet<Int>()
        var oldTimerAt: Int? = null
        var oldTarget = 5_120
        var oldGaps = 0
        var oldPlayed = 0
        var oldUnderruns = 0

        var ahead = 0
        var playing = false
        var started = false
        var silentMs = 0
        var idx = 0
        var t = 0
        val endMs = seconds * 1000 + 500
        while (t < endMs) {
            while (idx < arrivals.size && arrivals[idx].first <= t) {
                val seq = arrivals[idx].second
                idx += 1
                if (oldBuffer) {
                    if (oldNext == null) oldNext = seq
                    if (seq >= oldNext!!) oldPending.add(seq)
                } else {
                    p.push(seq, 0, samples, t.toLong())
                }
            }
            if (oldBuffer) {
                var n = oldNext
                if (n != null) {
                    fun drain() {
                        while (oldPending.remove(n!!)) {
                            ahead += samples
                            oldPlayed += 1
                            n = n!! + 1
                        }
                    }
                    drain()
                    if (oldPending.isEmpty()) oldTimerAt = null
                    if (oldPending.isNotEmpty() && oldTimerAt == null) oldTimerAt = t + oldTarget / 16
                    val at = oldTimerAt
                    val minKey = oldPending.minOrNull()
                    if (at != null && t >= at && minKey != null) {
                        oldGaps += minKey - n!!
                        ahead += minOf(minKey - n!!, 2) * samples
                        n = minKey
                        oldTimerAt = null
                        drain()
                        if (oldPending.isNotEmpty()) oldTimerAt = t + oldTarget / 16
                    }
                    oldNext = n
                }
            } else {
                for (a in p.pump(ahead, playing, t.toLong())) {
                    when (a) {
                        is BeamioVoicePlayoutPlanner.Action.Play -> ahead += a.samples
                        is BeamioVoicePlayoutPlanner.Action.Conceal -> ahead += a.samples
                        is BeamioVoicePlayoutPlanner.Action.Stretch -> ahead += a.samples
                        is BeamioVoicePlayoutPlanner.Action.Skip -> {}
                    }
                }
            }
            val target = if (oldBuffer) oldTarget else p.targetSamples
            if (!playing && ahead >= target) {
                playing = true
                started = true
            }
            if (playing) {
                ahead -= 160
                if (ahead <= 0) {
                    ahead = 0
                    playing = false
                    if (idx < arrivals.size) {
                        if (oldBuffer) {
                            oldUnderruns += 1
                            oldTarget = minOf(12_800, oldTarget + 2_560)
                        } else {
                            p.noteUnderrun(t.toLong())
                        }
                    }
                }
            } else if (started && idx < arrivals.size) {
                silentMs += 10
            }
            t += 10
        }
        return if (oldBuffer) {
            SimResult(oldGaps.toDouble() / maxOf(1, oldPlayed), oldUnderruns, ooo.toDouble() / arrivals.size, silentMs)
        } else {
            SimResult(
                p.counters.concealed.toDouble() / maxOf(1, p.counters.played),
                p.counters.underruns,
                ooo.toDouble() / arrivals.size,
                silentMs,
            )
        }
    }
}
