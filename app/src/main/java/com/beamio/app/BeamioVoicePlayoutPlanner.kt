package com.beamio.app

/**
 * Downlink jitter buffer driven by the playout clock (same rules as iOS
 * `BeamioVoicePlayoutPlanner.swift`).
 *
 * Frames reach us through a different random entry each, so 25–35 % arrive out
 * of order and up to ~0.3 s apart. The old buffer waited for a missing frame as
 * long as the whole playout depth, which drained the track, went silent and
 * rebuffered. Here a missing frame is waited for only while the track still has
 * audio queued: when about one frame is left, its slot is concealed and playout
 * moves on. A frame that arrives after its slot was concealed raises the depth
 * (by inserting a short stretch) so the next one has more time.
 *
 * Sizes are in 16 kHz samples. Frames carry their own length (the shells send
 * 160 ms, the PWA 80 ms); control placeholders are zero-sample items that only
 * move the sequence on. Not thread-safe: the caller holds its own lock.
 */
class BeamioVoicePlayoutPlanner<T>(val config: Config = Config()) {
    data class Config(
        val minTargetSamples: Int = 5_120, // 320 ms
        val maxTargetSamples: Int = 16_000, // 1 000 ms
        val underrunStepSamples: Int = 2_560, // 160 ms
        val lateStepSamples: Int = 1_280, // 80 ms
        val decayStepSamples: Int = 1_280, // 80 ms
        val decayIntervalMs: Long = 10_000L,
        val defaultFrameSamples: Int = 2_560, // 160 ms
        val maxPending: Int = 48,
    )

    sealed class Action<out T> {
        /** Play this frame now (audio, or a zero-sample control item). */
        data class Play<T>(val seq: Int, val payload: T, val samples: Int) : Action<T>()
        /** The frame for [seq] is not here and its turn has come: fill [samples]. */
        data class Conceal(val seq: Int, val samples: Int) : Action<Nothing>()
        /** Insert [samples] of silence without moving on (grows the depth). */
        data class Stretch(val samples: Int) : Action<Nothing>()
        /** Frames [from] until [to] were given up without filling. */
        data class Skip(val from: Int, val to: Int) : Action<Nothing>()
    }

    enum class PushResult { ACCEPTED, DUPLICATE, STALE, LATE }

    data class Counters(
        var played: Int = 0,
        var concealed: Int = 0,
        var late: Int = 0,
        var stretched: Int = 0,
        var skipped: Int = 0,
        var underruns: Int = 0,
    )

    private class Item<T>(val payload: T, val samples: Int)

    var targetSamples: Int = config.minTargetSamples
        private set
    val counters = Counters()
    var nextSeq: Int? = null
        private set
    private val pending = HashMap<Int, Item<T>>()
    private var pendingSamples = 0
    private val concealedSeqs = HashSet<Int>()
    private var stretchDebt = 0
    private var lastFrameSamples = config.defaultFrameSamples
    private var lastGrowthMs = 0L
    private var lastDecayMs = 0L

    val pendingCount: Int get() = pending.size

    /** Store one received frame. Call [pump] afterwards. */
    fun push(seq: Int, payload: T, samples: Int, nowMs: Long): PushResult {
        if (nextSeq == null) nextSeq = seq
        val next = nextSeq ?: return PushResult.STALE
        if (seq < next) {
            if (concealedSeqs.remove(seq)) {
                counters.late += 1
                grow(config.lateStepSamples, nowMs)
                return PushResult.LATE
            }
            return PushResult.STALE
        }
        if (pending.containsKey(seq)) return PushResult.DUPLICATE
        val n = maxOf(0, samples)
        pending[seq] = Item(payload, n)
        pendingSamples += n
        return PushResult.ACCEPTED
    }

    /**
     * Decide what to hand the player. [aheadSamples] is audio already queued in
     * the player and not yet heard; [playing] is false while it is still
     * prebuffering (at start or after it ran dry).
     */
    fun pump(aheadSamples: Int, playing: Boolean, nowMs: Long): List<Action<T>> {
        decayIfStable(nowMs)
        var next = nextSeq ?: return emptyList()
        var ahead = maxOf(0, aheadSamples)
        val out = ArrayList<Action<T>>()
        if (pending.size > config.maxPending) {
            val first = pending.keys.minOrNull()
            if (first != null && first > next) {
                out.add(Action.Skip(next, first))
                counters.skipped += first - next
                next = first
            }
        }
        while (true) {
            val item = pending.remove(next)
            if (item != null) {
                pendingSamples -= item.samples
                out.add(Action.Play(next, item.payload, item.samples))
                counters.played += 1
                if (item.samples > 0) lastFrameSamples = item.samples
                ahead += item.samples
                next += 1
                continue
            }
            val later = pending.keys.filter { it > next }.minOrNull() ?: break
            if (!playing) {
                // Not started yet: a hole at the front would hold the prebuffer
                // forever. Give it up once enough later audio is waiting.
                if (pendingSamples < targetSamples) break
                out.add(Action.Skip(next, later))
                counters.skipped += later - next
                next = later
                continue
            }
            // Still audio in the player: there is time to wait for it.
            if (ahead > lastFrameSamples) break
            if (stretchDebt > 0) {
                val s = minOf(stretchDebt, lastFrameSamples)
                stretchDebt -= s
                counters.stretched += 1
                out.add(Action.Stretch(s))
                ahead += s
                continue
            }
            out.add(Action.Conceal(next, lastFrameSamples))
            concealedSeqs.add(next)
            counters.concealed += 1
            ahead += lastFrameSamples
            next += 1
        }
        nextSeq = next
        val floor = next - 64
        concealedSeqs.removeAll { it < floor }
        return out
    }

    /** The player ran dry (nothing left at all). Rebuffer deeper next time. */
    fun noteUnderrun(nowMs: Long) {
        counters.underruns += 1
        grow(config.underrunStepSamples, nowMs)
        // The rebuffer itself adds the depth; no stretch needed.
        stretchDebt = 0
    }

    private fun grow(step: Int, nowMs: Long) {
        val next = minOf(config.maxTargetSamples, targetSamples + step)
        stretchDebt += next - targetSamples
        targetSamples = next
        lastGrowthMs = nowMs
        lastDecayMs = nowMs
    }

    private fun decayIfStable(nowMs: Long) {
        if (targetSamples <= config.minTargetSamples) return
        if (nowMs - lastGrowthMs < config.decayIntervalMs || nowMs - lastDecayMs < config.decayIntervalMs) return
        lastDecayMs = nowMs
        targetSamples = maxOf(config.minTargetSamples, targetSamples - config.decayStepSamples)
        stretchDebt = minOf(stretchDebt, targetSamples)
    }
}
