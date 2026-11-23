package com.beamio.app

import org.json.JSONObject

/**
 * Pre-answer UI-unlock timers (v97 §104; chat interface spec 15 §一 and 17). Native-owned.
 *
 * T_LOAD_MS and T_IN_MS are PROVISIONAL (set 2026-11-21):
 * 暂定，待真机实测替换. Their sum (55 s) stays under the 60 s ring constant.
 * remainingMs is a read-only millisecond count of the current phase; it never changes native timing.
 * PWA only reads it; it never generates it.
 */
object IncomingUnlockTimer {
    /** 暂定，待真机实测替换。 */
    const val T_LOAD_MS = 10_000L
    /** 暂定，待真机实测替换。 */
    const val T_IN_MS = 45_000L

    enum class Phase(val wire: String, val totalMs: Long) {
        /** T_load: the entry is not shown yet. */
        LOAD("load", T_LOAD_MS),
        /** T_in: the entry is shown and interactive. */
        INPUT("input", T_IN_MS),
    }

    /** Remaining milliseconds of [phase] after [elapsedMs]; never negative. */
    fun remainingMs(phase: Phase, elapsedMs: Long): Long = (phase.totalMs - elapsedMs).coerceAtLeast(0L)

    /** True once the phase has used its whole budget. A timeout ends the call; the budget is never extended. */
    fun expired(phase: Phase, elapsedMs: Long): Boolean = elapsedMs >= phase.totalMs

    /** Phase after the PWA reports the entry shown (incomingCallUnlockShown). */
    fun afterShown(from: Phase): Phase = if (from == Phase.LOAD) Phase.INPUT else from

    /**
     * Payload shared by incomingCallUnlockRequest and the incomingCallUnlock start parameters.
     * Null when the remaining time is not positive (the PWA refuses that launch, fail closed).
     */
    private val CALL_ID = Regex("^[A-Za-z0-9_-]{8,128}$")
    private val EOA = Regex("^0x[0-9a-f]{40}$")

    fun payload(callId: String, eoa: String, phase: Phase, remaining: Long): JSONObject? {
        // v114 §133.1: callId 8–128 [A-Za-z0-9_-]; eoa lower-case 0x address; remainingMs >= 1; phase load|input.
        if (!CALL_ID.matches(callId) || !EOA.matches(eoa) || remaining <= 0L) return null
        return JSONObject()
            .put("callId", callId)
            .put("eoa", eoa)
            .put("remainingMs", remaining)
            .put("phase", phase.wire)
    }
}
