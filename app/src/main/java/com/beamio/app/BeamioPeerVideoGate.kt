package com.beamio.app

/**
 * Peer camera on/off for the in-call screen. Same rules as the PWA
 * (`voicePeerVideoGate.ts`) and iOS (`BeamioPeerVideoGate.swift`).
 *
 * `voice_video_disable_v1` / `voice_video_enable_v1` carry the peer's send time
 * (`timestamp`, peer clock); video frames carry their capture (or send) time on
 * the same clock. A frame from at or before the "off" time is a late frame and
 * must never bring the picture back.
 * - A control older than the last one applied is stale (a repeated "off" that
 *   arrives after the camera came back on) and is ignored.
 * - A frame from after the "off" time means the camera is on again, even if the
 *   "on" control was lost.
 * - Frames without a time are shown only while the camera is on.
 */
class BeamioPeerVideoGate {
    /** Peer time of the newest enable/disable control applied (0 = none). */
    var stateTs = 0L
        private set
    /** Peer time of the newest "camera off" (0 = never off). */
    var offAt = 0L
        private set
    /** Camera currently off. */
    var off = false
        private set

    /** Returns false when the control is stale, so the caller leaves the screen as it is. */
    @Synchronized
    fun apply(enable: Boolean, timestamp: Long): Boolean {
        val ts = timestamp.coerceAtLeast(0L)
        if (ts > 0L && ts < stateTs) return false
        if (ts > 0L) stateTs = ts
        if (enable) {
            off = false
        } else {
            off = true
            if (ts > offAt) offAt = ts
        }
        return true
    }

    /** Late frame: from at or before the last "off", or without a time while off. */
    @Synchronized
    fun isStale(frameMs: Long): Boolean = if (frameMs > 0L) frameMs <= offAt else off

    /** Should this arriving frame be shown? A frame from after the last "off" also marks the camera as on again. */
    @Synchronized
    fun accept(frameMs: Long): Boolean {
        if (isStale(frameMs)) return false
        if (frameMs > 0L && off) off = false
        return true
    }

    @Synchronized
    fun reset() {
        stateTs = 0L
        offAt = 0L
        off = false
    }

    companion object {
        /** When to send `voice_video_disable_v1` again (ms after the camera went off). */
        val OFF_REPEAT_MS = longArrayOf(0L, 1_500L, 4_000L)
    }
}
