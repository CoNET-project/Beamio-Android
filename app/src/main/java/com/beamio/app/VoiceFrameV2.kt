package com.beamio.app

/**
 * Control frames inside an established AES channel (v72 §79, stage 1: pure functions).
 * canonical text (UTF-8, byte for byte): "CoNET voice_frame_v2\ntype:..\ncallId:..\nsessionId:..\nfrom:<lower>\nat:..\nseq:.."
 * Receive rules (79.3, 79.5): EIP-191 recovery == from; seq strictly greater than the last accepted seq in the
 * same direction; at inside the window (window value to be set from T_sys measurement, passed in, not invented
 * here). Any failure drops the frame silently (52.1). A new channel starts a new receiver (seq from 1, no reuse).
 */
object VoiceFrameV2 {
    const val HEADER = "CoNET voice_frame_v2"

    data class Frame(
        val type: String,
        val callId: String,
        val sessionId: String,
        val from: String,
        val atMs: Long,
        val seq: Long,
        val sig: String,
    )

    enum class Reject { BAD_SIG, FROM_MISSING, SEQ_NOT_ADVANCING, AT_OUT_OF_WINDOW, NOT_ALLOWED_TYPE }

    private val allowedTypes = setOf(
        "voice_end_v1", "voice_call_reject_v1", "voice_call_timeout_v1", "voice_call_ringing_v1", "voice_call_accept_v1",
    )

    fun canonicalText(type: String, callId: String, sessionId: String, from: String, atMs: Long, seq: Long): String =
        listOf(
            HEADER,
            "type:$type",
            "callId:$callId",
            "sessionId:$sessionId",
            "from:${from.trim().lowercase()}",
            "at:$atMs",
            "seq:$seq",
        ).joinToString("\n")

    /** Verify one frame against the receiver state. Returns null when accepted. */
    fun check(frame: Frame, lastAcceptedSeq: Long, nowMs: Long, windowMs: Long): Reject? {
        if (frame.type !in allowedTypes) return Reject.NOT_ALLOWED_TYPE
        if (frame.from.isBlank()) return Reject.FROM_MISSING
        if (frame.seq <= lastAcceptedSeq) return Reject.SEQ_NOT_ADVANCING
        if (kotlin.math.abs(nowMs - frame.atMs) > windowMs) return Reject.AT_OUT_OF_WINDOW
        val text = canonicalText(frame.type, frame.callId, frame.sessionId, frame.from, frame.atMs, frame.seq)
        val recovered = BeamioNativeEthSigner.recoverAddress(text, frame.sig)?.lowercase() ?: return Reject.BAD_SIG
        if (recovered != frame.from.trim().lowercase()) return Reject.BAD_SIG
        return null
    }

    /** Per-direction receiver for one channel: accepts a frame only if check passes, then advances seq. */
    class Receiver(private val windowMs: Long, private val nowMs: () -> Long) {
        private var lastSeq: Long = 0L

        @Synchronized
        fun accept(frame: Frame): Reject? {
            val r = check(frame, lastSeq, nowMs(), windowMs)
            if (r == null) lastSeq = frame.seq
            return r
        }

        @Synchronized
        fun lastAcceptedSeq(): Long = lastSeq
    }
}
