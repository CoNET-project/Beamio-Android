package com.beamio.app

import org.json.JSONArray

/**
 * Callee admission checks for a verified-decrypted voice_call_offer_v1 (spec chat interface spec 29 v33 §37,
 * r3ac R3AC-2, r3ad R3AD, r3ae R3AE-2, r3af R3AF). Pure functions and an in-memory dedupe
 * table; persistence and the decrypt step come later. Order (R3AE-2): R/from check, then
 * validUntil and skew, then dedupe and per-R quota. Nothing is recorded on a refusal.
 */
object VoiceOfferAdmission {
    const val SKEW_MS = 300_000L
    const val RETENTION_MS = 1_200_000L
    const val PER_CALLER_CAP = 50
    const val GLOBAL_CAP = 1000

    enum class Reject { FROM_MISMATCH, FROM_MISSING, EXPIRED, SKEW, PER_CALLER_FULL, GLOBAL_FULL, BAD_KEY, DUPLICATE, STORE_UNAVAILABLE }

    sealed class Verdict {
        object Admit : Verdict()
        data class Refuse(val reason: Reject) : Verdict()
    }

    /** Step 1 (R3AA-1): recovered signer R must equal the offer `from` (lower-case compare). */
    fun checkFrom(recoveredR: String?, from: String?): Reject? {
        val r = recoveredR?.trim()?.lowercase()
        val f = from?.trim()?.lowercase()
        if (f.isNullOrEmpty()) return Reject.FROM_MISSING
        if (r.isNullOrEmpty() || r != f) return Reject.FROM_MISMATCH
        return null
    }

    /** Step 3: now must not pass validUntil, and createdAt must lie within the skew of now. */
    fun checkWindow(nowMs: Long, createdAtMs: Long, validUntilMs: Long): Reject? {
        if (nowMs > validUntilMs) return Reject.EXPIRED
        // 300 s bounds only a future issuedAt (createdAt - now); an older offer inside its window is fine.
        if (createdAtMs - nowMs > SKEW_MS) return Reject.SKEW
        return null
    }

    /** Dedupe key: JSON array [callId, sessionId] (same bytes on all callee clients). */
    fun dedupeKey(callId: String, sessionId: String): String = JSONArray(listOf(callId, sessionId)).toString()

    /** In-memory dedupe table with a per-caller quota and a global cap. */
    class DedupeTable(private val nowMs: () -> Long) {
        private data class Entry(val callerR: String, val recordedAtMs: Long, val validUntilMs: Long)
        private val entries = LinkedHashMap<String, Entry>()

        @Synchronized
        fun size(): Int = entries.size

        /** Step 4 (R3AE-2): quota and dedupe. Does not record: call [record] after admission. */
        @Synchronized
        fun admit(key: String, callerR: String): Reject? {
            purgeExpired()
            if (entries.containsKey(key)) return null // duplicate of a recorded offer; caller decides
            val r = callerR.lowercase()
            val mine = entries.values.count { it.callerR == r }
            if (mine >= PER_CALLER_CAP) return Reject.PER_CALLER_FULL
            if (entries.size >= GLOBAL_CAP) return Reject.GLOBAL_FULL
            return null
        }

        data class Snap(val key: String, val callerR: String, val recordedAtMs: Long, val validUntilMs: Long)

        /** Current records (for persistence). */
        @Synchronized
        fun snapshot(): List<Snap> = entries.map { (k, e) -> Snap(k, e.callerR, e.recordedAtMs, e.validUntilMs) }

        /** Restore a persisted record with its original time (used on load only). */
        @Synchronized
        fun restore(key: String, callerR: String, recordedAtMs: Long, validUntilMs: Long) {
            entries[key] = Entry(callerR.lowercase(), recordedAtMs, validUntilMs)
            purgeExpired()
        }

        /** R3AF-1: written after the verdict is admit and before the ring. */
        @Synchronized
        fun record(key: String, callerR: String, validUntilMs: Long) {
            purgeExpired()
            entries[key] = Entry(callerR.lowercase(), nowMs(), validUntilMs)
        }

        @Synchronized
        fun isRecorded(key: String): Boolean {
            purgeExpired()
            return entries.containsKey(key)
        }

        private fun purgeExpired() {
            val now = nowMs()
            val it = entries.entries.iterator()
            while (it.hasNext()) {
                val e = it.next().value
                if (now - e.recordedAtMs > RETENTION_MS) it.remove()
            }
        }
    }

    /** Full admission for one verified offer, in the R3AE-2 order. */
    fun admit(
        table: DedupeTable,
        nowMs: Long,
        recoveredR: String?,
        from: String?,
        callId: String,
        sessionId: String,
        createdAtMs: Long,
        validUntilMs: Long,
    ): Verdict {
        checkFrom(recoveredR, from)?.let { return Verdict.Refuse(it) }
        checkWindow(nowMs, createdAtMs, validUntilMs)?.let { return Verdict.Refuse(it) }
        if (callId.isBlank() || sessionId.isBlank()) return Verdict.Refuse(Reject.BAD_KEY)
        val key = dedupeKey(callId, sessionId)
        if (table.isRecorded(key)) return Verdict.Refuse(Reject.DUPLICATE)
        table.admit(key, recoveredR!!)?.let { return Verdict.Refuse(it) }
        return Verdict.Admit
    }
}
