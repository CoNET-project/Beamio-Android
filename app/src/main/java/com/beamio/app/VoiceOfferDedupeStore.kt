package com.beamio.app

import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * File-backed dedupe table for callee offers (spec chat interface spec 29 v33 §37; r3ae R3AE-1; r3af).
 * Records survive restart: entries are written as JSON after each record, via temp file and
 * rename, and expired entries are dropped on load and on every use. Limits and key follow
 * [VoiceOfferAdmission]: key JSON.stringify([callId, sessionId]), 1200 s retention, per-caller
 * quota 50, global cap 1000 that evicts expired records only.
 */
class VoiceOfferDedupeStore(private val file: File, private val nowMs: () -> Long) {
    private val table = VoiceOfferAdmission.DedupeTable(nowMs)

    init {
        load()
    }

    /** Dedupe quota check (the caller admits first). */
    fun admit(key: String, callerR: String): VoiceOfferAdmission.Reject? = table.admit(key, callerR)

    /** Record an admitted offer (before the ring). Persists before returning. */
    fun record(key: String, callerR: String, validUntilMs: Long): Boolean {
        table.record(key, callerR, validUntilMs)
        return save()
    }

    fun isRecorded(key: String): Boolean = table.isRecorded(key)

    /**
     * Full admission for one verified offer (R3AE-2): R/from, window, duplicate, quota; then the
     * record is written (R3AF) before the ring. A failed write refuses (failure closed).
     */
    @Synchronized
    fun admitOffer(
        recoveredR: String?,
        from: String?,
        callId: String,
        sessionId: String,
        createdAtMs: Long,
        validUntilMs: Long,
    ): VoiceOfferAdmission.Verdict {
        val v = VoiceOfferAdmission.admit(table, nowMs(), recoveredR, from, callId, sessionId, createdAtMs, validUntilMs)
        if (v !is VoiceOfferAdmission.Verdict.Admit) return v
        val key = VoiceOfferAdmission.dedupeKey(callId, sessionId)
        if (!record(key, recoveredR!!, validUntilMs)) {
            return VoiceOfferAdmission.Verdict.Refuse(VoiceOfferAdmission.Reject.STORE_UNAVAILABLE)
        }
        return VoiceOfferAdmission.Verdict.Admit
    }

    fun size(): Int = table.size()

    private fun load() {
        if (!file.isFile) return
        val arr = runCatching { JSONArray(file.readText(Charsets.UTF_8)) }.getOrNull() ?: return
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            val key = o.optString("key")
            val r = o.optString("callerR")
            val recorded = o.optLong("recordedAtMs", -1L)
            val valid = o.optLong("validUntilMs", -1L)
            if (key.isEmpty() || r.isEmpty() || recorded < 0 || valid < 0) continue
            table.restore(key, r, recorded, valid)
        }
    }

    private fun save(): Boolean {
        val arr = JSONArray()
        for (e in table.snapshot()) {
            arr.put(JSONObject()
                .put("key", e.key)
                .put("callerR", e.callerR)
                .put("recordedAtMs", e.recordedAtMs)
                .put("validUntilMs", e.validUntilMs))
        }
        return runCatching {
            file.parentFile?.mkdirs()
            val tmp = File(file.parentFile, file.name + ".tmp")
            tmp.writeText(arr.toString(), Charsets.UTF_8)
            if (!tmp.renameTo(file)) {
                file.writeText(arr.toString(), Charsets.UTF_8)
                tmp.delete()
            }
            true
        }.getOrDefault(false)
    }
}
