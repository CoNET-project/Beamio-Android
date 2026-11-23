package com.beamio.app

import org.json.JSONArray
import org.json.JSONObject

/**
 * queryIncomingCallOutcome (spec r3gi §25.52EF, §25.52EH.1, §25.52EE.1, §25.52DU.1–DU.2).
 *
 * args `{calls:[{callId, sessionId, createdAt}]}`: callId and sessionId are strings (an empty string is a valid value),
 * createdAt is an integer (milliseconds). Any shape error (no calls array, more than [MAX_BATCH] entries, an entry that is
 * not an object, a missing or wrongly typed field) rejects the whole batch with `bad_args`, exactly once: no events, no
 * truncation, no partial processing.
 *
 * Otherwise one event per entry, in request order, with exactly these keys:
 * `{action:"incomingCallOutcome", callId, sessionId, rang}`. `rang` is always present: true if and only if neither id is
 * empty, the shell holds a ring record for exactly this (callId, sessionId) pair, and nowMs − createdAt ≤ [RETENTION_MS].
 * The ack comes before the events.
 */
object IncomingCallOutcome {
    const val ACTION = "queryIncomingCallOutcome"
    const val EVENT = "incomingCallOutcome"
    const val MAX_BATCH = 50
    const val RETENTION_MS = 3L * 24 * 60 * 60_000L

    sealed class Result {
        object BadArgs : Result()
        class Events(val events: List<JSONObject>) : Result()
    }

    /** Storage key of one ring record (the pair, not each id). */
    fun pairKey(callId: String, sessionId: String): String = "pair:" + callId + "\u001f" + sessionId

    /**
     * Keys the shell writes when a call rings (BeamioTelecomService.noteIncomingRang): the older per-id keys (trimmed, as
     * before) plus the pair key. The pair key uses callId and sessionId exactly as received, without trim, because the
     * query compares them exactly (§25.52EF.4); it is written only when both are non-empty (§25.52EH.1).
     */
    fun recordKeys(ids: List<String>, callId: String, sessionId: String): List<String> {
        val pair = if (callId.isNotEmpty() && sessionId.isNotEmpty()) listOf(pairKey(callId, sessionId)) else emptyList()
        return (ids.map { it.trim() }.filter { it.isNotEmpty() } + pair).distinct()
    }

    /** The query side (BeamioTelecomService.hasRangPair): exact pair, empty ids never match. */
    fun hasPair(contains: (String) -> Boolean, callId: String, sessionId: String): Boolean =
        callId.isNotEmpty() && sessionId.isNotEmpty() && contains(pairKey(callId, sessionId))

    fun evaluate(args: JSONObject, nowMs: Long, hasPair: (String, String) -> Boolean): Result {
        val calls = args.opt("calls") as? JSONArray ?: return Result.BadArgs
        if (calls.length() > MAX_BATCH) return Result.BadArgs
        val entries = ArrayList<Triple<String, String, Long>>(calls.length())
        for (i in 0 until calls.length()) {
            val o = calls.opt(i) as? JSONObject ?: return Result.BadArgs
            val callId = o.opt("callId") as? String ?: return Result.BadArgs
            val sessionId = o.opt("sessionId") as? String ?: return Result.BadArgs
            val createdAt = when (val v = o.opt("createdAt")) {
                is Int -> v.toLong()
                is Long -> v
                else -> return Result.BadArgs // missing, string, fraction, boolean, null
            }
            entries += Triple(callId, sessionId, createdAt)
        }
        return Result.Events(entries.map { (callId, sessionId, createdAt) ->
            val rang = callId.isNotEmpty() && sessionId.isNotEmpty() && hasPair(callId, sessionId) &&
                nowMs - createdAt <= RETENTION_MS
            JSONObject().put("action", EVENT).put("callId", callId).put("sessionId", sessionId).put("rang", rang)
        })
    }

    /** The BeamioShell answer: the ack (sent first) and the events (sent after it on cashtreesandroid). */
    fun respond(reqId: Any, args: JSONObject, nowMs: Long, hasPair: (String, String) -> Boolean): Pair<JSONObject, List<JSONObject>> {
        val ack = BeamioShellChannel.ack(ACTION, reqId)
        return when (val r = evaluate(args, nowMs, hasPair)) {
            is Result.BadArgs -> ack.put("ok", false).put("error", "bad_args") to emptyList()
            is Result.Events -> ack.put("ok", true) to r.events
        }
    }

}
