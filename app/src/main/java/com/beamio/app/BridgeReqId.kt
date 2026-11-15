package com.beamio.app

/**
 * Spec §25.52AW.1: a valid bridge reqId is an integer 0..2^53-1, or a string of at most 64 bytes of printable ASCII
 * (0x20-0x7E). Anything else (missing, negative, too large, non-integer number, other types) is invalid: the caller answers
 * `bad_request` with a null reqId, or, where a reply carries a reqId, sends null.
 */
object BridgeReqId {
    private const val MAX_INT: Long = 9_007_199_254_740_991L // 2^53 - 1

    /** The reqId itself when valid, else null. */
    fun valid(raw: Any?): Any? = when (raw) {
        is Int -> if (raw >= 0) raw else null
        is Long -> if (raw in 0..MAX_INT) raw else null
        is String -> if (raw.isNotEmpty() && raw.length <= 64 && raw.all { it.code in 0x20..0x7E }) raw else null
        else -> null // Double, Boolean, JSONObject, JSONArray, JSONObject.NULL, null
    }

    /** The valid `reqId` of a JSON object text, else null (also null when the text is not a JSON object). */
    fun fromJsonText(text: String): Any? =
        runCatching { org.json.JSONObject(text.trim()) }.getOrNull()?.let { valid(it.opt("reqId")) }
}
