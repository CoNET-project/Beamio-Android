package com.beamio.app

import java.util.concurrent.ConcurrentHashMap

/**
 * One incoming registration per call: callId -> sessionId (v48 §54.4). A call is the same
 * registration only when callId and sessionId both match; the same callId with another
 * sessionId is a different registration and is never matched.
 */
class IncomingPairRegistry {
    private val pairs = ConcurrentHashMap<String, String>()

    fun record(callId: String, sessionId: String) {
        val c = callId.trim()
        val s = sessionId.trim()
        if (c.isNotEmpty() && s.isNotEmpty()) pairs[c] = s
    }

    /** True only for this exact registration (callId and sessionId together). */
    fun matches(callId: String, sessionId: String): Boolean {
        val c = callId.trim()
        val s = sessionId.trim()
        return c.isNotEmpty() && s.isNotEmpty() && pairs[c] == s
    }

    fun remove(callId: String) {
        pairs.remove(callId.trim())
    }
}
