package com.beamio.app

/**
 * Input rules for the local dismiss of an unanswered incoming call (v48 §54.4–5; chat interface spec 25 callId).
 * callId is 8–128 characters of [A-Za-z0-9_-]; sessionId must be present. Anything else is
 * bad_request and acts on no call.
 */
object VoiceDismissInput {
    private val callIdRule = Regex("^[A-Za-z0-9_-]{8,128}$")

    fun validCallId(callId: String): Boolean = callIdRule.matches(callId)

    fun validSessionId(sessionId: String): Boolean = sessionId.isNotEmpty() && sessionId.length <= 256

    fun valid(callId: String, sessionId: String): Boolean = validCallId(callId) && validSessionId(sessionId)
}
