package com.beamio.app

import org.json.JSONObject

/** The nativeCallHangup event body (v66 §73): event channel only, not a command. */
object NativeCallHangupEvent {
    const val TYPE = "nativeCallHangup"
    const val REASON = "local_hangup"

    fun build(callId: String, sessionId: String, atMs: Long): JSONObject = JSONObject()
        .put("type", TYPE)
        .put("callId", callId)
        .put("sessionId", sessionId)
        .put("reason", REASON)
        .put("at", atMs)
}
