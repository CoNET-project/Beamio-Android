package com.beamio.app

import org.json.JSONObject

/**
 * Same-launch request correlation for the shell's bridge logs (S25 182 follow-up, 2026-11-20).
 *
 * Each line carries the command type, the valid reqId, the phase and elapsed milliseconds, plus the ack's ok flag and an
 * error code when there is one. It never carries a payload, a phrase, a key, an address or a chat body. A reply that arrives
 * more than [PAGE_TIMEOUT_MS] after the shell received the command is marked late (the page's own hello wait is 5 s).
 */
object ReqCorrelation {
    const val TAG = "BeamioReqCorr"

    /** The page's hello wait (PWA nativeConetChatTransport, 5 s). The shell only measures; the page decides. */
    const val PAGE_TIMEOUT_MS = 5_000L

    private val SAFE_CODE = Regex("^[A-Za-z0-9_.:-]{1,40}$")
    private val SAFE_CMD = Regex("^[A-Za-z0-9_.:-]{1,64}$")
    private val SAFE_RID = Regex("^[0-9]{1,16}$|^[A-Za-z0-9_.:-]{1,40}$")

    /** The reqId as logged: a number or a short safe token only; anything else is `invalid`. */
    fun safeRid(rid: Any): String = rid.toString().takeIf { SAFE_RID.matches(it) } ?: "invalid"

    /** The command name as logged, or null when it is not a safe token (such a command is not logged). */
    fun safeCmd(type: String): String? = type.takeIf { SAFE_CMD.matches(it) }

    /** The command type and valid reqId of a JSON command, or null when either is missing or the text is not a JSON object. */
    fun head(json: String?): Pair<String, Any>? {
        if (json == null) return null
        val o = runCatching { JSONObject(json) }.getOrNull() ?: return null
        val type = safeCmd(o.optString("type")) ?: return null
        val rid = BridgeReqId.valid(o.opt("reqId")) ?: return null
        return type to rid
    }

    /** `phase=enqueued` line, written when the shell accepts the command. */
    fun enqueued(channel: String, type: String, rid: Any): String =
        "channel=$channel phase=enqueued cmd=$type reqId=${safeRid(rid)}"

    /** `phase=started` line, written when the command leaves the queue; [queueMs] is the wait before it started. */
    fun started(channel: String, type: String, rid: Any, queueMs: Long): String =
        "channel=$channel phase=started cmd=$type reqId=${safeRid(rid)} queueMs=$queueMs"

    /**
     * `phase=reply` line for the first ack with this reqId. [payload] is read for `ok` and `error` only; an `event` wrapper is
     * unwrapped the same way as the SDK answer. Returns null when the payload is not an ack.
     */
    fun reply(channel: String, type: String, rid: Any, elapsedMs: Long, payload: JSONObject): String? {
        val ev = payload.optJSONObject("event") ?: payload
        if (ev.optString("type") != "ack") return null
        val ok = ev.optBoolean("ok", false)
        val err = ev.optString("error", "").takeIf { SAFE_CODE.matches(it) } ?: "none"
        val late = if (elapsedMs > PAGE_TIMEOUT_MS) " late=true" else ""
        return "channel=$channel phase=reply cmd=$type reqId=${safeRid(rid)} ms=$elapsedMs ok=$ok error=$err$late"
    }

    /** True when the payload (or its `event` wrapper) is an ack. */
    fun isAck(payload: JSONObject): Boolean = (payload.optJSONObject("event") ?: payload).optString("type") == "ack"

    /** Parses an outgoing reply text for [reply]; null when it is not a JSON object. */
    fun replyText(channel: String, type: String, rid: Any, elapsedMs: Long, text: String?): String? {
        if (text == null) return null
        val o = runCatching { JSONObject(text) }.getOrNull() ?: return null
        return reply(channel, type, rid, elapsedMs, o)
    }
}
