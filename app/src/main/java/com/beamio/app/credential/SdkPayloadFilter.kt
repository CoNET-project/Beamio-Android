package com.beamio.app.credential

import com.beamio.app.BridgeReqId
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap

/**
 * Every Chat SDK payload (`{action, event}`) on its way to the page, whichever command's deliver the SDK uses (it keeps
 * the latest one for later events). Spec r3np §25.52Y.38:
 *  - an ack whose reqId belongs to a pending walletCredential passes only in the shape of item 3 (e) (one credential,
 *    never both; W-N3), otherwise it becomes `key_over_bridge_refused` with no field of it;
 *  - any other payload carrying `mnemonic` / `eoaPrivateKey` is refused (item 14, W-N2): an ack with a valid reqId becomes
 *    `key_over_bridge_refused`, anything else is dropped;
 *  - every other payload passes unchanged (no allowlist, no rewriting; e.g. walletStatus notReadyReason, §25.52Y.39).
 * [Result.logLine] holds names, codes and durations only.
 */
class SdkPayloadFilter(private val clock: () -> Long) {
    private class Pending(val command: String, val startedMs: Long)
    private val pending = ConcurrentHashMap<String, Pending>()

    class Result(val payload: JSONObject?, val credentialReply: Boolean, val logLine: String?)

    /** [command] is walletCredential or walletEoaAddress (WalletCredentialGate.GATED_COMMANDS). */
    fun expectCredentialReply(reqId: Any, command: String = WalletCredentialGate.COMMAND) { pending[key(reqId)] = Pending(command, clock()) }
    fun cancel(reqId: Any) { pending.remove(key(reqId)) }

    fun filter(payload: JSONObject): Result {
        val e = payload.optJSONObject("event")
        val rid = e?.let { BridgeReqId.valid(it.opt("reqId")) }
        val p = if (e != null && rid != null && e.optString("type") == "ack") pending.remove(key(rid)) else null
        if (p != null) {
            val ms = clock() - p.startedMs
            if (!WalletCredentialGate.responseAllowed(e!!, p.command)) {
                val refused = WalletCredentialGate.refusal(rid, WalletCredentialGate.KEY_OVER_BRIDGE_REFUSED)
                return Result(event(refused), true, WalletCredentialGate.replyLine(p.command, refused, ms) + " sdkReplyRefused=true")
            }
            return Result(payload, true, WalletCredentialGate.replyLine(p.command, e, ms))
        }
        val hits = WalletCredentialGate.otherCommandPayloadKeyFields(payload)
        if (hits.isEmpty()) return Result(payload, false, null)
        val line = "refused sdk payload reqId=${rid ?: "null"} fields=$hits"
        return Result(rid?.let { event(WalletCredentialGate.refusal(it, WalletCredentialGate.KEY_OVER_BRIDGE_REFUSED)) }, false, line)
    }

    private fun key(rid: Any): String = (if (rid is String) "s:" else "n:") + rid

    companion object {
        fun event(e: JSONObject): JSONObject = JSONObject().put("action", "chatModuleEvent").put("event", e)
    }
}
