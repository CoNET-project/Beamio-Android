package com.beamio.app

import org.json.JSONObject
import java.security.MessageDigest

/**
 * Offer v4 verification (v108 §108.2–108.4, §108.7; v122 §141). Pure: injected recover and armor fingerprint.
 * Public v1 / v3 messages are not handled here (v137 §157: refused by schema).
 */
object VoiceOfferV4 {
    const val TYPE = "voice_call_offer_v1"
    const val PROTO = 4
    private val TOP_KEYS = setOf("type", "proto", "callId", "sessionId", "from", "to", "codec", "createdAt", "expiresAt", "timestamp", "cv", "cV", "sig")
    private val CHANNEL_KEYS = setOf("sid", "key", "wk", "temp", "tempPgpFpr", "tempPgpArmor", "auth")
    /** v129, chat interface spec 25: callId 8–128 [A-Za-z0-9_-]. */
    private val CALL_ID = Regex("^[A-Za-z0-9_-]{8,128}$")
    /** v153 §173.2: sessionId is 32 lower-case hex (128 random bits). Separate from callId's format. */
    private val SESSION_ID = Regex("^[0-9a-f]{32}$")
    /** v108 example codec; the spec names no other codec for v4 offers. */
    const val CODEC = "audio/pcm;rate=16000"

    fun sha256Hex(text: String): String =
        MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

    /** §108.3: one line per channel (role, sid, key, wk, temp, tempPgpFpr, armorSha256), joined by \n, no trailing newline. */
    fun chansDigest(channels: List<Pair<String, JSONObject>>): String {
        val text = channels.joinToString("\n") { (role, c) ->
            val armor = c.optString("tempPgpArmor", "")
            val armorSha = if (armor.isEmpty()) "" else sha256Hex(armor)
            "role:$role sid:${c.optString("sid")} key:${c.optString("key")} wk:${c.optString("wk")} " +
                "temp:${c.optString("temp")} tempPgpFpr:${c.optString("tempPgpFpr")} armorSha256:$armorSha"
        }
        return sha256Hex(text)
    }

    /** §108.4 canonical (timestamp is createdAt). */
    fun canonicalOffer(callId: String, sessionId: String, from: String, to: String, createdAt: Long, expiresAt: Long, codec: String, chansDigest: String): String =
        listOf(
            "CoNET voice_call_offer_v4",
            "callId:$callId",
            "sessionId:$sessionId",
            "from:${from.lowercase()}",
            "to:${to.lowercase()}",
            "createdAt:$createdAt",
            "expiresAt:$expiresAt",
            "timestamp:$createdAt",
            "codec:$codec",
            "chansDigest:$chansDigest",
        ).joinToString("\n")

    /** True when the offer has exactly the v4 keys (unknown keys are refused). */
    fun keysOk(offer: JSONObject): Boolean = offer.keys().asSequence().toSet() == TOP_KEYS

    /**
     * Full receiver check. Returns the failure reason, or null when the offer is valid.
     * Any failure refuses the whole offer silently (§108.7 step 1).
     */
    fun verify(
        offer: JSONObject,
        localEoa: String,
        nowMs: Long,
        recover: (String, String) -> String?,
        armorFingerprint: (String) -> String?,
    ): String? {
        if (offer.optString("type") != TYPE || offer.optInt("proto", -1) != PROTO) return "shape"
        if (!keysOk(offer)) return "unknown_key"
        val callId = offer.optString("callId")
        val sessionId = offer.optString("sessionId")
        val from = offer.optString("from").lowercase()
        val to = offer.optString("to").lowercase()
        val createdAt = offer.optLong("createdAt", -1L)
        val expiresAt = offer.optLong("expiresAt", -1L)
        val codec = offer.optString("codec")
        val sig = offer.optString("sig")
        if (!CALL_ID.matches(callId)) return "call_id"
        if (!SESSION_ID.matches(sessionId)) return "session_id"
        if (codec != CODEC) return "codec"
        if (sig.isBlank()) return "missing"
        if (createdAt <= 0L || expiresAt <= 0L) return "time"
        if (offer.optLong("timestamp", -1L) != createdAt) return "timestamp"
        if (to != localEoa.trim().lowercase()) return "not_for_local"
        if (nowMs >= expiresAt) return "expired"
        val cv = offer.optJSONObject("cv") ?: return "channel"
        val cV = offer.optJSONObject("cV") ?: return "channel"
        if (!channelKeysOk(cv) || !channelKeysOk(cV)) return "channel_unknown_key"
        val digest = chansDigest(listOf("cv" to cv, "cV" to cV))
        val text = canonicalOffer(callId, sessionId, from, to, createdAt, expiresAt, codec, digest)
        val signer = recover(text, sig) ?: return "sig"
        if (!signer.equals(from, ignoreCase = true)) return "sig_signer"
        for ((role, c) in listOf("cv" to cv, "cV" to cV)) {
            val ok = VoicePgpAuth.verify(
                callId, sessionId, role, c.optString("temp"), c.optString("tempPgpFpr"), c.optString("tempPgpArmor", ""),
                c.optJSONObject("auth") ?: return "auth", expiresAt, nowMs, armorFingerprint, recover,
            )
            if (!ok) return "channel_auth:$role"
        }
        return null
    }

    private fun channelKeysOk(c: JSONObject): Boolean = c.keys().asSequence().toSet().let { keys ->
        keys.all { it in CHANNEL_KEYS } && setOf("sid", "key", "wk", "temp", "tempPgpFpr", "auth").all { it in keys }
    }
}
