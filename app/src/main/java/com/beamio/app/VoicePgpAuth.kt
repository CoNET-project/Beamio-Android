package com.beamio.app

import org.json.JSONObject

/**
 * Account authorization of a temporary channel key (`voice_pgp_auth_v1`; v91 §94.2, v111 §128).
 *
 * The signer is the account EOA (EIP-191). The verifier rebuilds the canonical text from the
 * channel's top-level `tempPgpFpr` (the single source, §128), checks the `auth` object shape,
 * the fingerprint format and the validity window, then recovers the signer.
 * Any failure rejects that channel; nothing here is logged with key material.
 */
object VoicePgpAuth {
    const val PREFIX = "CoNET voice_pgp_auth_v1"
    private val FPR = Regex("^[0-9a-f]{40}$")
    private val AUTH_KEYS = setOf("from", "validUntil", "sig")

    /** Canonical text (UTF-8, `\n`-joined, lower case). `tempPgpFpr` is the top-level value. */
    fun canonical(callId: String, sessionId: String, channel: String, temp: String, tempPgpFpr: String, from: String, validUntil: Long): String =
        listOf(
            PREFIX,
            "callId:$callId",
            "sessionId:$sessionId",
            "channel:$channel",
            "temp:${temp.lowercase()}",
            "tempPgpFpr:${tempPgpFpr.lowercase()}",
            "from:${from.lowercase()}",
            "validUntil:$validUntil",
        ).joinToString("\n")

    /** `auth` must be exactly {from, validUntil, sig}; any other field (tempPgpFpr included) is refused. */
    fun authShapeOk(auth: JSONObject): Boolean = auth.keys().asSequence().toSet() == AUTH_KEYS

    /** Top-level tempPgpFpr: strict lower-case 40-hex, or empty when there is no PGP armor. */
    fun fprFormatOk(fpr: String): Boolean = fpr.isEmpty() || FPR.matches(fpr)

    /**
     * Full check of one channel. [armorFingerprint] returns the fingerprint of the attached armor
     * (lower-case 40-hex), or null when it cannot be read; [recover] is the EIP-191 recovery over the
     * canonical text (returns the signer address or null).
     */
    fun verify(
        callId: String,
        sessionId: String,
        channel: String,
        temp: String,
        topTempPgpFpr: String,
        tempPgpArmor: String,
        auth: JSONObject,
        offerExpiresAt: Long,
        nowMs: Long,
        armorFingerprint: (String) -> String?,
        recover: (String, String) -> String?,
    ): Boolean {
        if (!authShapeOk(auth) || !fprFormatOk(topTempPgpFpr)) return false
        if (topTempPgpFpr.isEmpty() && tempPgpArmor.isNotEmpty()) return false
        if (topTempPgpFpr.isNotEmpty()) {
            val fp = armorFingerprint(tempPgpArmor) ?: return false
            if (fp != topTempPgpFpr) return false
        } else {
            if (tempPgpArmor.isNotEmpty()) return false
        }
        val from = auth.optString("from")
        val sig = auth.optString("sig")
        val validUntil = auth.optLong("validUntil", -1L)
        if (from.isBlank() || sig.isBlank() || validUntil <= 0L) return false
        if (!(nowMs <= validUntil && validUntil <= offerExpiresAt)) return false
        val text = canonical(callId, sessionId, channel, temp, topTempPgpFpr, from, validUntil)
        val signer = recover(text, sig) ?: return false
        return signer.equals(from, ignoreCase = true)
    }
}
