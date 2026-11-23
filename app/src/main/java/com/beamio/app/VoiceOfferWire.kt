package com.beamio.app

import org.json.JSONObject

/**
 * Callee-side wire checks for a voice_call_offer_v1 (spec chat interface spec 29 v30 §33; PWA
 * encryptVoiceOfferArmorToCallee in voiceCallController.ts:157–184; signing in
 * voiceCallSession.ts:177–199). Pure functions, JVM-testable:
 *  - the PGP layer (decrypt of the armor) is NOT here: it needs the native vault and is
 *    device-only; these functions take the decrypted plaintext;
 *  - envelope: base64(JSON {timestamp, text, from, signMessage}); signMessage (EIP-191) over
 *    `text` must recover `from`;
 *  - inner offer: `text` is the signal JSON; its callerSignature (EIP-191) over the canonical
 *    text (header "CoNET voice_call_offer_v3", fields in §33.1 order, `to` lower-cased) must
 *    recover the same `from` (R).
 */
object VoiceOfferWire {
    const val HEADER = "CoNET voice_call_offer_v3"

    data class Envelope(val text: String, val from: String, val signMessage: String)

    /** Canonical signed text rebuilt from the signal fields (byte layout of the PWA sign text). */
    fun canonicalText(signal: JSONObject): String = listOf(
        HEADER,
        "callId:" + signal.optString("callId"),
        "sessionId:" + signal.optString("sessionId"),
        "to:" + signal.optString("to").trim().lowercase(),
        "createdAt:" + signal.optString("createdAt"),
        "expiresAt:" + signal.optString("expiresAt"),
        "timestamp:" + signal.optString("timestamp"),
        "codec:" + signal.optString("codec"),
        "callerPgp:" + signal.optString("callerPgp"),
        "callerRoute:" + signal.optString("callerRoute"),
    ).joinToString("\n")

    /** R of the inner offer: ecrecover of callerSignature over the canonical text. */
    fun innerSigner(signal: JSONObject): String? =
        BeamioNativeEthSigner.recoverAddress(canonicalText(signal), signal.optString("callerSignature"))

    /** Verified inner-offer fields: R equals the claimed from (spec 26.3 step 1). Null if not verified. */
    data class Verified(
        val from: String,
        val recoveredR: String,
        val to: String,
        val callId: String,
        val sessionId: String,
        val createdAtMs: Long,
        val expiresAtMs: Long,
        val callerPgp: String,
        val callerRoute: String,
        val proto: Int,
    )

    fun verifiedFields(signal: JSONObject): Verified? {
        if (signal.optString("type") != "voice_call_offer_v1") return null
        val from = signal.optString("from").trim().lowercase()
        val r = innerSigner(signal)?.trim()?.lowercase() ?: return null
        if (from.isEmpty() || r != from) return null
        val callId = signal.optString("callId").trim()
        val sessionId = signal.optString("sessionId").trim()
        if (callId.isEmpty()) return null
        return Verified(
            from = from,
            recoveredR = r,
            to = signal.optString("to").trim().lowercase(),
            callId = callId,
            sessionId = sessionId,
            createdAtMs = signal.optLong("createdAt", -1L),
            expiresAtMs = signal.optLong("expiresAt", -1L),
            callerPgp = signal.optString("callerPgp"),
            callerRoute = signal.optString("callerRoute"),
            proto = signal.optInt("proto", 0),
        )
    }

    /** Envelope from the decrypted plaintext (base64 of the envelope JSON). Null when malformed. */
    fun parseEnvelope(plaintext: String): Envelope? {
        val json = runCatching { JSONObject(String(base64Decode(plaintext.trim()) ?: return null, Charsets.UTF_8)) }
            .getOrNull() ?: return null
        val text = json.optString("text")
        val from = json.optString("from")
        val sig = json.optString("signMessage")
        if (text.isEmpty() || from.isEmpty() || sig.isEmpty()) return null
        return Envelope(text, from, sig)
    }

    /**
     * Outer envelope check (29 v30 §33; chat interface spec 29 v45 §50(3)): EIP-191 recovery of envelopeSignMessage over
     * the envelope text must equal envelopeFrom, and envelopeFrom must equal the inner from. Any missing
     * part or mismatch is false.
     */
    fun outerEnvelopeOk(envelopeText: String, envelopeSignMessage: String, envelopeFrom: String, innerFrom: String): Boolean {
        val ef = envelopeFrom.trim().lowercase()
        val inf = innerFrom.trim().lowercase()
        if (envelopeText.isEmpty() || envelopeSignMessage.isEmpty() || ef.isEmpty() || inf.isEmpty()) return false
        val recovered = BeamioNativeEthSigner.recoverAddress(envelopeText, envelopeSignMessage)?.lowercase() ?: return false
        return recovered == ef && ef == inf
    }

    /** Envelope check: signMessage over text recovers `from`. */
    fun envelopeSigner(e: Envelope): String? = BeamioNativeEthSigner.recoverAddress(e.text, e.signMessage)

    /** Standard base64 (RFC 4648) decode without android.util, so JVM tests can call it. */
    fun base64Decode(s: String): ByteArray? {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        val clean = s.trimEnd('=')
        if (clean.isEmpty() || clean.any { alphabet.indexOf(it) < 0 }) return null
        val out = java.io.ByteArrayOutputStream()
        var buf = 0
        var bits = 0
        for (c in clean) {
            buf = (buf shl 6) or alphabet.indexOf(c)
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out.write((buf shr bits) and 0xff)
            }
        }
        return out.toByteArray()
    }
}
