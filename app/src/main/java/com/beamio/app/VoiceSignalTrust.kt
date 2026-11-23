package com.beamio.app

import org.json.JSONObject

/**
 * Trust gate for voice signalling that drives call actions (v54 §61, v68 §75): a signal acts only when
 * it sits in an envelope whose EIP-191 signer equals envelope.from, equals the payload sender, and equals
 * the inner from. A bare signal (no envelope), a missing inner from, or any mismatch is dropped silently.
 * Pure functions: the chat line is the only input.
 */
object VoiceSignalTrust {
    data class Envelope(val text: String, val from: String, val signMessage: String)

    /** The envelope in a chat line: a JSON object, or base64 of one, with text, from and signMessage. */
    fun envelopeOf(line: String): Envelope? {
        val json = jsonOf(line.trim()) ?: run {
            val decoded = VoiceOfferWire.base64Decode(line.trim())?.let { String(it, Charsets.UTF_8) } ?: return null
            jsonOf(decoded.trim()) ?: return null
        }
        val text = json.optString("text")
        val from = json.optString("from")
        val sig = json.optString("signMessage")
        if (text.isEmpty() || from.isEmpty() || sig.isEmpty()) return null
        return Envelope(text, from, sig)
    }

    /** The inner signal when every trust condition holds; otherwise null (no action). */
    fun verifiedInner(line: String, payloadFrom: String): JSONObject? {
        val env = envelopeOf(line) ?: return null
        if (env.from.trim().lowercase() != payloadFrom.trim().lowercase()) return null
        val inner = jsonOf(env.text) ?: return null
        val innerFrom = inner.optString("from")
        if (innerFrom.isEmpty()) return null
        if (!VoiceOfferWire.outerEnvelopeOk(env.text, env.signMessage, env.from, innerFrom)) return null
        return inner
    }

    private fun jsonOf(s: String): JSONObject? = if (s.startsWith("{")) runCatching { JSONObject(s) }.getOrNull() else null
}
