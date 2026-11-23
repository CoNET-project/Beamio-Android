package com.beamio.app

/**
 * Incoming-call title rule (v116 §135, transitional, three ends alike).
 * Title: the verified `from` short address. Secondary text: the claimed tag, labelled 未核验,
 * never a title and never used for a name lookup.
 */
object IncomingCallTitle {
    const val UNVERIFIED_SUFFIX = "（未核验）"

    /** Title from the verified address; blank when there is none (the caller then uses its default). */
    fun title(verifiedAddress: String): String =
        if (verifiedAddress.isBlank()) "" else BeamioVoiceOfferIdentity.shortAddress(verifiedAddress.trim())

    /** Title for a call from its verified address (blank when unknown; the caller then uses its default). */
    fun forCall(callId: String, sessionId: String): String = title(VerifiedCallerRegistry.addressFor(callId, sessionId))

    /** Secondary line: the labelled claimed tag, or null when there is none. */
    fun secondary(claimedTag: String): String? =
        claimedTag.trim().takeIf { it.isNotEmpty() }?.let { it + UNVERIFIED_SUFFIX }
}

/**
 * The verified `from` of each incoming call, keyed by callId and sessionId. Written only from the
 * shell-verified offer path (never from a PWA-reported display), removed at the terminal cleanup.
 * Every incoming title, Person name, avatar key and Telecom display name reads this one source.
 */
object VerifiedCallerRegistry {
    private val byKey = java.util.concurrent.ConcurrentHashMap<String, String>()
    private val ADDRESS = Regex("^0x[0-9a-f]{40}$")

    fun put(callId: String, sessionId: String, from: String) {
        val addr = from.trim().lowercase()
        if (!ADDRESS.matches(addr)) return
        if (callId.isNotBlank()) byKey[callId] = addr
        if (sessionId.isNotBlank()) byKey[sessionId] = addr
    }

    /** The verified address for the call, or "" when none is known. */
    fun addressFor(callId: String, sessionId: String): String =
        byKey[callId] ?: byKey[sessionId] ?: ""

    fun remove(callId: String, sessionId: String) {
        if (callId.isNotBlank()) byKey.remove(callId)
        if (sessionId.isNotBlank()) byKey.remove(sessionId)
    }
}
