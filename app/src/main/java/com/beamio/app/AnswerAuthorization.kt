package com.beamio.app

import network.conet.chat.BeamioConetChatModule

/**
 * Callee answer gate (spec r3x §三; chat interface spec 22 §二; chat interface spec 26 §一; v114 §133.5).
 *
 * The SDK owns the decision: `incomingCallAuthorizeAnswer(callId, currentAccount)` returns
 * "allow", "deny", or "needs_unlock" (the SDK's own reason: the passcode unlock is what is missing).
 * Only "allow" permits the accept; "needs_unlock" starts the PWA unlock; anything else, an exception,
 * a blank input or an unreadable result is a deny. The shell does not infer the reason from other state
 * (gen, account, activity), so a non-passcode deny never opens the unlock entry.
 */
object AnswerAuthorization {
    enum class Verdict { ALLOW, NEEDS_UNLOCK, DENY }

    /** Pure decision over an injectable SDK call, so the fail-closed rules can be tested. */
    fun decide(callId: String, currentAccount: String, sdkAuthorize: (String, String) -> String?): Verdict {
        if (callId.isBlank() || currentAccount.isBlank()) return Verdict.DENY
        return try {
            when (sdkAuthorize(callId, currentAccount)) {
                "allow" -> Verdict.ALLOW
                "needs_unlock" -> Verdict.NEEDS_UNLOCK
                else -> Verdict.DENY
            }
        } catch (t: Throwable) {
            Verdict.DENY
        }
    }

    fun authorizeAnswer(callId: String, currentAccount: String): Verdict =
        decide(callId, currentAccount) { id, account -> BeamioConetChatModule.incomingCallAuthorizeAnswer(id, account) }

    /** Bind eligibility: a shell-verified offer whose `to` is exactly the current local account. */
    fun bindEligible(verified: Boolean, offerTo: String, localEoa: String): Boolean {
        val to = offerTo.trim().lowercase()
        return verified && to.isNotBlank() && to == localEoa.trim().lowercase()
    }

    /**
     * Sign-permission gate for the accept: bind first, then authorize. A bind that fails or
     * throws never reaches authorize. Only ALLOW returns true; every other outcome calls [onDenied].
     */
    fun permitSign(bind: () -> Boolean, authorize: () -> Verdict, onDenied: () -> Unit): Boolean {
        val bound = try { bind() } catch (t: Throwable) { false }
        if (!bound) { onDenied(); return false }
        val verdict = try { authorize() } catch (t: Throwable) { Verdict.DENY }
        if (verdict != Verdict.ALLOW) { onDenied(); return false }
        return true
    }
}
