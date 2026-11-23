package com.beamio.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Answer gate: SDK decision mapping (fail closed) and the bind-then-authorize sign gate. */
class AnswerAuthorizationTest {
    private val acct = "0x1111111111111111111111111111111111111111"
    private val call = "call-0001-abcdef"

    @Test fun allowPermits() {
        assertEquals(AnswerAuthorization.Verdict.ALLOW, AnswerAuthorization.decide(call, acct) { _, _ -> "allow" })
    }

    @Test fun needsUnlockIsItsOwnVerdict() {
        assertEquals(AnswerAuthorization.Verdict.NEEDS_UNLOCK, AnswerAuthorization.decide(call, acct) { _, _ -> "needs_unlock" })
    }

    @Test fun denyDenies() {
        assertEquals(AnswerAuthorization.Verdict.DENY, AnswerAuthorization.decide(call, acct) { _, _ -> "deny" })
    }

    @Test fun unreadableResultDenies() {
        assertEquals(AnswerAuthorization.Verdict.DENY, AnswerAuthorization.decide(call, acct) { _, _ -> null })
        assertEquals(AnswerAuthorization.Verdict.DENY, AnswerAuthorization.decide(call, acct) { _, _ -> "ALLOW" })
        assertEquals(AnswerAuthorization.Verdict.DENY, AnswerAuthorization.decide(call, acct) { _, _ -> "gen_mismatch" })
        assertEquals(AnswerAuthorization.Verdict.DENY, AnswerAuthorization.decide(call, acct) { _, _ -> "" })
    }

    @Test fun exceptionDenies() {
        val v = AnswerAuthorization.decide(call, acct) { _, _ -> throw IllegalStateException("sdk down") }
        assertEquals(AnswerAuthorization.Verdict.DENY, v)
    }

    @Test fun blankInputsDenyWithoutCallingSdk() {
        var called = false
        val sdk: (String, String) -> String? = { _, _ -> called = true; "allow" }
        assertEquals(AnswerAuthorization.Verdict.DENY, AnswerAuthorization.decide("", acct, sdk))
        assertEquals(AnswerAuthorization.Verdict.DENY, AnswerAuthorization.decide(call, "", sdk))
        assertFalse(called)
    }

    @Test fun sdkReceivesCallIdAndAccount() {
        var seen = ""
        AnswerAuthorization.decide(call, acct) { id, account -> seen = "$id|$account"; "allow" }
        assertEquals("$call|$acct", seen)
    }

    @Test fun gateSignsOnlyOnAllow() {
        var denied = 0
        val ok = AnswerAuthorization.permitSign(
            bind = { true }, authorize = { AnswerAuthorization.Verdict.ALLOW }, onDenied = { denied++ },
        )
        assertTrue(ok)
        assertEquals(0, denied)
    }

    @Test fun gateDeniesOnDenyAndReleases() {
        var denied = 0
        val ok = AnswerAuthorization.permitSign(
            bind = { true }, authorize = { AnswerAuthorization.Verdict.DENY }, onDenied = { denied++ },
        )
        assertFalse(ok)
        assertEquals(1, denied)
    }

    @Test fun bindFailureNeverReachesAuthorize() {
        var authorized = false
        var denied = 0
        val ok = AnswerAuthorization.permitSign(
            bind = { false },
            authorize = { authorized = true; AnswerAuthorization.Verdict.ALLOW },
            onDenied = { denied++ },
        )
        assertFalse(ok)
        assertFalse(authorized)
        assertEquals(1, denied)
    }

    @Test fun bindExceptionDenies() {
        var denied = 0
        val ok = AnswerAuthorization.permitSign(
            bind = { throw IllegalStateException("bind failed") },
            authorize = { AnswerAuthorization.Verdict.ALLOW },
            onDenied = { denied++ },
        )
        assertFalse(ok)
        assertEquals(1, denied)
    }

    @Test fun authorizeExceptionDenies() {
        var denied = 0
        val ok = AnswerAuthorization.permitSign(
            bind = { true },
            authorize = { throw IllegalStateException("authorize failed") },
            onDenied = { denied++ },
        )
        assertFalse(ok)
        assertEquals(1, denied)
    }

    @Test fun bindOnlyForVerifiedOfferToLocalAccount() {
        val me = "0x1111111111111111111111111111111111111111"
        assertTrue(AnswerAuthorization.bindEligible(true, me.uppercase(), me))
        assertFalse(AnswerAuthorization.bindEligible(false, me, me))
        assertFalse(AnswerAuthorization.bindEligible(true, "0x2222222222222222222222222222222222222222", me))
        assertFalse(AnswerAuthorization.bindEligible(true, "", me))
        assertFalse(AnswerAuthorization.bindEligible(true, me, ""))
    }
}
