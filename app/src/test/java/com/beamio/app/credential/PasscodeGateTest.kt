package com.beamio.app.credential

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Frozen passcode protocol v1 §一第 6-7 条 (shell side, WalletCredentialGate): the six commands are gated, their request shape
 * follows their own field list, and their replies may not carry key material or passcode fields.
 */
class PasscodeGateTest {
    private val eoa = "0x" + "a".repeat(40)

    private fun body(type: String, vararg pairs: Pair<String, Any>): JSONObject {
        val o = JSONObject().put("type", type).put("reqId", 9).put("eoa", eoa)
        pairs.forEach { (k, v) -> o.put(k, v) }
        return o
    }

    private fun refuseError(r: WalletCredentialGate.RequestCheck): String? =
        (r as? WalletCredentialGate.RequestCheck.Refuse)?.error

    @Test fun sixCommandsAreGated() {
        listOf("passcodeProvision", "passcodeUnlock", "passcodeChange", "passcodeDisable", "nativeRepairProvide", "passcodeStatus")
            .forEach { assertTrue(it, it in WalletCredentialGate.GATED_COMMANDS) }
        assertTrue(WalletCredentialGate.COMMAND in WalletCredentialGate.GATED_COMMANDS)
    }

    @Test fun trustedUnlockPassesAndExtraFieldIsBadRequest() {
        assertTrue(WalletCredentialGate.checkRequest(body("passcodeUnlock", "passcode" to "123456"), WalletCredentialGate.Verdict.TRUSTED) is WalletCredentialGate.RequestCheck.Pass)
        val extra = body("passcodeUnlock", "passcode" to "123456", "x" to "1")
        assertEquals("bad_request", refuseError(WalletCredentialGate.checkRequest(extra, WalletCredentialGate.Verdict.TRUSTED)))
    }

    @Test fun phraseOnUnlockIsKeyOverBridge() {
        val b = body("passcodeUnlock", "passcode" to "123456", "phrase" to "a b")
        assertEquals("key_over_bridge_refused", refuseError(WalletCredentialGate.checkRequest(b, WalletCredentialGate.Verdict.TRUSTED)))
    }

    @Test fun untrustedPasscodeRequestIsNotTrusted() {
        val b = body("passcodeUnlock", "passcode" to "123456")
        assertEquals("not_trusted", refuseError(WalletCredentialGate.checkRequest(b, WalletCredentialGate.Verdict.NO_MANIFEST_CAPABILITY)))
    }

    @Test fun replyWithPasscodeFieldIsRefused() {
        val leaked = JSONObject().put("type", "ack").put("reqId", 9).put("ok", true)
            .put("result", JSONObject().put("passcode", "123456"))
        assertFalse(WalletCredentialGate.responseAllowed(leaked, "passcodeProvision"))
    }

    @Test fun digitPasscodeValueInReplyIsRefused() {
        val leaked = JSONObject().put("type", "ack").put("reqId", 9).put("ok", true)
            .put("result", JSONObject().put("passcode", "654321").put("eoa", eoa))
        assertFalse(WalletCredentialGate.responseAllowed(leaked, "passcodeUnlock"))
    }

    @Test fun passcodeResultShapeIsNotWalletCredentialShape() {
        val ok = JSONObject().put("type", "ack").put("reqId", 9).put("ok", true)
            .put("result", JSONObject().put("passcode", "set").put("eoa", eoa).put("verifiedAddress", eoa))
        assertTrue(WalletCredentialGate.responseAllowed(ok, "passcodeProvision"))
    }
}
