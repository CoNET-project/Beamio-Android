package com.beamio.app.credential

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Frozen passcode protocol v1 §一第 6 条 (shell side, PageSyncRoute): the six passcode commands are routed, each carries only its
 * own fields, and a credential field outside the command's list is refused before the SDK.
 */
class PasscodeAllowlistTest {
    private val eoa = "0x" + "a".repeat(40)

    private fun body(type: String, vararg pairs: Pair<String, Any>): JSONObject {
        val o = JSONObject().put("type", type).put("reqId", 7).put("eoa", eoa)
        pairs.forEach { (k, v) -> o.put(k, v) }
        return o
    }

    @Test fun sixPasscodeCommandsAreRouted() {
        listOf(
            "passcodeProvision", "passcodeUnlock", "passcodeChange", "passcodeDisable", "nativeRepairProvide", "passcodeStatus",
        ).forEach { assertTrue(it, it in PageSyncRoute.COMMANDS) }
    }

    @Test fun existingCommandsAreUnchanged() {
        assertEquals(setOf("pwaWalletSync", "nativeMnemonicPreread", "pwaEmptySignal"), PageSyncRoute.COMMANDS - PageSyncRoute.PASSCODE_ALLOWED.keys)
    }

    @Test fun provisionMayCarryPhraseAndPasscode() {
        val b = body("passcodeProvision", "phrase" to "x", "passcode" to "123456")
        assertNull(PageSyncRoute.refusalBeforeSdk(b, trusted = true))
    }

    @Test fun unlockRefusesPhrase() {
        val b = body("passcodeUnlock", "passcode" to "123456", "phrase" to "x")
        assertEquals("key_over_bridge_refused", PageSyncRoute.refusalBeforeSdk(b, trusted = true)?.optString("error"))
    }

    @Test fun changeCarriesOnlyOldAndNewPasscode() {
        val ok = body("passcodeChange", "oldPasscode" to "111111", "newPasscode" to "222222")
        assertNull(PageSyncRoute.refusalBeforeSdk(ok, trusted = true))
        val bad = body("passcodeChange", "passcode" to "111111", "newPasscode" to "222222")
        assertEquals("key_over_bridge_refused", PageSyncRoute.refusalBeforeSdk(bad, trusted = true)?.optString("error"))
    }

    @Test fun statusCarriesNoCredential() {
        assertNull(PageSyncRoute.refusalBeforeSdk(body("passcodeStatus"), trusted = true))
        val b = body("passcodeStatus", "passcode" to "123456")
        assertEquals("key_over_bridge_refused", PageSyncRoute.refusalBeforeSdk(b, trusted = true)?.optString("error"))
    }

    @Test fun unknownFieldOnPasscodeCommandIsBadRequest() {
        val b = body("passcodeUnlock", "passcode" to "123456", "extra" to "1")
        assertEquals("bad_request", PageSyncRoute.refusalBeforeSdk(b, trusted = true)?.optString("error"))
    }

    @Test fun untrustedSourceIsRefusedFirst() {
        val b = body("passcodeUnlock", "passcode" to "123456")
        assertEquals("untrusted_source", PageSyncRoute.refusalBeforeSdk(b, trusted = false)?.optString("error"))
    }

    @Test fun otherCommandsHaveNoAllowlist() {
        assertNull(PageSyncRoute.allowedFieldsFor("pwaWalletSync"))
        assertNotNull(PageSyncRoute.allowedFieldsFor("passcodeStatus"))
    }

    @Test fun unlockMayCarryCallIdOnly() {
        val ok = body("passcodeUnlock", "passcode" to "123456", "callId" to "call-offer-0002")
        assertNull(PageSyncRoute.refusalBeforeSdk(ok, trusted = true))
        val bad = body("passcodeUnlock", "passcode" to "123456", "callId" to "call-offer-0002", "sessionId" to "x")
        assertEquals("bad_request", PageSyncRoute.refusalBeforeSdk(bad, trusted = true)?.optString("error"))
    }
}
