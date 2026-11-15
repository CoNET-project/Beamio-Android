package com.beamio.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Spec §25.52Y.39 items 9-10 (PM R1844): walletStatus answers carry `notReadyReason` (g1_uninitialized | unreadable).
 * The shell must pass SDK module events to the page unchanged: no field allowlist, no result rewriting.
 */
class WalletStatusPassThroughTest {
    private val main = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
    private val handler = main.substringAfter("private fun handleChatCommand(json: String, deliver: (JSONObject) -> Unit) {")
        .substringBefore("\n    private var qaEvalReceiver")

    @Test
    fun moduleEventsReachThePageUnchanged() {
        // The SDK callback hands its payload straight to deliver(payload); the only reads of `result` are debug logs.
        assertTrue(handler.contains("BeamioConetChatModule.handleCommand(applicationContext, body) { payload ->"))
        assertTrue(handler.contains("BeamioChatSendHold.onModuleEvent(payload)\n            deliver(payload)"))
        for (rewrite in listOf(".remove(", "result\", JSONObject()", "put(\"result\"", "notReadyReason\")")) {
            assertFalse("no result rewriting: $rewrite", handler.contains(rewrite))
        }
        assertEquals("result is only read inside the debug log block", 1, Regex("""optJSONObject\("result"\)""").findAll(handler).count())
        assertTrue(handler.substringBefore("optJSONObject(\"result\")").contains("if (BuildConfig.DEBUG) payload.optJSONObject(\"event\")"))
    }

    @Test
    fun notReadyReasonIsLoggedAsAPublicFieldInDebugOnly() {
        assertTrue(handler.contains("listOf(\"state\", \"status\", \"notReadyReason\", \"ready\", \"hasKey\", \"code\", \"kind\")"))
        assertTrue(handler.contains("QaBridgeLogFields.value(it, r.opt(it))"))
    }

    /** Review of e32ca58c: only the two defined values are printed; anything else becomes <unknown> (runtime check). */
    @Test
    fun notReadyReasonValueIsLimitedToItsTwoDefinedValues() {
        assertEquals("g1_uninitialized", QaBridgeLogFields.value("notReadyReason", "g1_uninitialized"))
        assertEquals("unreadable", QaBridgeLogFields.value("notReadyReason", "unreadable"))
        for (bad in listOf<Any?>("ok", "", "G1_UNINITIALIZED", "g1_uninitialized ", "0x1234", 7, null, org.json.JSONObject.NULL)) {
            assertEquals("bad value $bad", "<unknown>", QaBridgeLogFields.value("notReadyReason", bad))
        }
        assertEquals("not_ready", QaBridgeLogFields.value("status", "not_ready"))
    }
}
