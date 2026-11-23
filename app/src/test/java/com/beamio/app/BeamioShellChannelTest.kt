package com.beamio.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** window.BeamioShell: decisions, and which methods stay on addJavascriptInterface. */
class BeamioShellChannelTest {
    private val trusted = "https://appassets.androidplatform.net"

    private fun answer(d: BeamioShellChannel.Decision) = (d as BeamioShellChannel.Decision.Answer).ack

    @Test
    fun orderOriginJsonReqIdActionArgs() {
        val sub = answer(BeamioShellChannel.decide("{\"action\":\"openURL\",\"reqId\":7,\"args\":{\"url\":\"https://x\"}}", trusted, false))
        assertEquals("origin_refused", sub.getString("error")); assertEquals(7, sub.getInt("reqId")); assertFalse(sub.getBoolean("ok"))
        val other = answer(BeamioShellChannel.decide("{not json", "https://evil.example", true))
        assertEquals("origin_refused", other.getString("error")); assertTrue(other.isNull("reqId"))
        val bad = answer(BeamioShellChannel.decide("{not json", trusted, true))
        assertEquals("bad_request", bad.getString("error")); assertTrue(bad.isNull("reqId"))
        assertEquals("bad_request", answer(BeamioShellChannel.decide(null, trusted, true)).getString("error"))
        val badId = answer(BeamioShellChannel.decide("{\"action\":\"openURL\",\"reqId\":1.0}", trusted, true))
        assertEquals("bad_request", badId.getString("error")); assertTrue(badId.isNull("reqId"))
        val unknown = answer(BeamioShellChannel.decide("{\"action\":\"chatModuleCommand\",\"reqId\":\"r\"}", trusted, true))
        assertEquals("unknown_command", unknown.getString("error")); assertEquals("r", unknown.getString("reqId"))
        val badArgs = answer(BeamioShellChannel.decide("{\"action\":\"saveFile\",\"reqId\":1,\"args\":\"x\"}", trusted, true))
        assertEquals("bad_args", badArgs.getString("error"))
        assertEquals("bad_args", answer(BeamioShellChannel.decide("{\"action\":\"openURL\",\"reqId\":1,\"args\":{}}", trusted, true)).getString("error"))
    }

    @Test
    fun callCarriesTheOldArgument() {
        val open = BeamioShellChannel.decide("{\"action\":\"openURL\",\"reqId\":1,\"args\":{\"url\":\"https://beamio.app/\"}}", "$trusted/", true) as BeamioShellChannel.Decision.Call
        assertEquals("https://beamio.app/", open.arg)
        val scan = BeamioShellChannel.decide("{\"action\":\"scanQr\",\"reqId\":2,\"args\":{\"requestId\":\"q1\"}}", trusted, true) as BeamioShellChannel.Decision.Call
        assertEquals("q1", scan.arg)
        val save = BeamioShellChannel.decide("{\"action\":\"saveFile\",\"reqId\":3,\"args\":{\"name\":\"a\"}}", trusted, true) as BeamioShellChannel.Decision.Call
        assertEquals("{\"name\":\"a\"}", save.arg)
        val mic = BeamioShellChannel.decide("{\"action\":\"startNativeVoiceMic\",\"reqId\":4}", trusted, true) as BeamioShellChannel.Decision.Call
        assertEquals("", mic.arg)
    }

    /** / CV.2: no sensitive method is @JavascriptInterface on the base bridge; the kept ones are exactly these 13 . */
    @Test
    fun oldBridgeKeepsOnlyNonSensitiveMethods() {
        val src = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        val base = src.substring(src.indexOf("    private open inner class CashTreesJsBridge {"), src.indexOf("    private inner class CashTreesJsBridgeLegacy"))
            .let { it.substring(0, it.indexOf("\n    }\n") + 6) }
        val annotated = Regex("@JavascriptInterface\\s+(?:open\\s+)?fun\\s+(\\w+)").findAll(base).map { it.groupValues[1] }.toSortedSet()
        val kept = sortedSetOf(
            "applyEmbeddedPwaUpdate", "getNfcStatus", "requestDeliveryHealth", "openDeliverySettings", "dismissDeliveryHealthNotice",
            "getEmbeddedPwaVersion", "getEmbeddedPwaPendingVersion", "publishAppState",
            "clearOfflineChatAlerts", "notifyBackgroundChat", "debugLog", "chatModuleAvailable", "chatModuleIsRunning",
        )
        assertEquals(kept, annotated)
        assertEquals(25, BeamioShellChannel.ACTIONS.size) // +queryIncomingCallOutcome, +notifyVoiceMicReady, -scanRecoveryQr;
        // +nativeIdentityCheck, +uiLockState (qa.8 public entries), +incomingCallUnlockShown (A3),
        // +dismissIncomingSystemCall (v46 §52)
        for (name in BeamioShellChannel.ACTIONS.keys + listOf("chatModuleCommand", "chatModuleSignResponse")) {
            assertFalse("$name must not be on the base bridge", name in annotated)
        }
        // The legacy subclass is the only place that re-exposes them, and only behind the build flag.
        val legacy = Regex("private inner class CashTreesJsBridgeLegacy : CashTreesJsBridge\\(\\) \\{(.*?)\\n    \\}", RegexOption.DOT_MATCHES_ALL).find(src)!!.groupValues[1]
        val reexposed = Regex("@JavascriptInterface override fun (\\w+)").findAll(legacy).map { it.groupValues[1] }.toSet()
        // Legacy-bridge invariant, amended 2026-11-23 (minimum exposure): the legacy bridge re-exposes every ACTION
        // except the new identity / unlock commands below, which never go out over the sensitive legacy bridge.
        val legacyExcluded = setOf("nativeIdentityCheck", "uiLockState", "incomingCallUnlockShown")
        assertTrue(BeamioShellChannel.ACTIONS.keys.containsAll(legacyExcluded))
        assertEquals(BeamioShellChannel.ACTIONS.keys - legacyExcluded + setOf("chatModuleCommand", "chatModuleSignResponse"), reexposed)
        // The excluded commands have no entry at all on the legacy subclass (nor on the base bridge, checked above).
        for (name in legacyExcluded) {
            assertFalse("$name must not be on the legacy bridge", Regex("fun\\s+$name\\s*\\(").containsMatchIn(legacy))
        }
        assertTrue(src.contains("if (BuildConfig.LEGACY_SENSITIVE_BRIDGE) CashTreesJsBridgeLegacy() else CashTreesJsBridge()"))
        assertTrue(src.contains("BeamioShellChannel.attach(this) { call, gate -> handleShellCall(jsBridge, call, gate) }"))
    }

    @Test
    fun dispatcherRefusesBeforeCalling() {
        val src = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        val body = Regex("private fun handleShellCall\\(.*?\\n    \\}\\n", RegexOption.DOT_MATCHES_ALL).find(src)!!.value
        val gate = body.indexOf("gate?.let")  // the gate result is computed off main and passed in (ANR fix 2026-11-17)
        val urlCheck = body.indexOf("UrlSecretCheck.ruleFor(url)")
        val firstCall = body.indexOf("bridge.openURL(")
        assertTrue(gate in 0 until urlCheck); assertTrue(urlCheck < firstCall)
        for (name in BeamioShellChannel.ACTIONS.keys) assertTrue("dispatch $name", body.contains("\"$name\" ->"))
    }
}
