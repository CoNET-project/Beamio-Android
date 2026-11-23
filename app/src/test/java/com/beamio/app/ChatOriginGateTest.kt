package com.beamio.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** scheme 2 (spec r3ej §25.52CJ.3, r3em CM.3): chat channel origin gate. */
class ChatOriginGateTest {
    @Test
    fun originParsing() {
        assertEquals("https://appassets.androidplatform.net", ChatOriginGate.originOf("https://appassets.androidplatform.net/assets/index.html#/home"))
        assertEquals("https://appassets.androidplatform.net", ChatOriginGate.originOf("HTTPS://AppAssets.AndroidPlatform.net/x"))
        assertEquals("https://appassets.androidplatform.net:8443", ChatOriginGate.originOf("https://appassets.androidplatform.net:8443/x"))
        assertNull(ChatOriginGate.originOf("https://user@appassets.androidplatform.net/x"))
        assertNull(ChatOriginGate.originOf("about:blank"))
        assertNull(ChatOriginGate.originOf(null))
    }

    @Test
    fun onlyTheTrustedOriginPasses() {
        assertTrue(ChatOriginGate.allowed(ChatOriginGate.originOf("https://appassets.androidplatform.net/index.html")))
        for (u in listOf(
            "http://appassets.androidplatform.net/", "https://appassets.androidplatform.net:8443/",
            "https://evil.appassets.androidplatform.net/", "https://appassets.androidplatform.net.evil.example/",
            "https://beamio.app/", "file:///android_asset/index.html", "about:blank",
        )) assertFalse(u, ChatOriginGate.allowed(ChatOriginGate.originOf(u)))
        assertFalse(ChatOriginGate.allowed(null))
    }

    /** Origin is checked before anything else in chatModuleCommand; both page callbacks record it. */
    @Test
    fun wiring() {
        val src = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        val body = Regex("fun chatModuleCommand\\(json: String\\) \\{(.*?)\\n        \\}\\n", RegexOption.DOT_MATCHES_ALL).find(src)!!.groupValues[1]
        // Gate order 2026-11-17: pwaWalletSync / nativeMnemonicPreread (and the passcode commands) enter the page-sync
        // trust gate first and return; every other command meets the origin check as the first statement after that block.
        val afterPageSync = body.substringAfter("PageSyncRoute.normalize(json)?.let { pageSync ->").substringAfter("\n                return\n            }\n")
        assertEquals("if (!ChatOriginGate.allowed(embeddedTopOrigin)) {",
            afterPageSync.lines().map { it.trim() }.first { it.isNotEmpty() && !it.startsWith("//") })
        assertTrue(body.indexOf("PageSyncRoute.normalize(json)") < body.indexOf("ChatOriginGate.allowed"))
        // the shared command path (JSON, reqId, SDK) moved to handleChatCommand, which the legacy entry calls only
        // after the origin gate; window.BeamioChat reaches it only through BeamioChatChannel.decide (origin and main frame).
        assertTrue(body.indexOf("ChatOriginGate.allowed") < body.indexOf("handleChatCommand(json, WalletCredentialGate.Channel.JS_INTERFACE)"))
        assertFalse(body.contains("BeamioConetChatModule.handleCommand"))
        val shared = Regex("private fun handleChatCommand\\(json: String, channel: WalletCredentialGate.Channel, deliver: \\(JSONObject\\) -> Unit\\) \\{(.*?)\\n    \\}\\n", RegexOption.DOT_MATCHES_ALL).find(src)!!.groupValues[1]
        assertTrue(shared.indexOf("JSONObject(json)") < shared.indexOf("BeamioConetChatModule.handleCommand"))
        assertEquals(2, Regex("handleChatCommand\\(json").findAll(src).count() - 1) // definition + two callers
        assertTrue(src.contains("\"origin_refused\"") || src.contains("ChatOriginGate.ERROR"))
        assertEquals(2, Regex("embeddedTopOrigin = ChatOriginGate.originOf\\(url\\)").findAll(src).count())
        // Only the embedded WebView gets the JS interfaces; popups and the in-app browser get none.
        assertEquals(1, Regex("addJavascriptInterface\\(jsBridge, \"CashTreesAndroid\"\\)").findAll(src).count())
    }
}
