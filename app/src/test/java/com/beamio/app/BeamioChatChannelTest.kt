package com.beamio.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** window.BeamioChat (PM R763 scheme 1) decisions, and the embedded WebView never loading other origins top-level (R758). */
class BeamioChatChannelTest {
    private val trusted = "https://appassets.androidplatform.net"

    @Test
    fun originAndMainFrameComeFirst() {
        val sub = BeamioChatChannel.decide("{\"type\":\"hello\",\"reqId\":5}", trusted, isMainFrame = false)
        assertTrue(sub is BeamioChatChannel.Decision.Answer)
        val e = (sub as BeamioChatChannel.Decision.Answer).event
        assertEquals("origin_refused", e.getString("error")); assertEquals(5, e.getInt("reqId"))
        val other = BeamioChatChannel.decide("{\"type\":\"hello\",\"reqId\":\"r\"}", "https://evil.example", isMainFrame = true)
        assertEquals("origin_refused", (other as BeamioChatChannel.Decision.Answer).event.getString("error"))
        // origin is checked before JSON: unparsable data from another origin is still origin_refused, reqId null
        val otherBad = BeamioChatChannel.decide("{not json", "https://evil.example", isMainFrame = true) as BeamioChatChannel.Decision.Answer
        assertEquals("origin_refused", otherBad.event.getString("error")); assertTrue(otherBad.event.isNull("reqId"))
    }

    @Test
    fun jsonThenCommandOrSign() {
        val bad = BeamioChatChannel.decide("{not json", trusted, isMainFrame = true) as BeamioChatChannel.Decision.Answer
        assertEquals("bad_request", bad.event.getString("error")); assertTrue(bad.event.isNull("reqId"))
        val none = BeamioChatChannel.decide(null, trusted, isMainFrame = true) as BeamioChatChannel.Decision.Answer
        assertEquals("bad_request", none.event.getString("error"))
        assertTrue(BeamioChatChannel.decide("{\"type\":\"hello\",\"reqId\":1}", "$trusted/", isMainFrame = true) is BeamioChatChannel.Decision.Command)
        assertTrue(BeamioChatChannel.decide("{\"type\":\"chatModuleSignResponse\",\"reqId\":1,\"ok\":false}", trusted, true) is BeamioChatChannel.Decision.Sign)
    }

    /** r3et §25.52CT.5: a non-string message is malformed; AA.10: events go to the latest main-frame reply proxy. */
    @Test
    fun nonStringAndEventTarget() {
        val src = File("src/main/java/com/beamio/app/BeamioChatChannel.kt").readText()
        assertTrue(src.contains("if (message.type == WebMessageCompat.TYPE_STRING) runCatching { message.data }.getOrNull() else null"))
        val none = BeamioChatChannel.decide(null, trusted, isMainFrame = true) as BeamioChatChannel.Decision.Answer
        assertEquals("bad_request", none.event.getString("error")); assertTrue(none.event.isNull("reqId"))
        assertTrue(src.contains("onCommand(d.json) { payload -> toLatest(payload.toString()) }"))
        // refusals answer the sender only and never update the event target
        val answer = Regex("is Decision.Answer -> ([^\\n]*)").find(src)!!.groupValues[1]
        assertTrue(answer.startsWith("own(")); assertTrue(!answer.contains("latest"))
    }

    @Test
    fun wiring() {
        val src = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        assertTrue(src.contains("BeamioChatChannel.attach("))
        assertTrue(src.contains("onCommand = { json, deliver -> handleChatCommand(json, deliver) }"))
        // legacy channel: origin gate, then the same shared path
        assertTrue(src.contains("handleChatCommand(json) { payload -> runOnUiThread { dispatchAndroidBridgeJsonToWeb(payload) } }"))
        // R758: both shouldOverrideUrlLoading variants hand other-origin top-level navigations away from the embedded WebView
        assertEquals(2, Regex("if \\(leaveEmbeddedForExternal\\(").findAll(src).count())
        val leave = Regex("private fun leaveEmbeddedForExternal\\(url: String\\): Boolean \\{(.*?)\\n    \\}", RegexOption.DOT_MATCHES_ALL).find(src)!!.groupValues[1]
        assertTrue(leave.indexOf("UrlSecretCheck.ruleFor(url)") < leave.indexOf("openExternalUrlFromBridge(url)"))
    }
}
