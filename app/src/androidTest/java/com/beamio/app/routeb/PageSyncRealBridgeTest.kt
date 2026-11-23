package com.beamio.app.routeb

import android.webkit.WebView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.beamio.app.MainActivity
import network.conet.chat.nativekey.NativeQaStateHooks
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.atomic.AtomicReference

/**
 * Real bridge write-evidence (contract v3.3, E6/E8.1 scope), synthetic values only, on an isolated emulator.
 *
 * 1. The QA hook builds the state "window after, only private key B" from a synthetic phrase (no MNEM record).
 * 2. From the trusted main frame of the embedded page, `window.BeamioShellRecord` sends pwaWalletSync(B): the SDK answers ok with
 *    result.sync = updated (the phrase is written).
 * 3. nativeMnemonicPreread then answers result.state = valid.
 * 4. Negative: pwaEmptySignal sent from a child frame is answered untrusted_source (the SDK is not called; checked in logcat).
 *
 * Requires the nativekeySdk variant with -PchatQaHooks=true (the hook is compiled only into the QA AAR).
 */
@RunWith(AndroidJUnit4::class)
class PageSyncRealBridgeTest {

    /** Public BIP-39 test vector (not an account). Its EOA is the first derived address of the standard path. */
    private val syntheticPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val syntheticEoa = "0x9858effd232b4033e47d90003d41ec34ecaeda94"

    @Test
    fun trustedMainFrameWritesAndPrereadsValid_childFrameRefused() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val ctx = instrumentation.targetContext
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            val webView = awaitEmbeddedWebView(scenario)
            assertNotNull("embedded WebView not found", webView)
            webView!!

            // OK: the hook built the key-only state now. ALREADY_PRESENT: an earlier run on this same AVD built it and left it (the
            // hook refuses any existing account); the pwaWalletSync answer below still decides, since a present MNEM would answer idempotent.
            val outcome = NativeQaStateHooks.makeKeyOnlyAccount(ctx, syntheticPhrase)
            assertTrue("hook outcome must be OK or ALREADY_PRESENT, was $outcome", outcome == "OK" || outcome == "ALREADY_PRESENT")

            val sync = send(webView, JSONObject()
                .put("type", "pwaWalletSync").put("reqId", 1001).put("eoa", syntheticEoa)
                .put("phrase", syntheticPhrase).put("seq", 1))
            assertEquals("pwaWalletSync ok", true, sync.optBoolean("ok"))
            assertEquals("pwaWalletSync sync", "updated", sync.optJSONObject("result")?.optString("sync"))

            val preread = send(webView, JSONObject().put("type", "nativeMnemonicPreread").put("reqId", 1002).put("seq", 2))
            assertEquals("preread valid", "valid", preread.optJSONObject("result")?.optString("state"))
            assertEquals("preread eoa", syntheticEoa, preread.optJSONObject("result")?.optString("eoa"))

            val child = sendFromChildFrame(webView, JSONObject()
                .put("type", "pwaEmptySignal").put("reqId", 1003).put("seq", 3))
            assertEquals("child frame refused", "untrusted_source", child.optString("error"))
            assertTrue("child frame refusal must be ok:false", child.optBoolean("ok") == false)
        }
    }

    /** Both sides empty (no native record, no PWA phrase): the pre-read answers absent. Must run before any account is written. */
    @Test
    fun bothSidesEmptyPrereadIsAbsent() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            val webView = awaitEmbeddedWebView(scenario)
            assertNotNull("embedded WebView not found", webView)
            // The PWA confirms it holds no phrase first (pwaEmptySignal, trusted main frame); the SDK's pre-read answer is cached from that.
            val empty = send(webView!!, JSONObject().put("type", "pwaEmptySignal").put("reqId", 999).put("seq", 1))
            assertEquals("pwaEmptySignal reply: $empty", true, empty.optBoolean("ok"))
            val preread = send(webView, JSONObject().put("type", "nativeMnemonicPreread").put("reqId", 1000).put("seq", 2))
            assertEquals("preread absent (reply: $preread)", "absent", preread.optJSONObject("result")?.optString("state"))
        }
    }

    /** The embedded page's WebView: its URL is on the app-assets origin. Polls up to 90 s for the bootstrap to load it. */
    private fun awaitEmbeddedWebView(scenario: ActivityScenario<MainActivity>): WebView? {
        val found = AtomicReference<WebView?>(null)
        val deadline = System.currentTimeMillis() + 90_000L
        while (System.currentTimeMillis() < deadline && found.get() == null) {
            scenario.onActivity { activity ->
                found.set(findWebView(activity.window.decorView) { it.url?.startsWith("https://appassets.androidplatform.net") == true })
            }
            if (found.get() == null) Thread.sleep(500)
        }
        return found.get()
    }

    private fun findWebView(root: android.view.View, match: (WebView) -> Boolean): WebView? {
        if (root is WebView && match(root)) return root
        if (root is android.view.ViewGroup) {
            for (i in 0 until root.childCount) {
                findWebView(root.getChildAt(i), match)?.let { return it }
            }
        }
        return null
    }

    /** Sends one request from the main frame and returns the first reply object (ok, result, error). Null on timeout. */
    private fun send(webView: WebView, request: JSONObject): JSONObject {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        instrumentation.runOnMainSync {
            webView.evaluateJavascript(
                "(function(){window.__rb_last=null;window.BeamioShellRecord.onmessage=function(e){window.__rb_last=e.data;};" +
                    "window.BeamioShellRecord.postMessage(${JSONObject.quote(request.toString())});})();",
                null,
            )
        }
        return pollReply(webView, "window.__rb_last") ?: JSONObject().put("error", "no_reply")
    }

    /** Sends one request from a child frame (an iframe of the embedded page); the reply reaches the parent page. */
    private fun sendFromChildFrame(webView: WebView, request: JSONObject): JSONObject {
        val inner = "<script>window.onload=function(){window.BeamioShellRecord.onmessage=function(e){parent.__rb_child=e.data;};" +
            "window.BeamioShellRecord.postMessage(" + JSONObject.quote(request.toString()) + ");};</script>"
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            webView.evaluateJavascript(
                "(function(){window.__rb_child=null;var f=document.createElement('iframe');f.srcdoc=" + JSONObject.quote(inner) +
                    ";document.body.appendChild(f);})();",
                null,
            )
        }
        return pollReply(webView, "window.__rb_child") ?: JSONObject().put("error", "no_reply")
    }

    private fun pollReply(webView: WebView, expr: String): JSONObject? {
        val deadline = System.currentTimeMillis() + 15_000L
        while (System.currentTimeMillis() < deadline) {
            val raw = AtomicReference<String?>(null)
            val latch = java.util.concurrent.CountDownLatch(1)
            InstrumentationRegistry.getInstrumentation().runOnMainSync {
                webView.evaluateJavascript(expr) { value ->
                    raw.set(value)
                    latch.countDown()
                }
            }
            latch.await(5, java.util.concurrent.TimeUnit.SECONDS)
            val text = raw.get()
            if (!text.isNullOrEmpty() && text != "null") {
                // evaluateJavascript returns a JSON-encoded string; decode it, then parse the reply object.
                val inner = runCatching { org.json.JSONTokener(text).nextValue() as? String }.getOrNull() ?: text
                return runCatching { JSONObject(inner) }.getOrNull()
            }
            Thread.sleep(300)
        }
        return null
    }
}
