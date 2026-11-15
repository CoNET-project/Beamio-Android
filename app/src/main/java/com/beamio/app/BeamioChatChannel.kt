package com.beamio.app

import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.webkit.WebView
import androidx.webkit.JavaScriptReplyProxy
import androidx.webkit.WebMessageCompat
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import org.json.JSONObject

/**
 * `window.BeamioChat` (PM R756/R763 scheme 1; spec r3er §25.52AA.10): the chat-module
 * channel with origin and main-frame checks. WebViewCompat.addWebMessageListener with the only allowed origin
 * https://appassets.androidplatform.net.
 *
 * Page -> shell: `BeamioChat.postMessage(JSON.stringify(cmd))`, cmd as for CashTreesAndroid.chatModuleCommand
 * (`{type, reqId, ...}`); a sign answer is `{type:"chatModuleSignResponse", reqId, ok, signature?, error?}`.
 * Shell -> page: `BeamioChat.onmessage` receives JSON strings equal to the cashtreesandroid event detail
 * (`{action:"chatModuleEvent", event}` / `{action:"chatModuleSignRequest", ...}`).
 * Order: origin and main frame, then JSON, then reqId (inside the shared command path). Each refusal is answered once.
 * A message that is not a string (spec r3et §25.52CT.5) counts as malformed JSON: bad_request with reqId null.
 * The legacy CashTreesAndroid.chatModuleCommand stays (top-level origin gate) until the page has switched.
 */
object BeamioChatChannel {
    const val JS_NAME = "BeamioChat"
    const val SIGN_RESPONSE = "chatModuleSignResponse"

    private val main by lazy { Handler(Looper.getMainLooper()) }

    fun attach(webView: WebView, onCommand: (String, (JSONObject) -> Unit) -> Unit, onSignResponse: (String) -> Unit) {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) return
        WebViewCompat.addWebMessageListener(webView, JS_NAME, setOf(ChatOriginGate.TRUSTED)) { _: WebView, message: WebMessageCompat, sourceOrigin: Uri, isMainFrame: Boolean, reply: JavaScriptReplyProxy ->
            // AA.10 / CT.5: every page message is a JSON string; anything else (an ArrayBuffer) is malformed -> bad_request.
            val data = if (message.type == WebMessageCompat.TYPE_STRING) runCatching { message.data }.getOrNull() else null
            val own: (String) -> Unit = { s -> main.post { runCatching { reply.postMessage(s) } } }
            when (val d = decide(data, sourceOrigin.toString(), isMainFrame)) {
                // A refusal goes back to the frame that sent it and never becomes the event target.
                is Decision.Answer -> own(JSONObject().put("action", "chatModuleEvent").put("event", d.event).toString())
                is Decision.Sign -> { latest = reply; onSignResponse(d.json) }
                is Decision.Command -> {
                    // AA.10: SDK events (acks and async events) go to the most recent main-frame reply proxy; after a
                    // reload the new page's first message takes over.
                    latest = reply
                    onCommand(d.json) { payload -> toLatest(payload.toString()) }
                }
            }
        }
    }

    /** The reply proxy of the most recent accepted main-frame message (AA.10 async event target). */
    @Volatile private var latest: JavaScriptReplyProxy? = null

    private fun toLatest(s: String) { main.post { runCatching { latest?.postMessage(s) } } }

    sealed class Decision {
        /** The shell answers by itself (origin_refused or bad_request) and nothing reaches the SDK. */
        class Answer(val event: JSONObject) : Decision()
        class Sign(val json: String) : Decision()
        class Command(val json: String) : Decision()
    }

    /** Pure decision, testable on the JVM: origin and main frame first, then JSON; reqId is checked in the command path. */
    fun decide(data: String?, sourceOrigin: String, isMainFrame: Boolean): Decision {
        val origin = ChatOriginGate.originOf(sourceOrigin) ?: sourceOrigin.trimEnd('/')
        if (!isMainFrame || origin != ChatOriginGate.TRUSTED) {
            return Decision.Answer(ack(data?.let { BridgeReqId.fromJsonText(it) }, ChatOriginGate.ERROR))
        }
        val body = data?.let { runCatching { JSONObject(it) }.getOrNull() } ?: return Decision.Answer(ack(null, "bad_request"))
        return if (body.optString("type") == SIGN_RESPONSE) Decision.Sign(data) else Decision.Command(data)
    }

    private fun ack(reqId: Any?, error: String): JSONObject =
        JSONObject().put("type", "ack").put("reqId", reqId ?: JSONObject.NULL).put("ok", false).put("error", error)
}
