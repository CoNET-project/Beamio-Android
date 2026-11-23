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
 * `window.BeamioShell` (spec §25.22.1, §25.52CT.4, §25.52CV.2; message format proposed by the
 * Android shell, to be written into the spec): the sensitive CashTreesAndroid methods (keys, identity, files, external
 * links, payment, camera, microphone) moved off addJavascriptInterface onto WebViewCompat.addWebMessageListener with the
 * only allowed origin https://appassets.androidplatform.net, main frame only. Same mechanism as window.BeamioChat
 * (§25.52AA.10).
 *
 * Page -> shell: `BeamioShell.postMessage(JSON.stringify({action, reqId, args?}))`. `action` is the old method name;
 * `args` is an object carrying what the old method took (see [ACTIONS]); reqId follows §25.52AW.1.
 * Shell -> page: `BeamioShell.onmessage` receives exactly one JSON string per message,
 * `{type:"ack", action, reqId, ok, result?, error?}`. Results that the old methods sent later as `cashtreesandroid`
 * events (scan results, file saved, ciphertext posted, call events) still arrive that way, on the main frame only.
 *
 * Order: origin and main frame, then string and JSON, then reqId, then action, then args. Each refusal is answered once:
 * - other origin or not the main frame: `origin_refused` (reqId echoed when valid, else null);
 * - not a string, or not a JSON object: `bad_request`, reqId null;
 * - invalid reqId: `bad_request`, reqId null;
 * - unknown action: `unknown_command`;
 * - args present but not an object, or a required field missing: `bad_args`.
 */
object BeamioShellChannel {
    const val JS_NAME = "BeamioShell"

    /** How an action's `args` map onto the old method's single String parameter. */
    enum class Arg {
        /** The old method took a JSON object text: `args` (or `{}`) is passed as that text. */
        JSON,
        /** The old method took a URL: `args.url` (string, required). */
        URL,
        /** The old method took a request id: `args.requestId` (string, may be empty). */
        REQUEST_ID,
        /** The old method took nothing. */
        NONE,
    }

    val ACTIONS: Map<String, Arg> = linkedMapOf(
        // external links, payment
        "openURL" to Arg.URL,
        "openInAppBrowser" to Arg.JSON, // {url, requestId?}
        "queryInstalledApps" to Arg.JSON,
        "listInstalledWalletApps" to Arg.JSON,
        "scanQr" to Arg.REQUEST_ID,
        // files, camera
        "saveFile" to Arg.JSON,
        "requestCameraCapture" to Arg.JSON,
        // identity
        "bindPushIdentity" to Arg.JSON,
        "postPgpCiphertext" to Arg.JSON,
        "setNativeSiNodeRoster" to Arg.JSON,
        "setNativeVoiceRelayNodes" to Arg.JSON,
        "cacheCallerAvatars" to Arg.JSON,
        // system calls
        "prepareSystemCall" to Arg.JSON,
        "cancelPreparedSystemCall" to Arg.JSON,
        "startSystemCall" to Arg.JSON,
        "reportIncomingSystemCall" to Arg.JSON,
        "endSystemCall" to Arg.JSON,
        "nativeIdentityCheck" to Arg.JSON,
        "uiLockState" to Arg.JSON,
        "incomingCallUnlockShown" to Arg.JSON,
        "dismissIncomingSystemCall" to Arg.JSON,
        // call metadata and audio routing
        "queryIncomingCallOutcome" to Arg.JSON,
        "notifyVoiceMicReady" to Arg.JSON,
        // microphone
        "startNativeVoiceMic" to Arg.NONE,
        "stopNativeVoiceMic" to Arg.NONE,
    )

    private val main by lazy { Handler(Looper.getMainLooper()) }

    /** Off-main work for the no-key gate (SDK vault reads). One thread, in arrival order. */
    private val gateExecutor: java.util.concurrent.ExecutorService by lazy {
        java.util.concurrent.Executors.newSingleThreadExecutor { r -> Thread(r, "beamio-shell-gate").apply { isDaemon = true } }
    }

    /** The no-key gate answer for [action], or null. Passed to [attach]'s callback so the callback needs no SDK read on main. */
    var gateFor: (String) -> String? = { _ -> null }

    /** [onCall] runs on the main thread with the gate answer computed off it, and returns the ack to send. */
    fun attach(webView: WebView, onCall: (Decision.Call, String?) -> JSONObject) {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) return
        WebViewCompat.addWebMessageListener(webView, JS_NAME, setOf(ChatOriginGate.TRUSTED)) { _: WebView, message: WebMessageCompat, sourceOrigin: Uri, isMainFrame: Boolean, reply: JavaScriptReplyProxy ->
            val data = if (message.type == WebMessageCompat.TYPE_STRING) runCatching { message.data }.getOrNull() else null
            val post: (JSONObject) -> Unit = { o -> main.post { runCatching { reply.postMessage(o.toString()) } } }
            when (val d = decide(data, sourceOrigin.toString(), isMainFrame)) {
                is Decision.Answer -> post(d.ack)
                is Decision.Call -> {
                    // ANR fix (S25 176, 2026-11-17): the no-key gate reads the SDK vault (keystore). It is computed off the main thread;
                    // the call itself still runs on main, with the gate result passed in. A failed read stays internal_error.
                    gateExecutor.execute {
                        val gate = runCatching { gateFor(d.action) }
                        main.post {
                            val ack = runCatching { onCall(d, gate.getOrThrow()) }.getOrElse { ack(d.action, d.reqId).put("ok", false).put("error", "internal_error") }
                            runCatching { reply.postMessage(ack.toString()) }
                        }
                    }
                }
            }
        }
    }

    sealed class Decision {
        class Answer(val ack: JSONObject) : Decision()
        /** [arg] is the String the old method took (JSON text, URL or request id); empty for [Arg.NONE]. */
        class Call(val action: String, val reqId: Any, val kind: Arg, val arg: String, val args: JSONObject) : Decision()
    }

    fun ack(action: String?, reqId: Any?): JSONObject =
        JSONObject().put("type", "ack").put("action", action ?: JSONObject.NULL).put("reqId", reqId ?: JSONObject.NULL)

    private fun refuse(action: String?, reqId: Any?, error: String) = Decision.Answer(ack(action, reqId).put("ok", false).put("error", error))

    /** Pure decision, testable on the JVM. */
    fun decide(data: String?, sourceOrigin: String, isMainFrame: Boolean): Decision {
        val origin = ChatOriginGate.originOf(sourceOrigin) ?: sourceOrigin.trimEnd('/')
        if (!isMainFrame || origin != ChatOriginGate.TRUSTED) {
            return refuse(null, data?.let { BridgeReqId.fromJsonText(it) }, ChatOriginGate.ERROR)
        }
        val body = data?.let { runCatching { JSONObject(it) }.getOrNull() } ?: return refuse(null, null, "bad_request")
        val reqId = BridgeReqId.valid(body.opt("reqId")) ?: return refuse(null, null, "bad_request")
        val action = body.opt("action") as? String
        val kind = action?.let { ACTIONS[it] } ?: return refuse(action, reqId, "unknown_command")
        val rawArgs = body.opt("args")
        val args = when (rawArgs) {
            null, JSONObject.NULL -> JSONObject()
            is JSONObject -> rawArgs
            else -> return refuse(action, reqId, "bad_args")
        }
        val arg = when (kind) {
            Arg.JSON -> args.toString()
            Arg.URL -> (args.opt("url") as? String)?.takeIf { it.isNotEmpty() } ?: return refuse(action, reqId, "bad_args")
            Arg.REQUEST_ID -> (args.opt("requestId") as? String) ?: ""
            Arg.NONE -> ""
        }
        return Decision.Call(action, reqId, kind, arg, args)
    }
}
