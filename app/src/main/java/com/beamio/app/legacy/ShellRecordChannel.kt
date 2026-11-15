package com.beamio.app.legacy

import android.content.Context
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.webkit.WebView
import androidx.webkit.JavaScriptReplyProxy
import androidx.webkit.WebMessageCompat
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import com.beamio.app.BuildConfig
import android.os.SystemClock
import com.beamio.app.credential.ShellCredentialTrust
import com.beamio.app.credential.WalletCredentialGate
import java.io.File
import java.util.concurrent.Executors

/**
 * Plan N wiring (spec r3ay §25.52D.5, §25.52D.9). In every build with BuildConfig.PLAN_N (release and store always,
 * debug unless -PplanN=false).
 *
 * - Startup: [start] runs before the WebView exists (copy P, then initialisation and PGP migration on a worker).
 * - Channel: `window.BeamioShellRecord` via [WebViewCompat.addWebMessageListener], allowed origin
 *   `https://appassets.androidplatform.net`, main frame only. Not `addJavascriptInterface`.
 *   Page: `BeamioShellRecord.postMessage(JSON.stringify({type, reqId, record?}))`; reply arrives on
 *   `BeamioShellRecord.onmessage` as a JSON string `{reqId, code, …}`.
 */
object ShellRecordChannel {
    const val JS_NAME = "BeamioShellRecord"
    /** AX.1 envelope for a message the shell cannot parse: exactly one answer, reqId null, nothing echoed. */
    const val BAD_REQUEST = "{\"type\":\"ack\",\"reqId\":null,\"ok\":false,\"error\":\"bad_request\"}"
    const val ORIGIN = "https://appassets.androidplatform.net"
    private const val TAG = "BeamioShellRecord"

    /** PM R675 / spec r3cx §25.52AZ.4: release builds inject the channel; the switch is PLAN_N only. */
    val enabled: Boolean = BuildConfig.PLAN_N

    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    val state = ShellRecordState()

    fun log(s: String) = Log.i(TAG, s.take(200))

    /**
     * Call before the first WebView is created. R389: the page record (store and bridge) belongs to the Android SDK;
     * the shell only copies P, reads the legacy PGP and hands it to the SDK's run(source). The shell-side store, bridge
     * and cipher stay in this package as local reference code for the SDK and are not wired.
     */
    fun start(context: Context, runner: PgpMigrationRunner) {
        if (!enabled || started) return
        started = true
        val app = context.applicationContext
        val init = ShellRecordInit(
            webviewIdbDir = File(app.dataDir, "app_webview/Default/IndexedDB/https_appassets.androidplatform.net_0.indexeddb.leveldb"),
            tempDir = File(app.noBackupFilesDir, "plan-n-p-copy"),
            store = null, state = state, runner = runner, log = ::log, importer = PageRecordImporter.Unavailable,
            firstRun = FirstRunImporters.current,
            firstRunDone = File(app.noBackupFilesDir, "plan-n/first-run-done"),
        )
        try { init.prepare() } catch (e: Exception) { log("prepare failed ${e.javaClass.simpleName}") }
        worker.execute { try { init.run() } catch (e: Exception) { log("init failed ${e.javaClass.simpleName}"); state.migrating = false } }
    }

    @Volatile private var started = false

    /**
     * The origin-limited channel for the SDK page bridge (spec §25.52D.5; SDK refuses shellRecord* on the generic bridge).
     * `window.BeamioShellRecord.postMessage(JSON)`; the reply is the SDK's JSON on `onmessage`. Every reply passes the exit
     * assertion (PGP private fields or header → refused, counts only in the log).
     */
    fun attach(webView: WebView) {
        if (!enabled) return
        val handler = PageBridgeHandlers.current ?: run { log("channel not attached: no SDK page bridge"); return }
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) { log("channel unavailable (WEB_MESSAGE_LISTENER)"); return }
        WebViewCompat.addWebMessageListener(webView, JS_NAME, setOf(ORIGIN)) { _: WebView, message: WebMessageCompat, sourceOrigin: Uri, isMainFrame: Boolean, reply: JavaScriptReplyProxy ->
            // Spec r3cv §25.52AX.1: a message the channel cannot use gets exactly one answer, nothing reaches the SDK.
            val data = message.data ?: run { reply.postMessage(BAD_REQUEST); return@addWebMessageListener }
            val embedded = isMainFrame && sourceOrigin.toString().trimEnd('/') == ORIGIN
            val size = data.toByteArray(Charsets.UTF_8).size
            val origin = sourceOrigin.toString()
            worker.execute {
                val started = SystemClock.elapsedRealtime()
                // Unparsable JSON never reaches the SDK (AX.1); unknown types and bad reqIds are answered by the SDK handler.
                val body = runCatching { org.json.JSONObject(data) }.getOrNull()
                val parsed = body != null
                var out = if (!parsed) BAD_REQUEST
                else if (body!!.optString("type") in WalletCredentialGate.GATED_COMMANDS) {
                    // PM R1911: walletEoaAddress (and later walletCredential) is answered by the SDK on this window channel.
                    // Shell gate before and after the SDK call; logs: names, verdict, code, ms only (log points 1-3).
                    val w = WalletCredentialGate.windowCredential(
                        body,
                        verdict = {
                            ShellCredentialTrust.verdict(
                                WalletCredentialGate.Channel.WEB_MESSAGE, isMainFrame, origin,
                                requireCapability = WalletCredentialGate.requiresCapability(body.optString("type")),
                            )
                        },
                        sdk = { handler.handle(embedded, data, size) },
                        clock = { SystemClock.elapsedRealtime() },
                    )
                    w.logs.forEach { log(it) }
                    w.reply
                }
                else try { handler.handle(embedded, data, size) } catch (e: Exception) { ShellRecordReplies.fallback(data) }
                val hits = LegacyRecord.pgpPrivateHits(out.toCharArray())
                if (hits != 0) { log("channel exit assert FAIL pgpPrivateHits=$hits"); out = ShellRecordReplies.fallback(data) }
                else log("channel exit assert pass")
                // Spec r3nq §25.52Y.41: W fields (privateKeyArmor, mnemonicPhrase, recoveryWords) leave only behind the
                // trust gate (origin, main frame, verified bundle); otherwise the whole reply is not_trusted. This round no
                // capability check (r3nt §25.52Y.43 item 6 (i), PM R1863). Logs: names, verdict, code, ms only.
                val gated = try {
                    WalletCredentialGate.gateShellRecordRead(data, out) {
                        ShellCredentialTrust.verdict(WalletCredentialGate.Channel.WEB_MESSAGE, isMainFrame, origin, requireCapability = false)
                    }
                } catch (e: Exception) {
                    log(WalletCredentialGate.errorLine(WalletCredentialGate.SHELL_RECORD_READ, ShellRecordReplies.validReqId(data), e)) // log point 3
                    WalletCredentialGate.ShellRecordGateResult(WalletCredentialGate.shellRecordRefusal(ShellRecordReplies.validReqId(data)), null, emptyList())
                }
                out = gated.reply
                gated.verdict?.let { v ->
                    log(WalletCredentialGate.entryLine(WalletCredentialGate.SHELL_RECORD_READ, ShellRecordReplies.validReqId(data), v)) // log point 1
                    val ev = runCatching { org.json.JSONObject(out) }.getOrNull() ?: org.json.JSONObject()
                    log(WalletCredentialGate.replyLine(WalletCredentialGate.SHELL_RECORD_READ, ev, SystemClock.elapsedRealtime() - started, gated.wFields)) // log point 2
                }
                main.post { runCatching { reply.postMessage(out) } }
            }
        }
        log("channel attached (SDK page bridge)")
    }
}

/** Shell-side window-channel replies (kept outside [ShellRecordChannel] so JVM tests need no Android classes). */
internal object ShellRecordReplies {
    /**
     * Spec r3ef §25.52CF: the shell's answer when the SDK handler throws or its reply fails the exit assertion. Exactly one,
     * the request's reqId echoed, no rev, record, exception text or content.
     * - shellRecordRead:  {type:"ack", reqId, ok:false, error:"record_unreadable"} (r3ok §25.52D.6 note: an `error` + X code is
     *   envelope-level, never in result.code)
     * - shellRecordWrite: {type:"ack", reqId, ok:true, result:{code:"write_failed"}} (the page reads rev back before retrying)
     * - an invalid reqId never takes the fallback: {type:"ack", reqId:null, ok:false, error:"bad_request"}
     * - any other type: {type:"ack", reqId, ok:false, error:"unknown_command"} (AU.1)
     */
    fun fallback(data: String): String {
        val obj = runCatching { org.json.JSONObject(data) }.getOrNull()
        val reqId = obj?.let { validReqId(it) } ?: return envelope(null, "bad_request")
        return when (obj.optString("type")) {
            "shellRecordRead" -> envelope(reqId, "record_unreadable")
            "shellRecordWrite" -> ack(reqId).put("ok", true).put("result", org.json.JSONObject().put("code", "write_failed")).toString()
            else -> envelope(reqId, "unknown_command")
        }
    }

    /** The request's reqId if it is valid per §25.52AW.1, else null. */
    fun validReqId(data: String): Any? = com.beamio.app.BridgeReqId.fromJsonText(data)

    private fun validReqId(obj: org.json.JSONObject): Any? = com.beamio.app.BridgeReqId.valid(obj.opt("reqId"))

    private fun ack(reqId: Any?): org.json.JSONObject = org.json.JSONObject().put("type", "ack").put("reqId", reqId ?: org.json.JSONObject.NULL)

    private fun envelope(reqId: Any?, error: String): String = ack(reqId).put("ok", false).put("error", error).toString()
}
