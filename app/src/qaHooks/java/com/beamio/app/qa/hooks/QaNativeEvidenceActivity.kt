package com.beamio.app.qa.hooks

import android.app.Activity
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import network.conet.chat.BeamioConetChatModule
import network.conet.chat.nativekey.NativeQaHooks
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

/**
 * QA ONLY (PM R591, spec §25.37.4 A5 device evidence). Compiled only with -PchatQaHooks into debug builds; release and store
 * builds never contain this class (checked by scripts/verify-android-no-qa-hooks.sh).
 *
 * The page calls the SDK's QA-only native entry [NativeQaHooks.runCommand] (present only in the QA AAR built with
 * -PchatQaHooks) in process. It does not go through the WebView bridge and declares no capability; the SDK applies its own
 * allowlist, refuses key fields and strips key names from the answer. Each result is shown and logged as a summary only: type, reqId,
 * ok, code or error, and the names of the result fields. Values are never shown or logged, except a shortened address.
 *
 * runCommand swaps the WebView emit out for the call and restores it afterwards: do not drive WebView chat while this page
 * runs a command. It blocks, so it runs on [worker]. The SDK also logs one line per call under tag BeamioNativeQa.
 *
 * adb: `am start -f 0x10008000 -n <pkg>/com.beamio.app.qa.hooks.QaNativeEvidenceActivity --es cmd identityPublic` runs one
 * allowed command on open (NEW_TASK|CLEAR_TASK recreates the page in the same process, so SDK state is kept; a plain repeat
 * `am start` was not delivered to onNewIntent on the test emulator). Without `cmd` nothing runs until a button is pressed.
 */
class QaNativeEvidenceActivity : Activity() {
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private lateinit var out: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(32, 48, 32, 32) }
        col.addView(TextView(this).apply { text = "QA ONLY - native evidence (not for release)"; setTypeface(null, Typeface.BOLD) })
        for (c in COMMANDS) col.addView(Button(this).apply {
            text = c
            isAllCaps = false
            setOnClickListener { run(c) }
        })
        col.addView(Button(this).apply { text = "status"; isAllCaps = false; setOnClickListener { status() } })
        out = TextView(this).apply { setTextIsSelectable(false); typeface = Typeface.MONOSPACE; textSize = 11f }
        col.addView(out)
        setContentView(ScrollView(this).apply { addView(col) })
        fromIntent(intent)
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        fromIntent(intent)
    }

    private fun fromIntent(i: android.content.Intent?) {
        i?.getStringExtra("cmd")?.let { c ->
            when {
                c == "status" -> status()
                // R1601 emulator acceptance only: open the shell's own native import page (the same page the PWA opens), so an
                // isolated test key can be typed in for the data-retention check. Opens nothing when a key already exists.
                c == "openImport" -> show("openImport -> " + com.beamio.app.nativekey.NativeKeyImportRoute.open())
                c in COMMANDS -> run(c)
                else -> show("refused cmd (not allowed)")
            }
        }
    }

    private fun run(type: String) {
        val reqId = REQ.incrementAndGet()
        val body = JSONObject().put("type", type).put("reqId", reqId)
        show("-> $type reqId=$reqId")
        worker.execute {
            try {
                show("<- " + summary(NativeQaHooks.runCommand(applicationContext, type, body, 15_000L)))
            } catch (e: Exception) {
                show("!! $type ${e.javaClass.simpleName}")
            }
        }
    }

    private fun status() = worker.execute {
        show("status running=${BeamioConetChatModule.isRunning()} nativeSessionReady=${BeamioConetChatModule.isNativeSessionReady()}")
    }

    private fun show(line: String) {
        Log.i(TAG, line.take(300))
        main.post { out.append(line.take(300) + "\n") }
    }

    override fun onDestroy() {
        worker.shutdown()
        super.onDestroy()
    }

    companion object {
        const val TAG = "BeamioQaEvidence"
        private val REQ = AtomicInteger(900_000_000)

        /**
         * PM-approved A5 commands (R603) that the SDK's QA entry also allows (pgpRestoreEvaluate from SDK ab1ed76, read-only:
         * evaluate before pgpRestore). init and provisionIdentity are in the SDK allowlist but not approved here; import and
         * recovery are not offered.
         */
        val COMMANDS = listOf("walletStatus", "identityPublic", "pgpRestoreEvaluate", "pgpRestore")

        private val ADDR = Regex("0x[0-9a-fA-F]{40}")

        /** type, reqId, ok, code/error/sub and field names only; nested field names one level down; addresses shortened. */
        fun summary(outer: JSONObject): String {
            // The SDK wraps page events as {action, event}; summarise the inner event.
            val inner = outer.optJSONObject("event")
            val ev = inner ?: outer
            val sb = StringBuilder()
            if (inner != null) sb.append("action=").append(outer.optString("action")).append(' ')
            sb.append("type=").append(ev.optString("type")).append(" reqId=").append(ev.opt("reqId"))
            if (ev.has("ok")) sb.append(" ok=").append(ev.optBoolean("ok"))
            if (ev.optBoolean("qaRefusal")) sb.append(" qaRefusal=true")
            for (k in listOf("code", "error", "sub", "state", "status")) {
                val v = ev.opt(k)
                if (v is String && v.length <= 40 && !v.contains(' ')) sb.append(' ').append(k).append('=').append(v)
            }
            val result = ev.opt("result")
            when (result) {
                is JSONObject -> {
                    sb.append(" result.keys=").append(keys(result))
                    for (k in listOf("code", "sub", "state", "status")) {
                        val v = result.opt(k)
                        if (v is String && v.length <= 40 && !v.contains(' ')) sb.append(" result.").append(k).append('=').append(v)
                    }
                    (result.opt("eoa") as? String)?.let { if (ADDR.matches(it)) sb.append(" result.eoa=").append(short(it)) }
                }
                is JSONArray -> sb.append(" result=array(").append(result.length()).append(')')
                null -> {}
                else -> sb.append(" result=").append(result.javaClass.simpleName)
            }
            sb.append(" keys=").append(keys(ev))
            return ADDR.replace(sb.toString()) { short(it.value) }
        }

        private fun keys(o: JSONObject): String = o.keys().asSequence().toList().sorted().joinToString(",", "[", "]")
        private fun short(a: String) = a.take(6) + "…" + a.takeLast(4)
    }
}
