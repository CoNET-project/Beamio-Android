package com.beamio.app.legacy

import android.content.Context
import android.util.Log
import network.conet.chat.nativekey.LegacyStoreReport
import java.io.File

/**
 * Start-up report of the legacy store (E9.11.29 r2 / E9.11.31 r3-amend1): the shell tells the SDK what it found in the OLD PWA origin
 * directory, before the first WebView loads. The current PWA's own origin (https_appassets…) never counts.
 *
 * Verified on a debug build (2026-11-17, synthetic IndexedDB, no network): the old origin directory is
 * `https_beamio.app_0.indexeddb.leveldb`; the current origin is `https_appassets.androidplatform.net_0.indexeddb.leveldb`.
 *
 * Rules: no old-origin directory → absent. An old-origin directory exists → unreadable (no reader is validated for `found` yet, so
 * `found` is never reported). Only the SDK's `reportLegacyStore` writes the report; this shell imports nothing.
 */
object LegacyStoreReportShell {
    const val OLD_ORIGIN_DIR = "https_beamio.app_0.indexeddb.leveldb"
    private const val TAG = "LegacyStoreReport"

    /** The value to report for the WebView data directory [webviewRoot] (the app_webview folder). Pure for the JVM tests. */
    fun valueFor(webviewRoot: File): String =
        if (File(webviewRoot, "Default/IndexedDB/$OLD_ORIGIN_DIR").exists()) LegacyStoreReport.UNREADABLE else LegacyStoreReport.ABSENT

    /**
     * Runs the report on a background thread and waits for it (bounded), so the report is written before any WebView loads. A failure
     * or timeout is logged by type only; it never blocks start-up for longer than [timeoutMs].
     */
    fun reportBeforeWebView(context: Context, timeoutMs: Long = 3_000L) {
        val app = context.applicationContext
        val worker = Thread({
            try {
                val value = valueFor(File(app.dataDir, "app_webview"))
                val code = LegacyStoreReport.reportLegacyStore(app, value)
                Log.i(TAG, "reportLegacyStore value=$value code=$code")
            } catch (e: Exception) {
                Log.w(TAG, "reportLegacyStore failed: ${e.javaClass.simpleName}")
            }
        }, "legacy-store-report")
        worker.start()
        worker.join(timeoutMs)
        if (worker.isAlive) Log.w(TAG, "reportLegacyStore still running after ${timeoutMs}ms; the WebView is not held back further")
    }
}
