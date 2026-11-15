package com.beamio.app

import android.os.Handler
import android.os.Looper

/**
 * Views may only be changed on the main thread. Telecom, FCM and the WebView
 * bridge call into the incoming window from their own threads (Samsung
 * 1.0.161: an FCM push for a call the page had just reported changed the
 * window's title on the Firebase-Messaging thread and the app crashed).
 * [run] runs the block now on the main thread, else posts it there.
 */
internal object BeamioUiThread {
    /** Replaced in unit tests (no Looper on the JVM). */
    @Volatile
    internal var isMainThread: () -> Boolean = { Looper.myLooper() == Looper.getMainLooper() }

    @Volatile
    internal var postToMain: (Runnable) -> Unit = { Handler(Looper.getMainLooper()).post(it) }

    fun run(block: () -> Unit) {
        if (isMainThread()) block() else postToMain(Runnable(block))
    }
}
