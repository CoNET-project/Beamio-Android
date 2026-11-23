package com.beamio.app.qa

import android.app.Activity
import android.content.BroadcastReceiver
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView

/**
 * Release and store builds: a no-op with the same calls as the debug write guard (src/debug). It holds no host
 * list, page script, JS interface or probe receiver, so none of that is compiled into a release artifact.
 */
object QaWriteGuard {
    const val isActive: Boolean = false

    fun intercept(request: WebResourceRequest, source: String): WebResourceResponse? = null

    fun nativeWriteAllowed(what: String, host: String?): Boolean = true

    fun sdkCommandAllowed(type: String?): Boolean = true

    fun decorateScript(path: String?, response: WebResourceResponse?): WebResourceResponse? = response

    fun log(text: String) {}

    fun installWebViewHooks(webView: WebView) {}

    fun installNativeHooks(activity: Activity, webViewOf: () -> WebView?): BroadcastReceiver? = null
}
