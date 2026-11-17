package com.beamio.app.net

import android.util.Log
import android.webkit.WebResourceResponse
import java.io.ByteArrayInputStream
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.URI

/**
 * PM 2026-11-17: beamio.app (and www / subdomains) is a third-party parking host. Until the OTA to 0.52.933 has run, no request to it
 * may leave the device with wallet or address data.
 *
 * - WebView (page) requests: [blockedResponse] answers 403 with an empty body; nothing is forwarded.
 * - Native requests (HttpURLConnection, including the chat SDK's default base before init): the process-wide [ProxySelector]
 *   sends a request to a legacy host through a dead loopback proxy, so the connection is refused and nothing reaches beamio.app.
 *   Every other host is delegated to the previously installed selector (or NO_PROXY), so beamio.ca requests are unchanged.
 * - Logs carry only the host and the first path segment. Query strings and later segments (ids) are never logged.
 */
object LegacyBeamioHostGuard {
    /** The legacy parking host and its subdomains. */
    fun isLegacyHost(host: String?): Boolean {
        val h = host?.trim()?.lowercase()?.trimEnd('.') ?: return false
        return h == "beamio.app" || h.endsWith(".beamio.app")
    }

    /** Only the host and the first path segment (an id after it is never logged), never the query. */
    fun logLine(host: String?, path: String?): String {
        val prefix = (path ?: "").split('/').filter { it.isNotEmpty() }.take(1).joinToString("/")
        return "blocked legacy host=${host ?: "?"} path=/${prefix}"
    }

    /**
     * Navigation (main frame or not) to a legacy host that is not mapped to a local asset is cancelled: not loaded and not handed
     * to an external browser. Returns true when the navigation must be cancelled; logs host and first path segment only.
     */
    fun cancelNavigation(host: String?, path: String?, mappedLocally: Boolean): Boolean {
        if (mappedLocally || !isLegacyHost(host)) return false
        logSink(logLine(host, path))
        return true
    }

    /** Pure decision for an external hand-off: an http(s) URL to a legacy host is refused. Other schemes are not decided here. */
    fun isExternalRefused(scheme: String?, host: String?): Boolean {
        val sc = scheme?.lowercase() ?: return false
        return (sc == "http" || sc == "https") && isLegacyHost(host)
    }

    /**
     * Pure decision for an external intent (r9): refused when its data is an http(s) legacy URL, or when its
     * browser fallback URL is one. [fallback] is the raw browser_fallback_url (may be null or blank).
     */
    fun isIntentRefused(dataScheme: String?, dataHost: String?, fallback: String?): Boolean {
        if (isExternalRefused(dataScheme, dataHost)) return true
        val fb = fallback?.trim()?.takeIf { it.isNotEmpty() } ?: return false
        return try {
            val uri = java.net.URI(fb)
            isExternalRefused(uri.scheme, uri.host)
        } catch (_: Exception) {
            false
        }
    }

    /** As [isIntentRefused], logs the block (host and first path segment only). Used by the Activity's startActivity choke point. */
    fun refuseIntent(dataScheme: String?, dataHost: String?, dataPath: String?, fallback: String?): Boolean {
        if (!isIntentRefused(dataScheme, dataHost, fallback)) return false
        val fb = fallback?.trim()?.takeIf { it.isNotEmpty() }
        val fbHost = fb?.let { runCatching { java.net.URI(it).host }.getOrNull() }
        val fbPath = fb?.let { runCatching { java.net.URI(it).path }.getOrNull() }
        if (isExternalRefused(dataScheme, dataHost)) logSink(logLine(dataHost, dataPath))
        else logSink(logLine(fbHost, fbPath))
        return true
    }

    /** As [isExternalRefused], and logs the block (host and first path segment only). */
    fun refuseExternal(scheme: String?, host: String?, path: String?): Boolean {
        if (!isExternalRefused(scheme, host)) return false
        logSink(logLine(host, path))
        return true
    }

    /** Where a block line goes. Logcat in the app; tests replace it. */
    @Volatile
    var logSink: (String) -> Unit = { Log.w(TAG, it) }

    private val deadProxy: Proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", 9))

    /** A 403 with no body for a WebView request to a legacy host. */
    fun blockedResponse(): WebResourceResponse =
        WebResourceResponse(
            "text/plain",
            "utf-8",
            403,
            "Forbidden",
            emptyMap(),
            ByteArrayInputStream(ByteArray(0)),
        )

    /** A selector that routes legacy hosts to the dead proxy and delegates everything else to [delegate]. */
    fun selectorFor(delegate: ProxySelector?): ProxySelector = object : ProxySelector() {
        override fun select(uri: URI?): List<Proxy> {
            if (uri != null && isLegacyHost(uri.host)) {
                logSink(logLine(uri.host, uri.path))
                return listOf(deadProxy)
            }
            return delegate?.select(uri) ?: listOf(Proxy.NO_PROXY)
        }

        override fun connectFailed(uri: URI?, sa: SocketAddress?, ioe: java.io.IOException?) {
            if (uri != null && isLegacyHost(uri.host)) return
            delegate?.connectFailed(uri, sa, ioe)
        }
    }

    /** Installs the guard once per process (idempotent: a second call keeps the first installed selector). */
    @Synchronized
    fun install() {
        val current = ProxySelector.getDefault()
        if (current is GuardSelector) return
        ProxySelector.setDefault(GuardSelector(current))
    }

    private class GuardSelector(delegate: ProxySelector?) : ProxySelector() {
        private val inner = selectorFor(delegate)
        override fun select(uri: URI?): List<Proxy> = inner.select(uri)
        override fun connectFailed(uri: URI?, sa: SocketAddress?, ioe: java.io.IOException?) = inner.connectFailed(uri, sa, ioe)
    }

    private const val TAG = "LegacyBeamioHostGuard"
}
