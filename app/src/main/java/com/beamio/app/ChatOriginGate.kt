package com.beamio.app

/**
 * Spec r3ej §25.52CJ.3 / r3em CM.3 (scheme 2): before chatModuleCommand reaches the SDK, the shell checks
 * that the top-level page of the embedded WebView is the trusted origin. JavascriptInterface calls carry no origin, so
 * the shell records the top-level URL's origin on onPageStarted/onPageFinished and compares it here.
 * Limit: a frame of another origin inside a trusted top-level page cannot be told apart (scheme 1, a WebMessageListener
 * channel with origin and main-frame checks, is the formal fix).
 */
object ChatOriginGate {
    const val TRUSTED = "https://appassets.androidplatform.net"
    const val ERROR = "origin_refused"

    /** `scheme://host[:port]` in lower case, or null when the URL has no usable scheme and host. */
    fun originOf(url: String?): String? {
        if (url.isNullOrBlank()) return null
        val u = runCatching { java.net.URI(url.trim()) }.getOrNull() ?: return null
        val scheme = u.scheme?.lowercase() ?: return null
        val host = u.host?.lowercase() ?: return null
        if (u.rawUserInfo != null) return null
        val port = if (u.port == -1) "" else ":" + u.port
        return "$scheme://$host$port"
    }

    fun allowed(topOrigin: String?): Boolean = topOrigin == TRUSTED
}
