package com.beamio.app.search

import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.net.URLEncoder

/**
 * The native search-users lookup (caller tag by wallet address). Per the PM 2026-11-17 ruling (same as iOS 105):
 * - the request goes to https://beamio.ca/api/search-users only (never beamio.app, which resolves to a parking host);
 * - automatic redirects are off; one redirect is followed only when it is an absolute https URL on exactly beamio.ca;
 *   any other redirect (foreign host, http, relative, missing Location) is refused and not requested;
 * - non-2xx, no data, timeouts and transport errors answer null and never throw to the caller.
 * This applies to this request only; no global redirect or client setting changes.
 */
object SearchUsersLookup {
    const val ALLOWED_HOST = "beamio.ca"
    private const val ENDPOINT = "https://beamio.ca/api/search-users"
    const val DEFAULT_CONNECT_MS = 10_000
    const val DEFAULT_READ_MS = 12_000

    /** One HTTP answer. [location] is the Location header of a redirect, [body] the text of a 2xx answer. */
    data class Response(val code: Int, val location: String?, val body: String?)

    /** Performs one GET without following redirects. Tests replace it with a fake. */
    fun interface Transport {
        fun get(url: String, connectTimeoutMs: Int, readTimeoutMs: Int): Response
    }

    val httpUrlTransport: Transport = Transport { url, connectTimeoutMs, readTimeoutMs ->
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            instanceFollowRedirects = false
            connectTimeout = connectTimeoutMs
            readTimeout = readTimeoutMs
        }
        try {
            val code = conn.responseCode
            val location = conn.getHeaderField("Location")
            val body = if (code in 200..299) {
                conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            } else {
                null
            }
            Response(code, location, body)
        } finally {
            conn.disconnect()
        }
    }

    /** The absolute target of a redirect when it is https on exactly beamio.ca, else null (refused). */
    fun allowedRedirectTarget(location: String?): String? {
        val raw = location?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        return try {
            val uri = URI(raw)
            if (!uri.isAbsolute) return null
            if (!uri.scheme.equals("https", ignoreCase = true)) return null
            if (!uri.host.equals(ALLOWED_HOST, ignoreCase = true)) return null
            if (uri.userInfo != null) return null
            if (uri.port != -1 && uri.port != 443) return null
            raw
        } catch (_: Exception) {
            null
        }
    }

    /**
     * The search-users body for [keyward] (a wallet address), or null. At most two requests: the first, and one allowed redirect.
     */
    fun fetchBody(
        keyward: String,
        connectTimeoutMs: Int = DEFAULT_CONNECT_MS,
        readTimeoutMs: Int = DEFAULT_READ_MS,
        transport: Transport = httpUrlTransport,
    ): String? {
        val url = "$ENDPOINT?keyward=${URLEncoder.encode(keyward, Charsets.UTF_8.name())}"
        return try {
            val first = transport.get(url, connectTimeoutMs, readTimeoutMs)
            when (first.code) {
                in 200..299 -> first.body
                in 300..399 -> {
                    val target = allowedRedirectTarget(first.location) ?: return null
                    val second = transport.get(target, connectTimeoutMs, readTimeoutMs)
                    if (second.code in 200..299) second.body else null
                }
                else -> null
            }
        } catch (_: Exception) {
            null
        }
    }
}
