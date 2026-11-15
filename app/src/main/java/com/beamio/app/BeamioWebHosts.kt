package com.beamio.app

/**
 * Beamio website hosts (PM R1626/R1637, owner-authorized move beamio.app → beamio.ca, 2026-11-15).
 *
 * Exact host names only, no wildcard. Network calls from the shell go to [CANONICAL] and nowhere else.
 * Local data does not depend on these hosts: the embedded page origin is https://appassets.androidplatform.net
 * and the native wallet lives under files/native_wallet_v1.
 */
object BeamioWebHosts {
    const val CANONICAL = "beamio.ca"
    const val CANONICAL_ORIGIN = "https://$CANONICAL"

    /** Exact hosts whose `/app/…` links open the embedded app (mapped to the local bundle). */
    val WEB_HOSTS: Set<String> = setOf("beamio.ca", "www.beamio.ca")

    fun isWebHost(host: String?): Boolean = host?.lowercase() in WEB_HOSTS

    /** The chat SDK's API base on the live domain (PM R2040). */
    const val CHAT_API_BASE = "$CANONICAL_ORIGIN/api"

    /**
     * PM R2040: the chat SDK (0.2.16-r1841qa) defaults `apiBaseUrl` to https://beamio.app/api and keeps it when an `init`
     * payload has none. The value to put into a page `init` so the SDK never falls back to the old domain: the live base
     * when the field is missing or blank, or the same URL moved to beamio.ca / www.beamio.ca when it names beamio.app /
     * www.beamio.app; null when the given value stays as it is.
     */
    fun chatApiBaseFor(raw: String?): String? {
        val v = raw?.trim().orEmpty()
        if (v.isEmpty()) return CHAT_API_BASE
        val u = runCatching { java.net.URI(v) }.getOrNull() ?: return null
        val moved = when (u.host?.lowercase()) {
            "beamio.app" -> "beamio.ca"
            "www.beamio.app" -> "www.beamio.ca"
            else -> return null
        }
        return java.net.URI("https", null, moved, -1, u.rawPath?.takeIf { it.isNotEmpty() } ?: "/api", null, null).toString()
    }

    // NFC/SUN links are blocked by BeamioNfcSunBlock (a block list, both domains), not by this allow list.
}
