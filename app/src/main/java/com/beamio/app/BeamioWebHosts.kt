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

    // NFC/SUN links are blocked by BeamioNfcSunBlock (a block list, both domains), not by this allow list.
}
