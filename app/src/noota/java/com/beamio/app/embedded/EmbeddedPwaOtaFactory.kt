package com.beamio.app.embedded

import org.json.JSONObject

/**
 * Store build type: no remote PWA update code is compiled. There is never a daemon, no capability
 * bit and no update-available event (ota-pwa-protocol.md section 1).
 */
object EmbeddedPwaOtaFactory {
    @Suppress("UNUSED_PARAMETER")
    fun create(
        bundleStore: EmbeddedPwaBundleStore,
        onUpdateAvailable: (currentVer: String, pendingVer: String) -> Unit,
        remotePwaUpdate: Boolean,
    ): EmbeddedPwaOtaDaemon? = null

    fun capabilityScript(): String? = null

    @Suppress("UNUSED_PARAMETER")
    fun updateAvailableEvent(currentVer: String, pendingVer: String): JSONObject? = null
}
