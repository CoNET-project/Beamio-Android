package com.beamio.app.embedded

import com.beamio.app.BuildConfig
import org.json.JSONObject

/**
 * Non-store build types: the remote PWA update daemon is compiled in (it still runs only when enabled).
 * Everything the page can see of the update path (capability bit, update-available event) lives
 * here, so the store build type has none of it (scripts/verify-android-store-no-ota.sh).
 */
object EmbeddedPwaOtaFactory {
    /** Capability name agreed with the PWA and the iOS shell (ota-pwa-protocol.md section 8). */
    const val OTA_CAPABILITY = "pwa.embedded-ota.v1"

    fun create(
        bundleStore: EmbeddedPwaBundleStore,
        onUpdateAvailable: (currentVer: String, pendingVer: String) -> Unit,
        remotePwaUpdate: Boolean,
    ): EmbeddedPwaOtaDaemon? = EmbeddedPwaUpdateDaemon(
        bundleStore,
        onUpdateAvailable,
        remotePwaUpdate,
        manifestUrl = BuildConfig.OTA_MANIFEST_URL.ifBlank { EmbeddedPwaOtaConstants.REMOTE_UPDATE_MANIFEST },
        bundleBaseUrl = BuildConfig.OTA_BUNDLE_BASE.ifBlank { EmbeddedPwaOtaConstants.REMOTE_BUNDLE_BASE },
        checkIntervalMs = BuildConfig.OTA_CHECK_INTERVAL_MS.takeIf { it > 0 } ?: 15L * 60L * 1000L,
    )

    /** Document-start script declaring `window.__CT_ANDROID_CAPS__['pwa.embedded-ota.v1'] = true`. */
    fun capabilityScript(): String? =
        "window.__CT_ANDROID_CAPS__=Object.assign(window.__CT_ANDROID_CAPS__||{},{'$OTA_CAPABILITY':true});"

    /** Bridge event sent to the page when a newer bundle is staged. */
    fun updateAvailableEvent(currentVer: String, pendingVer: String): JSONObject? =
        JSONObject()
            .put("action", "embeddedPwaUpdateAvailable")
            .put("currentVer", currentVer)
            .put("pendingVer", pendingVer)
}
