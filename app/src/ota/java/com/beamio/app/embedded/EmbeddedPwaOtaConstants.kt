package com.beamio.app.embedded

/**
 * Remote PWA update endpoints. Lives in the `ota` source set only (debug, release), so the
 * `store` build type has no update URL in its dex (checked by scripts/verify-android-store-no-ota.sh).
 */
object EmbeddedPwaOtaConstants {
    const val REMOTE_UPDATE_MANIFEST = "https://beamio.ca/app/update.json"
    const val REMOTE_BUNDLE_BASE = "https://beamio.ca/app/"
}
