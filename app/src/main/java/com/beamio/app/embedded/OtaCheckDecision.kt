package com.beamio.app.embedded

/** Outcome of one OTA check against the active bundle version (pure, unit-tested). */
internal enum class OtaCheckDecision { SKIP_ACTIVE_UNKNOWN, NO_NEWER, STAGE }

/**
 * An unknown active version (null) never compares as older than anything: the check is skipped, so an unreadable
 * update.json cannot pull a remote bundle in (PM review, 2026-11-17: an unknown version is not 0.0.0).
 */
internal fun decideOtaCheck(activeVersion: String?, remoteVer: String): OtaCheckDecision = when {
    activeVersion == null -> OtaCheckDecision.SKIP_ACTIVE_UNKNOWN
    !EmbeddedPwaBundleStore.isSemverNewer(activeVersion, remoteVer) -> OtaCheckDecision.NO_NEWER
    else -> OtaCheckDecision.STAGE
}
