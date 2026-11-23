package com.beamio.app.legacy

/**
 * QA-only read-failure hook (2026-11-22, QA read-failure path). Only the debugqa source set
 * (src/qaHooks, -PchatQaHooks) installs an implementation; every other build keeps [QaReadFaults.current] null, so the
 * shell answers exactly as before. The hook never touches the keystore, the record or the SDK; it only chooses the
 * reply for shellRecordRead.
 */
internal interface QaReadFault {
    /** The reply to send instead of the SDK answer, or null to let the normal path run. */
    fun replyFor(type: String, data: String): String?
}

internal object QaReadFaults {
    @Volatile
    var current: QaReadFault? = null
}
