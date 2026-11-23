package com.beamio.app.nativekey

/**
 * Shell bridge entries outside the SDK that are refused while the device has no native key (spec 25.26.4b, T-161;
 * rule 2026-11-12). The check runs before the entry reads its argument, so the payload is never parsed.
 *
 * - G0 (no native record): `no_key`.
 * - G1 (a record, this session not initialised) should answer `not_ready`, but the SDK of that time does not expose the
 *   session state to the shell, so G1 and G2 both pass through here. Recorded as a gap for the SDK line.
 * - Unknown (chat SDK without native key support): pass through, the behaviour before this change.
 *
 * `saveRecoveryQrToPhotos` and `registerPushDeviceHttp` from the iOS list have no Android entry; `scanRecoveryQr` was
 * removed from the Android shell .
 */
object ShellNoKeyGate {
    const val NO_KEY = "no_key"
    const val NOT_READY = "not_ready"

    val GATED: Set<String> = setOf(
        // calls
        "prepareSystemCall", "cancelPreparedSystemCall", "startSystemCall", "reportIncomingSystemCall", "endSystemCall",
        // chat notifications
        "clearOfflineChatAlerts", "notifyBackgroundChat",
        // PGP material
        "postPgpCiphertext", // setNativeChatPgpSecrets removed
        // node configuration
        "setNativeVoiceRelayNodes", "setNativeSiNodeRoster",
        // signing reply, push binding
        "chatModuleSignResponse", "bindPushIdentity",
        // scanRecoveryQr removed from the shell
        // (2026-11-14, spec r3cy §25.26.4b additions): call-related entries refused like the calls above
        "notifyVoiceMicReady", "queryIncomingCallOutcome", "startNativeVoiceMic", "cacheCallerAvatars",
    )

    /** The refusal code for [entry], or `null` to let it run. */
    fun answer(entry: String, backend: NativeKeyBackend = NativeKeyBackends.current): String? {
        if (entry !in GATED) return null
        // Spec §25.26.4c: G1 (record present, session not initialised) answers not_ready; the SDK reports the session state.
        return when {
            backend.hasKey() == false -> NO_KEY
            backend.hasKey() == true && backend.sessionReady() == false -> NOT_READY
            else -> null
        }
    }
}
