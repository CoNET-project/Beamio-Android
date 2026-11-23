package com.beamio.app

/**
 * Values the debug-only BeamioQaBridge log may print for public status fields of a chat-module answer.
 * `notReadyReason` (spec §25.52Y.39 items 9-10) is printed only when it is one of its two defined values; anything else
 * is printed as `<unknown>` so an unexpected string never reaches the log (same rule as the iOS shell).
 */
object QaBridgeLogFields {
    val NOT_READY_REASONS = setOf("g1_uninitialized", "unreadable", "passcode_required")
    const val UNKNOWN = "<unknown>"

    fun value(key: String, raw: Any?): String = when (key) {
        "notReadyReason" -> (raw as? String)?.takeIf { it in NOT_READY_REASONS } ?: UNKNOWN
        else -> raw.toString()
    }
}
