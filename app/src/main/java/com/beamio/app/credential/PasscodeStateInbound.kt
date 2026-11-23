package com.beamio.app.credential

import org.json.JSONObject

/**
 * Shell inbound side of `passcodeState` (frozen protocol v1 §一第 4 条; index x §25.2). The shell takes its own copy of the SDK's
 * event; it does not stop anything in this step (the stop actions come later, see the design note).
 *
 * - Only an event from the SDK's native delivery path counts ([Source.SDK_NATIVE]); a page message never does.
 * - The payload is a closed shape `{type, set, locked}`. Any other key (a credential name included) or a non-boolean value is rejected.
 * - Nothing here reads or keeps a credential. The result carries two booleans only.
 */
object PasscodeStateInbound {
    const val EVENT_TYPE = "passcodeState"

    /** Stop the shell's account-bound components on a lock. Off by default (the lock behaviour waits on the SDK). */
    const val STOP_ON_PASSCODE_LOCKED = false

    private val SHAPE: Set<String> = setOf("type", "set", "locked")

    /**
     * Where the payload came from. SDK_NATIVE is a call-site constant (the callback of BeamioConetChatModule.handleCommand in
     * MainActivity.sdkDeliver), not a fact checked from the payload. It holds only while (a) the page can reach that callback
     * only through handleCommand and the callback does not put page input at the top-level `type`, and (b) a reply's type is
     * "ack", which never collides with passcodeState. If the SDK later lets a reply's result carry page input, re-assess this.
     */
    enum class Source { SDK_NATIVE, PAGE }

    enum class Outcome { IGNORED_NOT_EVENT, IGNORED_SOURCE, REJECTED_SHAPE, ACCEPTED }

    data class State(val set: Boolean, val locked: Boolean)

    /** The inner event of `{action, event: {...}}`, or the payload itself when it is already bare. */
    fun eventOf(payload: JSONObject): JSONObject = payload.optJSONObject("event") ?: payload

    /** The state when [event] is a closed-shape passcodeState, else null. */
    fun parse(event: JSONObject): State? {
        if (event.optString("type") != EVENT_TYPE) return null
        if (event.keys().asSequence().any { it !in SHAPE }) return null
        val set = event.opt("set") as? Boolean ?: return null
        val locked = event.opt("locked") as? Boolean ?: return null
        return State(set, locked)
    }

    /**
     * Classifies one payload from [source]. The state is non-null only for [Outcome.ACCEPTED].
     * REJECTED_SHAPE has no side effect while [STOP_ON_PASSCODE_LOCKED] is false. Before the stop is enabled, a REJECTED_SHAPE
     * for a passcodeState must be handled as unknown and conservative (a real locked=true may sit behind an extra field).
     */
    fun observe(payload: JSONObject, source: Source): Pair<Outcome, State?> {
        val event = eventOf(payload)
        if (event.optString("type") != EVENT_TYPE) return Outcome.IGNORED_NOT_EVENT to null
        if (source != Source.SDK_NATIVE) return Outcome.IGNORED_SOURCE to null
        val state = parse(event) ?: return Outcome.REJECTED_SHAPE to null
        return Outcome.ACCEPTED to state
    }

    /** Whether an accepted lock would stop the components. False while the flag is off; account switch and logout are not handled here. */
    fun shouldStopOnLock(state: State): Boolean = STOP_ON_PASSCODE_LOCKED && state.locked
}
