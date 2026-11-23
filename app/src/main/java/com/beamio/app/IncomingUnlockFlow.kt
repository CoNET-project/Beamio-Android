package com.beamio.app

import android.os.Handler
import android.os.Looper
import org.json.JSONObject

/**
 * Pure state machine for the pre-answer unlock of one incoming call (v97 §104; v114 §133).
 * No Android types and an injected clock, so it can be tested on the JVM.
 *
 * Phases: LOAD (T_load) then INPUT (T_in), budgets from [IncomingUnlockTimer] (provisional).
 * - [start] opens the flow for one call and returns the request payload (null: refused, fail closed).
 * - [shown] (PWA `incomingCallUnlockShown`) switches LOAD to INPUT once; a repeat, a different callId or
 *   a non-loading phase is ignored.
 * - [unlockOk] (passcodeUnlock ok with the same callId and eoa) yields AUTHORIZE once.
 * - [cancel] and an expired budget yield CANCEL. Neither counts as a passcode error.
 * Every operation returns the effects to run; the caller runs them outside its lock.
 */
class UnlockMachine(private val now: () -> Long) {
    enum class Kind { REQUEST, AUTHORIZE, CANCEL }

    /** One effect for the caller. [payload] is set for REQUEST only. */
    data class Effect(val kind: Kind, val callId: String, val payload: JSONObject? = null)

    private class Entry(val callId: String, val eoa: String) {
        var phase: IncomingUnlockTimer.Phase = IncomingUnlockTimer.Phase.LOAD
        var phaseStartedAt: Long = 0L
        var authorized = false
    }

    private var entry: Entry? = null

    /** The active call, or null. */
    fun activeCallId(): String? = entry?.callId

    /** Epoch millis when the current budget ends, or null when no flow is active. */
    fun deadlineAt(): Long? = entry?.let { it.phaseStartedAt + it.phase.totalMs }

    fun phaseOf(callId: String): IncomingUnlockTimer.Phase? = entry?.takeIf { it.callId == callId }?.phase

    /** Starts the flow. A previous flow for another call is cancelled first. */
    fun start(callId: String, eoa: String): List<Effect> {
        val out = ArrayList<Effect>()
        entry?.let { old ->
            if (old.callId != callId) out += Effect(Kind.CANCEL, old.callId)
            entry = null
        }
        val e = Entry(callId, eoa)
        e.phase = IncomingUnlockTimer.Phase.LOAD
        e.phaseStartedAt = now()
        val payload = IncomingUnlockTimer.payload(callId, eoa, e.phase, IncomingUnlockTimer.Phase.LOAD.totalMs)
        if (payload == null) {
            out += Effect(Kind.CANCEL, callId)
            return out
        }
        entry = e
        out += Effect(Kind.REQUEST, callId, payload)
        return out
    }

    fun shown(callId: String): List<Effect> {
        val e = entry ?: return emptyList()
        if (e.callId != callId || e.phase != IncomingUnlockTimer.Phase.LOAD) return emptyList()
        e.phase = IncomingUnlockTimer.afterShown(e.phase)
        e.phaseStartedAt = now()
        return emptyList()
    }

    fun unlockOk(callId: String, eoa: String): List<Effect> {
        val e = entry ?: return emptyList()
        if (e.callId != callId || e.authorized || !e.eoa.equals(eoa, ignoreCase = true)) return emptyList()
        e.authorized = true
        entry = null
        return listOf(Effect(Kind.AUTHORIZE, callId))
    }

    fun cancel(callId: String): List<Effect> {
        val e = entry ?: return emptyList()
        if (e.callId != callId) return emptyList()
        entry = null
        return if (e.authorized) emptyList() else listOf(Effect(Kind.CANCEL, callId))
    }

    /** Budget check at the current time: an expired phase cancels; a live one yields nothing. */
    fun tick(): List<Effect> {
        val e = entry ?: return emptyList()
        if (!IncomingUnlockTimer.expired(e.phase, now() - e.phaseStartedAt)) return emptyList()
        entry = null
        return listOf(Effect(Kind.CANCEL, e.callId))
    }
}

/**
 * Android wrapper: runs the callbacks registered per call, outside the lock, and schedules the
 * budget check on the main thread. The decision logic lives in [UnlockMachine].
 */
object IncomingUnlockFlow {
    private class Callbacks(val onAuthorize: () -> Unit, val onCancel: () -> Unit)

    private val main = Handler(Looper.getMainLooper())
    private val lock = Any()
    private val machine = UnlockMachine { System.currentTimeMillis() }
    private val callbacks = HashMap<String, Callbacks>()
    private var scheduled: Runnable? = null

    private val tickRunnable = Runnable { runEffects(synchronized(lock) { machine.tick() }) }

    /**
     * Starts the flow. [emit] delivers the request to a running PWA and returns false when none runs;
     * then the flow is cancelled (cold-start is not wired yet: fail closed).
     */
    fun start(
        callId: String,
        eoa: String,
        emit: (JSONObject) -> Boolean,
        onAuthorize: () -> Unit,
        onCancel: () -> Unit,
    ) {
        val effects = synchronized(lock) {
            callbacks[callId] = Callbacks(onAuthorize, onCancel)
            machine.start(callId, eoa).also { reschedule() }
        }
        // Request effects go to the PWA; a refused emit becomes a cancel through the machine.
        val toRun = ArrayList<UnlockMachine.Effect>()
        for (e in effects) {
            if (e.kind == UnlockMachine.Kind.REQUEST) {
                if (emit(e.payload!!)) continue
                toRun += synchronized(lock) { machine.cancel(callId).also { reschedule() } }
            } else {
                toRun += e
            }
        }
        runEffects(toRun)
    }

    fun shown(callId: String) {
        synchronized(lock) { machine.shown(callId).also { reschedule() } }
    }

    fun unlockOk(callId: String, eoa: String) {
        runEffects(synchronized(lock) { machine.unlockOk(callId, eoa).also { reschedule() } })
    }

    fun cancel(callId: String) {
        runEffects(synchronized(lock) { machine.cancel(callId).also { reschedule() } })
    }

    private fun reschedule() {
        scheduled?.let { main.removeCallbacks(it) }
        scheduled = null
        val at = machine.deadlineAt() ?: return
        val delay = (at - System.currentTimeMillis()).coerceAtLeast(0L)
        main.postDelayed(tickRunnable, delay)
        scheduled = tickRunnable
    }

    /** Runs each effect's callback. Called without the lock held. */
    private fun runEffects(effects: List<UnlockMachine.Effect>) {
        for (e in effects) {
            val cb = synchronized(lock) { callbacks.remove(e.callId) } ?: continue
            when (e.kind) {
                UnlockMachine.Kind.AUTHORIZE -> cb.onAuthorize()
                UnlockMachine.Kind.CANCEL -> cb.onCancel()
                UnlockMachine.Kind.REQUEST -> Unit
            }
        }
    }
}
