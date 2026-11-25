package com.beamio.app.nativekey

import org.json.JSONObject
import java.lang.ref.WeakReference

/**
 * Native recovery engine hookup (PWA `nativeRecovery.ts`). Since 192 (spec r3sc, plan A / P1) there is no native recovery page:
 *
 * - The page sends `{type:"nativeRecoveryOpen", reqId}` (no data) on the chat-module channel. The SDK calls its launcher; the shell
 *   opens a headless session ([NativeRecoveryHeadless]) and shows nothing. The SDK keeps the page's reqId.
 * - The page then sends the shell action `nativeRecoverySubmit` (`{path:"code", code}` or `{path:"account", name, password}`) on the
 *   trusted `window.BeamioShell` WebMessage channel, or `nativeRecoveryCancel`. The shell turns the secret into a CharArray at once and
 *   hands it to the SDK engine (NativeRecovery.restoreWithRecoveryCode / restoreWithAccountPassword).
 * - The result `{type:"nativeRecoveryResult", reqId, code}` is sent by the SDK with the page's reqId, plus `eoa` (only with `ok`) or
 *   `cooldownSec` (only with `backoff`). The mnemonic and the key stay native; nothing secret goes back to the page.
 * - `nativeRecoveryOpen` is not `nativeImportOpen` (private key import): the two are never mapped onto each other.
 */
object NativeRecoveryProtocol {
    const val OPEN_COMMAND = "nativeRecoveryOpen"
    const val RESULT_EVENT = "nativeRecoveryResult"
}

/** Result codes, the same list as the PWA (`NATIVE_RECOVERY_RESULT_CODES`). */
enum class RecoveryCode(val wire: String) {
    OK("ok"),
    CANCELLED("cancelled"),
    INVALID_FORMAT("invalid_format"),
    BAD_PIN("bad_pin"),
    BACKOFF("backoff"),
    NOT_FOUND("not_found"),
    NETWORK_ERROR("network_error"),
    ALREADY_EXISTS("already_exists"),
    RECORD_INVALID("record_invalid"),
    WRITE_FAILED("write_failed"),
    READBACK_FAILED("readback_failed"),
    /** SDK 0.2.11: the record is in the old format. Not in the PWA's list (the page ignores this code). */
    LEGACY_RECORD("legacy_record"),
    ;

    companion object {
        fun fromWire(w: String): RecoveryCode = values().firstOrNull { it.wire == w } ?: RECORD_INVALID
    }
}

/** What the backend returns. `eoa` only with OK; `cooldownSec` only with BACKOFF. */
data class RecoveryOutcome(val code: RecoveryCode, val eoa: String? = null, val cooldownSec: Int? = null)

/** The native recovery engine (Android SDK). The code array is wiped by the caller after the call. */
interface NativeRecoveryBackend {
    val supported: Boolean
    fun recover(recoveryCode: CharArray): RecoveryOutcome

    /** Path B (spec r3u 25.42.3): account name (plain text, trimmed by the engine) and password (wiped by the caller). */
    fun recoverWithPassword(accountName: String, password: CharArray): RecoveryOutcome = RecoveryOutcome(RecoveryCode.RECORD_INVALID)

    /** The user closed the page before a result: the engine tells the web page `cancelled` (SDK `NativeRecoveryHost.cancel`). */
    fun cancel() = Unit

    /** No SDK recovery API in this build. */
    object Unavailable : NativeRecoveryBackend {
        override val supported = false
        override fun recover(recoveryCode: CharArray) = RecoveryOutcome(RecoveryCode.RECORD_INVALID)
    }
}

object NativeRecoveryBackends {
    @Volatile
    var current: NativeRecoveryBackend = NativeRecoveryBackend.Unavailable
}

object NativeRecoveryFlow {
    private val EOA = Regex("^0x[0-9a-fA-F]{40}$")

    /** Spec r3u 25.42 path A: after trimming spaces the code must be exactly 22 characters of [0-9A-Za-z]. */
    fun formatOk(code: CharArray): Boolean {
        var start = 0
        var end = code.size
        while (start < end && code[start].isWhitespace()) start++
        while (end > start && code[end - 1].isWhitespace()) end--
        val n = end - start
        if (n != 22) return false
        for (i in start until end) {
            val c = code[i]
            if (!((c in '0'..'9') || (c in 'A'..'Z') || (c in 'a'..'z'))) return false
        }
        return true
    }

    /** Runs one recovery: shape check, then the backend. Wipes the array in every case. */
    fun submit(code: CharArray, backend: NativeRecoveryBackend = NativeRecoveryBackends.current): RecoveryOutcome {
        try {
            if (!formatOk(code)) return RecoveryOutcome(RecoveryCode.INVALID_FORMAT)
            if (!backend.supported) return RecoveryOutcome(RecoveryCode.RECORD_INVALID)
            return sanitize(backend.recover(code))
        } catch (_: Exception) {
            return RecoveryOutcome(RecoveryCode.RECORD_INVALID)
        } finally {
            code.fill('\u0000')
        }
    }

    /** Path B: both fields must be non-empty after trimming (r3u 25.42.3 item 3). Wipes the password in every case. */
    fun submitPassword(accountName: String, password: CharArray, backend: NativeRecoveryBackend = NativeRecoveryBackends.current): RecoveryOutcome {
        try {
            if (accountName.isBlank() || password.all { it.isWhitespace() }) return RecoveryOutcome(RecoveryCode.INVALID_FORMAT)
            if (!backend.supported) return RecoveryOutcome(RecoveryCode.RECORD_INVALID)
            return sanitize(backend.recoverWithPassword(accountName, password))
        } catch (_: Exception) {
            return RecoveryOutcome(RecoveryCode.RECORD_INVALID)
        } finally {
            password.fill('\u0000')
        }
    }

    /** Keeps only what the page may see: eoa only with OK (and only a well-formed address), cooldown only with BACKOFF. */
    fun sanitize(o: RecoveryOutcome): RecoveryOutcome = RecoveryOutcome(
        code = o.code,
        eoa = o.eoa?.takeIf { o.code == RecoveryCode.OK && EOA.matches(it) },
        cooldownSec = o.cooldownSec?.takeIf { o.code == RecoveryCode.BACKOFF && it in 1..86_400 },
    )

    /**
     * The `nativeRecoveryResult` event payload for the page that asked with [reqId] (spec §25.52Y.27, r3na): a result is
     * never built without the page's reqId. In the shipped builds the SDK sends this event (NativeRecoveryHost.emit, which
     * always carries reqId); this helper is the shell's own form of the same payload and is used by tests only.
     */
    fun resultEvent(reqId: Any, o: RecoveryOutcome): JSONObject {
        val s = sanitize(o)
        val p = JSONObject().put("type", NativeRecoveryProtocol.RESULT_EVENT).put("reqId", reqId).put("code", s.code.wire)
        s.eoa?.let { p.put("eoa", it) }
        s.cooldownSec?.let { p.put("cooldownSec", it) }
        return p
    }

    /** Same envelope as the SDK module events (`emitEvent`): the page reads `detail.action == "chatModuleEvent"`. */
    fun envelope(event: JSONObject): JSONObject = JSONObject().put("action", "chatModuleEvent").put("event", event)

    fun ack(reqId: Int, ok: Boolean, error: String? = null): JSONObject {
        val p = JSONObject().put("type", "ack").put("reqId", reqId).put("ok", ok)
        if (!ok) p.put("error", error ?: "error")
        return p
    }

    /**
     * Handles a chat-module command if it is `nativeRecoveryOpen`; returns false for any other command (which then goes
     * to the SDK as before). [open] shows the native recovery page and returns whether it is (being) shown.
     */
    fun intercept(
        body: JSONObject,
        emit: (JSONObject) -> Unit,
        open: () -> Boolean,
        backend: NativeRecoveryBackend = NativeRecoveryBackends.current,
    ): Boolean {
        if (body.optString("type") != NativeRecoveryProtocol.OPEN_COMMAND) return false
        val reqId = body.optInt("reqId", -1)
        if (reqId < 0) return true
        when {
            !backend.supported -> emit(envelope(ack(reqId, false, "not_supported")))
            open() -> emit(envelope(ack(reqId, true)))
            else -> emit(envelope(ack(reqId, false, "not_available")))
        }
        return true
    }
}

/** Connects the SDK's `NativeRecoveryHost.launcher` to the activity on screen (MainActivity registers its headless opener). */
object NativeRecoveryRoute {
    private var opener: WeakReference<() -> Boolean>? = null

    @Synchronized
    fun register(open: () -> Boolean) {
        opener = WeakReference(open)
    }

    @Synchronized
    fun unregister(open: () -> Boolean) {
        if (opener?.get() === open) opener = null
    }

    /** Called by the SDK launcher. `true` only when a headless session was opened. */
    fun open(): Boolean {
        if (!NativeRecoveryBackends.current.supported) return false
        val o = synchronized(this) { opener?.get() } ?: return false
        return o()
    }
}


/**
 * The headless recovery session (spec r3sc R3/R4, plan A / P1). No UI is ever shown: [open] only records that the SDK has a page
 * session (it holds the page's reqId), and the page's `nativeRecoverySubmit` runs the engine through [NativeRecoveryFlow].
 *
 * - One submission at a time. A failure keeps the session open (the page may submit again); `ok` ends it, as in the SDK host.
 * - [cancel] ends the session; the SDK then sends `cancelled` to the page if no result was sent (NativeRecoveryHost.pageClosed).
 * - Every secret array is wiped by [NativeRecoveryFlow] in all cases. Nothing here logs; callers log the action name and code only.
 */
object NativeRecoveryHeadless {
    /** Answers of the shell actions (r3sc R4). The engine's result goes to the page as `nativeRecoveryResult`, not here. */
    const val NOT_AVAILABLE = "not_available"
    const val BAD_ARGS = "bad_args"
    const val ORIGIN_REFUSED = "origin_refused"

    @Volatile
    private var sessionOpen = false
    private val inFlight = java.util.concurrent.atomic.AtomicBoolean(false)

    /** Runs the engine call (it waits for the SDK callback, up to 90 s); replaced by tests. */
    @Volatile
    var executor: java.util.concurrent.Executor = java.util.concurrent.Executors.newSingleThreadExecutor { r ->
        Thread(r, "beamio-recovery").apply { isDaemon = true }
    }

    /** Told after each engine result (the screen guard re-checks the key state). Never given a secret. */
    @Volatile
    var onOutcome: ((RecoveryOutcome) -> Unit)? = null

    /** The SDK launcher (through [NativeRecoveryRoute]): opens the session, never a page. */
    fun open(backend: NativeRecoveryBackend = NativeRecoveryBackends.current): Boolean {
        if (!backend.supported) return false
        sessionOpen = true
        return true
    }

    fun isOpen(): Boolean = sessionOpen

    /**
     * Path A. Returns null when accepted (the result follows as an SDK event), else the refusal code. The shell does no format check
     * (spec r3se R3SB-5): an empty, blank or wrong-length code goes to the engine, which answers invalid_format in the result event.
     * [code] is wiped in every case.
     */
    fun submitCode(code: CharArray, backend: NativeRecoveryBackend = NativeRecoveryBackends.current): String? =
        start({ code.fill('\u0000') }) { NativeRecoveryFlow.sanitize(backend.recover(code)) }

    /** Path B. Same contract as [submitCode]; the name is passed as given (no normalisation); [password] is wiped in every case. */
    fun submitAccount(name: String, password: CharArray, backend: NativeRecoveryBackend = NativeRecoveryBackends.current): String? =
        start({ password.fill('\u0000') }) { NativeRecoveryFlow.sanitize(backend.recoverWithPassword(name, password)) }

    private fun start(wipe: () -> Unit, run: () -> RecoveryOutcome): String? {
        if (!sessionOpen || !inFlight.compareAndSet(false, true)) {
            wipe()
            return NOT_AVAILABLE
        }
        try {
            executor.execute {
                val outcome = try {
                    run()
                } catch (_: Exception) {
                    RecoveryOutcome(RecoveryCode.RECORD_INVALID)
                } finally {
                    wipe()
                    inFlight.set(false)
                }
                if (outcome.code == RecoveryCode.OK) sessionOpen = false
                runCatching { onOutcome?.invoke(outcome) }
            }
        } catch (_: Exception) {
            wipe()
            inFlight.set(false)
            return NOT_AVAILABLE
        }
        return null
    }

    /** The page left the form (or reloaded, or the activity is gone): the session ends and the SDK reports `cancelled` once. */
    fun cancel(backend: NativeRecoveryBackend = NativeRecoveryBackends.current) {
        val wasOpen = sessionOpen
        sessionOpen = false
        if (wasOpen) runCatching { backend.cancel() }
    }
}
