package com.beamio.app.nativekey

import com.beamio.app.BeamioShellChannel
import org.json.JSONObject

/**
 * The account-create shell actions of the onboarding page (spec r3si/r3sj item 63, plan r3-create §4.2), on `window.BeamioShell` only
 * (WebMessage, trusted origin, main frame, then [trusted] = ShellCredentialTrust). No JavascriptInterface or BeamioChat path carries them:
 * those answer `origin_refused` ([NativeRecoveryShellAction.jsInterfaceRefusal]).
 *
 * - `accountCreateRegister` args `{tag, password}`: passed as they are to the SDK command `accountCreateRegister` (the SDK owns the four-key
 *   check, its gate order, `not_available` / `not_ready` / `tag_taken` / `already_registered`). The answer is the shell envelope with the
 *   SDK's own result: `{type:"ack", action, reqId, ok:true, result:{accountName, wallet, signMessage, recover, recoverCodeBase58}}` or
 *   `{..., ok:false, error}`. The shell never logs, keeps or echoes the args or the result.
 * - `secureScreen {on}`: `on` must be a boolean and the only field (else `bad_args`). While on, the window is FLAG_SECURE (or-ed with the G0
 *   guard); the shell turns it off by itself after [SECURE_SCREEN_MAX_MS] and on a cold start (the state is in memory only).
 */
object ShellAccountCreateAction {
    const val REGISTER = "accountCreateRegister"
    const val SECURE_SCREEN = "secureScreen"
    const val CAPABILITY = "account.page-create.v1"

    /** r3si (4)(d): the shell's own limit, later than the page's 5-minute display timeout. */
    const val SECURE_SCREEN_MAX_MS = 10 * 60 * 1000L

    /** How long the shell waits for the SDK's answer to `accountCreateRegister` (the page's own timeout is 120 s). */
    const val SDK_ANSWER_TIMEOUT_MS = 125_000L

    val NAMES: Set<String> = setOf(REGISTER, SECURE_SCREEN)

    private const val BAD_ARGS = "bad_args"
    private const val ORIGIN_REFUSED = "origin_refused"

    /**
     * `accountCreateRegister`. [sdk] runs the SDK command and returns its bare ack (or null on timeout). The args object is emptied of the
     * password in every case.
     */
    fun register(
        reqId: Any,
        args: JSONObject,
        trusted: () -> Boolean,
        sdk: (JSONObject) -> JSONObject?,
    ): JSONObject {
        val ack = BeamioShellChannel.ack(REGISTER, reqId)
        try {
            if (!runCatching(trusted).getOrDefault(false)) return ack.put("ok", false).put("error", ORIGIN_REFUSED)
            // The envelope fields are the shell's: a page value for `type` or `reqId` would replace them.
            if (args.has("type") || args.has("reqId")) return ack.put("ok", false).put("error", BAD_ARGS)
            val body = JSONObject().put("type", REGISTER).put("reqId", reqId)
            for (k in args.keys()) body.put(k, args.get(k))
            args.remove("password")
            val answer = try {
                sdk(body)
            } finally {
                body.remove("password")
            }
                ?: return ack.put("ok", false).put("error", "not_ready")
            return if (answer.optBoolean("ok", false)) {
                ack.put("ok", true).also { a -> answer.optJSONObject("result")?.let { a.put("result", it) } }
            } else {
                ack.put("ok", false).put("error", answer.optString("error").ifEmpty { "not_ready" })
            }
        } finally {
            args.remove("password")
        }
    }

    /** What the shell does with its 10-minute timer for one `secureScreen` request (spec CP-22). */
    enum class SecureTimer {
        /** Turning on from off: start the timer. */
        START,
        /** Already on and asked on again: the timer keeps counting from the first on (CP-22); nothing is reset. */
        KEEP,
        /** Turning off: stop the timer. */
        STOP,
    }

    fun secureTimerFor(wasOn: Boolean, on: Boolean): SecureTimer = when {
        !on -> SecureTimer.STOP
        wasOn -> SecureTimer.KEEP
        else -> SecureTimer.START
    }

    /** `secureScreen {on}`. [apply] sets the shell state; returns the ack. */
    fun secureScreen(reqId: Any, args: JSONObject, trusted: () -> Boolean, apply: (Boolean) -> Unit): JSONObject {
        val ack = BeamioShellChannel.ack(SECURE_SCREEN, reqId)
        if (!runCatching(trusted).getOrDefault(false)) return ack.put("ok", false).put("error", ORIGIN_REFUSED)
        val on = args.opt("on")
        if (args.length() != 1 || on !is Boolean) return ack.put("ok", false).put("error", BAD_ARGS)
        apply(on)
        return ack.put("ok", true)
    }
}
