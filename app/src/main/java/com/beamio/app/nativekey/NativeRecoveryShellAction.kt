package com.beamio.app.nativekey

import com.beamio.app.BeamioShellChannel
import org.json.JSONObject

/**
 * The shell actions of the onboarding recovery on the PWA page (spec r3sc R4/R5, plan A / P1), on `window.BeamioShell` only
 * (WebMessage, trusted origin, main frame, then [trusted] = ShellCredentialTrust). No JavascriptInterface carries them.
 *
 * - `nativeRecoverySubmit` args `{path:"code", code}` or `{path:"account", name, password}` and nothing else (spec r3se R4, R3SB-5).
 *   `bad_args` only for: a missing field, a field that is not a string, an unknown path, an extra field, or a value over its limit in
 *   UTF-8 bytes of the decoded JSON string (code 64, name 128, password 256; an unpaired surrogate counts as U+FFFD, 3 bytes; the raw
 *   string, not trimmed). No format check and no name normalisation here: empty and blank values go to the engine, which answers
 *   `invalid_format` in the result event (22 characters is the engine's check too). Other refusals: `origin_refused` (not trusted),
 *   `not_available` (no open session, or a submission still running). `ok:true` means the engine started; its result reaches the page
 *   as the SDK's `nativeRecoveryResult` with the page's reqId.
 * - `nativeRecoveryCancel` (no args): ends the session; the SDK sends `cancelled` once if no result was sent.
 * - `shellCapabilities` (no args): `{capabilities:[...]}`, with [CAPABILITY] when the engine is mounted.
 *
 * The secret strings are turned into CharArray at once and removed from the args object; nothing here logs or echoes a value.
 */
object NativeRecoveryShellAction {
    const val SUBMIT = "nativeRecoverySubmit"
    const val CANCEL = "nativeRecoveryCancel"
    const val CAPABILITIES = "shellCapabilities"
    const val CAPABILITY = "recovery.page-input.v1"

    /** R3SB-5 upper bounds in UTF-8 bytes of the raw string; longer is `bad_args`. */
    const val MAX_CODE_BYTES = 64
    const val MAX_NAME_BYTES = 128
    const val MAX_PASSWORD_BYTES = 256

    /**
     * UTF-8 length of [s] as a decoder would encode it, without building the bytes: an unpaired surrogate counts as U+FFFD (3 bytes).
     * (String.getBytes would write it as '?', 1 byte, and undercount.)
     */
    fun utf8Bytes(s: String): Int {
        var n = 0
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c.code < 0x80 -> n += 1
                c.code < 0x800 -> n += 2
                Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1]) -> { n += 4; i++ }
                else -> n += 3 // BMP character, or an unpaired surrogate (U+FFFD)
            }
            i++
        }
        return n
    }

    private val SECRET_KEYS = listOf("code", "name", "password")

    /** r3si (7): `["recovery.page-input.v1","account.page-create.v1"]`, each only when its engine is mounted. */
    fun capabilities(
        backend: NativeRecoveryBackend = NativeRecoveryBackends.current,
        create: NativeAccountCreateBackend = NativeAccountCreateBackends.current,
    ): JSONObject =
        JSONObject().put("capabilities", org.json.JSONArray().apply {
            if (backend.supported) put(CAPABILITY)
            if (create.supported) put(ShellAccountCreateAction.CAPABILITY)
        })

    /**
     * The ack for [action] (SUBMIT or CANCEL). [trusted] runs first; on refusal the args are dropped unread. Never returns or logs a
     * secret. [args] is emptied of the secret fields in every case.
     */
    fun answer(
        action: String,
        reqId: Any,
        args: JSONObject,
        trusted: () -> Boolean,
        headless: NativeRecoveryHeadless = NativeRecoveryHeadless,
        backend: NativeRecoveryBackend = NativeRecoveryBackends.current,
    ): JSONObject {
        val ack = BeamioShellChannel.ack(action, reqId)
        try {
            if (!runCatching(trusted).getOrDefault(false)) return refuse(ack, NativeRecoveryHeadless.ORIGIN_REFUSED)
            return when (action) {
                CANCEL -> {
                    if (args.length() != 0) return refuse(ack, NativeRecoveryHeadless.BAD_ARGS)
                    headless.cancel(backend)
                    ack.put("ok", true)
                }
                SUBMIT -> submit(ack, args, headless, backend)
                else -> refuse(ack, "unknown_command")
            }
        } finally {
            SECRET_KEYS.forEach { args.remove(it) }
        }
    }

    private fun submit(ack: JSONObject, args: JSONObject, headless: NativeRecoveryHeadless, backend: NativeRecoveryBackend): JSONObject {
        val keys = args.keys().asSequence().toSet()
        fun text(key: String, max: Int): String? = (args.opt(key) as? String)?.takeIf { utf8Bytes(it) <= max }
        val refusal = when (args.opt("path")) {
            "code" -> {
                if (keys != setOf("path", "code")) return refuse(ack, NativeRecoveryHeadless.BAD_ARGS)
                val code = text("code", MAX_CODE_BYTES) ?: return refuse(ack, NativeRecoveryHeadless.BAD_ARGS)
                args.remove("code")
                headless.submitCode(code.toCharArray(), backend)
            }
            "account" -> {
                if (keys != setOf("path", "name", "password")) return refuse(ack, NativeRecoveryHeadless.BAD_ARGS)
                val name = text("name", MAX_NAME_BYTES)
                val password = text("password", MAX_PASSWORD_BYTES)
                if (name == null || password == null) return refuse(ack, NativeRecoveryHeadless.BAD_ARGS)
                args.remove("password")
                headless.submitAccount(name, password.toCharArray(), backend)
            }
            else -> return refuse(ack, NativeRecoveryHeadless.BAD_ARGS)
        }
        return if (refusal == null) ack.put("ok", true) else refuse(ack, refusal)
    }

    private fun refuse(ack: JSONObject, code: String): JSONObject = ack.put("ok", false).put("error", code)

    /** The window.BeamioShell-only names (recovery, capabilities, account create); any other channel that sees one of them refuses it. */
    val NAMES: Set<String> = setOf(SUBMIT, CANCEL, CAPABILITIES) + ShellAccountCreateAction.NAMES

    /** Background time after which an open session is cancelled (r3se R4(e) "后台超时"; engineering default, the spec gives no value). */
    const val BACKGROUND_TIMEOUT_MS = 5 * 60 * 1000L

    /**
     * r3se R4(b), vector RN-01 (and r3si item 63 (2), vectors CN-01/CN-02): a JavascriptInterface or BeamioChat message naming one of these actions (as `action`, `type`, or a nested
     * `command.type`) is answered `origin_refused` and never reaches the engine or the SDK. The args are not read. Null otherwise.
     */
    fun jsInterfaceRefusal(json: String): JSONObject? {
        val o = runCatching { JSONObject(json) }.getOrNull() ?: return null
        val name = listOf(o.opt("action"), o.opt("type"), o.optJSONObject("command")?.opt("type")).firstOrNull { it is String && it in NAMES } as? String
            ?: return null
        return BeamioShellChannel.ack(name, com.beamio.app.BridgeReqId.valid(o.opt("reqId"))).put("ok", false).put("error", NativeRecoveryHeadless.ORIGIN_REFUSED)
    }
}
