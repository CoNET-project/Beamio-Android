package com.beamio.app.credential

import com.beamio.app.BridgeReqId
import org.json.JSONObject

/**
 * Routing and the pre-SDK refusals of `pwaWalletSync` and `nativeMnemonicPreread` (contract v3.3 §十一, §59(1)(c)(d);
 * errata E1: trustedOrigin is judged first, then the credential fields).
 *
 * - [normalize] finds the command in a flat body (`{type, ...}`) or a nested one (`{command: {type, ...}}`). Both shapes go through
 *   the trust gate; any other body returns null and keeps its existing path.
 * - [refusalBeforeSdk] decides, from the shell's own trust verdict, whether the request is refused before the SDK sees it. A null
 *   result means the request may be forwarded. The SDK owns the format, stale_seq and overwrite rules.
 * - Nothing here reads or returns a phrase; the refusal carries only `reqId` and the error code.
 */
object PageSyncRoute {
    const val PWA_SYNC = "pwaWalletSync"
    const val PREREAD = "nativeMnemonicPreread"
    /** PWA empty signal (spec r2.5.2 53): it changes native state (the narrow discard), so it is trust-gated like the other two. */
    const val PWA_EMPTY_SIGNAL = "pwaEmptySignal"
    const val UNTRUSTED_SOURCE = "untrusted_source"

    /** Passcode protocol v1 (frozen, §一第 6 条): the six commands the page sends; the shell only forwards them. */
    const val PASSCODE_PROVISION = "passcodeProvision"
    const val PASSCODE_UNLOCK = "passcodeUnlock"
    const val PASSCODE_CHANGE = "passcodeChange"
    const val PASSCODE_DISABLE = "passcodeDisable"
    const val NATIVE_REPAIR_PROVIDE = "nativeRepairProvide"
    const val PASSCODE_STATUS = "passcodeStatus"

    /**
     * Per-command allowed fields of the passcode commands, besides `type` and `reqId` (frozen protocol v1 §一第 6 条). A field
     * outside this list makes the request `bad_request` before the SDK sees it.
     */
    val PASSCODE_ALLOWED: Map<String, Set<String>> = mapOf(
        PASSCODE_PROVISION to setOf("eoa", "phrase", "passcode"),
        PASSCODE_UNLOCK to setOf("eoa", "passcode", "callId"), // callId optional: incoming-call unlock (chat interface spec 10/11)
        PASSCODE_CHANGE to setOf("eoa", "oldPasscode", "newPasscode"),
        PASSCODE_DISABLE to setOf("eoa", "passcode"),
        NATIVE_REPAIR_PROVIDE to setOf("eoa", "phrase", "passcode", "requestReqId"),
        PASSCODE_STATUS to setOf("eoa"),
    )

    /** Credential fields each passcode command may carry (lower case); the rest of [CREDENTIAL_FIELDS] is refused for it. */
    private val PASSCODE_CREDENTIAL: Map<String, Set<String>> = mapOf(
        PASSCODE_PROVISION to setOf("phrase", "passcode"),
        PASSCODE_UNLOCK to setOf("passcode"),
        PASSCODE_CHANGE to setOf("oldpasscode", "newpasscode"),
        PASSCODE_DISABLE to setOf("passcode"),
        NATIVE_REPAIR_PROVIDE to setOf("phrase", "passcode"),
        PASSCODE_STATUS to emptySet(),
    )

    val COMMANDS: Set<String> = setOf(PWA_SYNC, PREREAD, PWA_EMPTY_SIGNAL) + PASSCODE_ALLOWED.keys

    /** Lower-case credential field names. `phrase` is allowed on pwaWalletSync only (§59(1)(c)); the passcode fields are per command. */
    private val CREDENTIAL_FIELDS: Set<String> = setOf(
        "phrase", "mnemonic", "eoaprivatekey", "privatekeyhex", "recoverycode", "pin", "password",
        "passcode", "oldpasscode", "newpasscode",
    )

    /**
     * pwaWalletSync (M6, method Y, 2026-11-23): besides the credential fields above, the bridge key names of
     * [WalletCredentialGate.KEY_FIELDS] (privateKey, walletPrivateKey, seed, ...) are refused too (vector MG-08). `phrase` and
     * `passcode` are not in this set: `passcode` is allowed only next to a v3 passcode envelope `cipher` ([pwaSyncRefusal]).
     */
    // Lazy: WalletCredentialGate reads PageSyncRoute.PASSCODE_ALLOWED during its own initialisation (no init cycle).
    private val PWA_SYNC_FORBIDDEN: Set<String> by lazy { (CREDENTIAL_FIELDS + WalletCredentialGate.KEY_FIELDS) - "phrase" - "passcode" }

    /** M6 §2.2: the passcode in pwaWalletSync is the six digits the user just typed, as a string. */
    private val SIX_DIGITS = Regex("^[0-9]{6}$")

    /** Fields of a v3 passcode envelope (mnemonic-cipher-format.v3); each must be a non-empty string, `v` the number 3. */
    private val V3_ENVELOPE_STRINGS = listOf("mode", "eoa", "kdf", "salt", "iv", "alg", "ct")

    /**
     * Credential fields refused for [command]: for pwaWalletSync everything but `phrase` and `passcode` (passcode has its own
     * rule, [pwaSyncRefusal]); for a passcode command everything except the fields that command carries; everything (phrase
     * included) for the other two, which carry no phrase.
     */
    fun forbiddenFieldsFor(command: String): Set<String> = when {
        command == PWA_SYNC -> PWA_SYNC_FORBIDDEN
        command in PASSCODE_ALLOWED -> CREDENTIAL_FIELDS - (PASSCODE_CREDENTIAL[command] ?: emptySet())
        else -> CREDENTIAL_FIELDS
    }

    /** The fields a passcode command may carry, including `type` and `reqId`; null for every other command (no change to them). */
    fun allowedFieldsFor(command: String): Set<String>? = PASSCODE_ALLOWED[command]?.plus(setOf("type", "reqId"))

    /**
     * The flat form of a page-sync request, or null when [json] is not one. A nested `command` object is used only when its own
     * `type` is a page-sync command, so no other request changes shape.
     */
    fun normalize(json: String): JSONObject? {
        val root = runCatching { JSONObject(json) }.getOrNull() ?: return null
        if (root.optString("type") in COMMANDS) return root
        val nested = root.optJSONObject("command") ?: return null
        return if (nested.optString("type") in COMMANDS) nested else null
    }

    /**
     * Defence in depth (2026-11-22): a page never supplies `trustedOrigin`. Every page body that goes to the SDK
     * is stripped first; only a page-sync command that passed [ShellCredentialTrust] gets the shell's own marker set again
     * (see [channelAnswer] and handlePageSyncCommand). Covers the top level and a nested `command` object.
     */
    fun stripPageTrustedOrigin(body: JSONObject): JSONObject {
        body.remove("trustedOrigin")
        body.optJSONObject("command")?.remove("trustedOrigin")
        return body
    }

    /** Text form for raw messages (shellRecord). Returns [json] unchanged when no `trustedOrigin` is present or it is not JSON. */
    fun stripPageTrustedOriginText(json: String): String {
        val o = runCatching { JSONObject(json) }.getOrNull() ?: return json
        val nested = o.optJSONObject("command")
        if (!o.has("trustedOrigin") && (nested == null || !nested.has("trustedOrigin"))) return json
        stripPageTrustedOrigin(o)
        return o.toString()
    }

    /**
     * JavascriptInterface channel (CashTreesAndroid.chatModuleCommand, every frame can call it, no frame or origin check):
     * page-sync and passcode commands are refused here, before the SDK. The PWA sends them on window.BeamioShellRecord
     * (Android has no chat-module path for them), which carries the origin and main-frame checks. Other commands: null.
     */
    fun refusalOnJsInterface(json: String): JSONObject? {
        val body = normalize(json) ?: return null
        return WalletCredentialGate.refusal(BridgeReqId.valid(body.opt("reqId")), UNTRUSTED_SOURCE)
    }

    /**
     * The refusal to answer before anything reaches the SDK, or null when the request may be forwarded.
     * [trusted] is the shell's own verdict (the page's `trustedOrigin` is never read here).
     */
    fun refusalBeforeSdk(body: JSONObject, trusted: Boolean): JSONObject? {
        val rid = BridgeReqId.valid(body.opt("reqId"))
        if (!trusted) return WalletCredentialGate.refusal(rid, UNTRUSTED_SOURCE)
        val command = body.optString("type")
        if (WalletCredentialGate.keyFieldNames(body, forbiddenFieldsFor(command)).isNotEmpty()) {
            return WalletCredentialGate.refusal(rid, WalletCredentialGate.KEY_OVER_BRIDGE_REFUSED)
        }
        if (command == PWA_SYNC) pwaSyncRefusal(body)?.let { return WalletCredentialGate.refusal(rid, it) }
        // Passcode commands: any field outside the command's own list is a shape error (frozen protocol v1 §一第 6 条).
        allowedFieldsFor(command)?.let { allowed ->
            if (body.keys().asSequence().any { it !in allowed }) return WalletCredentialGate.refusal(rid, WalletCredentialGate.BAD_REQUEST)
        }
        return null
    }

    /**
     * M6 (method Y, passcode-preserving unlock sync, vectors MG-03..MG-07): the error code that refuses a trusted
     * pwaWalletSync before the SDK, or null to forward it. Runs after the forbidden-field check, so only `phrase`, `passcode`
     * and `cipher` are judged here; no value is read beyond its type and shape, and none is returned or logged.
     * - `passcode` without `cipher`, or anywhere but the top level: key_over_bridge_refused (MG-03, MG-04);
     * - `cipher` together with `phrase`: key_over_bridge_refused (MG-05);
     * - `passcode` with `cipher`: the passcode must be a six-digit string (MG-06) and the cipher a v3 passcode envelope
     *   object (MG-07), otherwise bad_request.
     * A request without `passcode` keeps its earlier path unchanged (its cipher is judged by the SDK, as before).
     */
    private fun pwaSyncRefusal(body: JSONObject): String? {
        val hasCipher = body.has("cipher")
        val hasPhrase = WalletCredentialGate.keyFieldNames(body, setOf("phrase")).isNotEmpty()
        val passcodeNames = WalletCredentialGate.keyFieldNames(body, setOf("passcode"))
        val topPasscode = body.has("passcode")
        if (passcodeNames.isNotEmpty() && (!topPasscode || !hasCipher)) return WalletCredentialGate.KEY_OVER_BRIDGE_REFUSED
        // A nested "passcode" (under any key name case) next to the top-level one is not the allowed field either.
        if (topPasscode && body.keys().asSequence().count { it.lowercase() == "passcode" } != 1) return WalletCredentialGate.KEY_OVER_BRIDGE_REFUSED
        if (topPasscode && containsNested(body, "passcode")) return WalletCredentialGate.KEY_OVER_BRIDGE_REFUSED
        if (hasCipher && hasPhrase) return WalletCredentialGate.KEY_OVER_BRIDGE_REFUSED
        if (!topPasscode) return null
        val passcode = body.opt("passcode")
        if (passcode !is String || !SIX_DIGITS.matches(passcode)) return WalletCredentialGate.BAD_REQUEST
        if (!isV3PasscodeEnvelope(body.opt("cipher"))) return WalletCredentialGate.BAD_REQUEST
        return null
    }

    /** True when a key named [name] (case-insensitive) occurs below the top level of [body]. */
    private fun containsNested(body: JSONObject, name: String): Boolean =
        body.keys().asSequence().any { k -> WalletCredentialGate.keyFieldNames(body.opt(k), setOf(name)).isNotEmpty() }

    /** v3 passcode envelope (mnemonic-cipher-format.v3): an object, `v` the number 3, mode "passcode", the other fields strings. */
    private fun isV3PasscodeEnvelope(v: Any?): Boolean {
        if (v !is JSONObject) return false
        val version = v.opt("v")
        if (version !is Number || version.toDouble() != 3.0) return false
        if (V3_ENVELOPE_STRINGS.any { k -> (v.opt(k) as? String).isNullOrEmpty() }) return false
        return v.optString("mode") == "passcode"
    }

    /**
     * The shell's log line for a page-sync request (NE-07, E6): the command, the trust outcome, the reqId and the error code only.
     * It never takes the reply, so a phrase or an address from the SDK cannot reach the log through this line.
     */
    fun logLine(command: String, trusted: Boolean, reqId: Any?, error: String?): String =
        "$command gate trusted=$trusted reqId=${reqId ?: "null"} error=${error ?: "none"}"

    /**
     * The answer on a trusted WebMessage channel (ShellRecordChannel). [trusted] is the shell's verdict from the channel's own
     * sourceOrigin and isMainFrame. A refusal is returned and [sdk] is not called. Otherwise the page's own `trustedOrigin` is
     * dropped, the shell's marker is set, and the SDK's bare ack is returned unchanged. A null answer means the SDK gave none
     * (the page's own timeout decides; no answer code is invented here).
     */
    fun channelAnswer(body: JSONObject, trusted: Boolean, sdk: (JSONObject) -> JSONObject?): JSONObject? {
        body.remove("trustedOrigin")
        refusalBeforeSdk(body, trusted)?.let { return it }
        body.put("trustedOrigin", true)
        return sdk(body)
    }
}
