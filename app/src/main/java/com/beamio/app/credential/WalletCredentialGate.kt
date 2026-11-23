package com.beamio.app.credential

import com.beamio.app.BridgeReqId
import com.beamio.app.ChatOriginGate
import org.json.JSONArray
import org.json.JSONObject

/**
 * Shell side of `walletCredential` (spec r3np §25.52Y.38 items 2, 3, 11, 13 (a), 14) and of the `shellRecordRead` W-field
 * read-back gate (spec r3nq §25.52Y.41). Pure and JVM-testable: the runtime inputs (manifest capability bits, native SDK
 * capability list, bundle verification, channel) come in through [TrustInputs]; [ShellCredentialTrust] fills them in.
 *
 * Nothing here logs or returns a credential value. Log lines carry only the command name, reqId, the trust verdict
 * name, ok, the error code, field names and the duration (§25.52Y.38 item 11 (c) points 1-3; §25.52Y.41 item 5).
 */
object WalletCredentialGate {
    const val COMMAND = "walletCredential"
    /** Spec r3nw/r3ob §25.52Y.42 item 5 (c)(d): address only, same trust gate ((3)). */
    const val ADDRESS_COMMAND = "walletEoaAddress"
    /** The commands that take this shell path. */
    /** Frozen passcode protocol v1 §一第 7 条: the six passcode commands join the gated path (their field lists are PageSyncRoute's). */
    val GATED_COMMANDS: Set<String> = setOf(COMMAND, ADDRESS_COMMAND) + PageSyncRoute.PASSCODE_ALLOWED.keys
    const val CAPABILITY = "wallet.credential.v1"
    /** Frozen passcode protocol v1 §一第 5 条: the passcode capability, reported by the SDK's hello only; the shell never declares it. */
    const val PASSCODE_CAPABILITY = "wallet.passcode.v1"
    const val SHELL_RECORD_READ = "shellRecordRead"

    const val NOT_TRUSTED = "not_trusted"
    const val BAD_REQUEST = "bad_request"
    const val KEY_OVER_BRIDGE_REFUSED = "key_over_bridge_refused"
    const val UNAVAILABLE = "unavailable"
    /** shellRecordRead wire code for logical not_trusted (r3oh §25.52Y.41 item 6, §25.52D.6). */
    const val SHELL_RECORD_ORIGIN_REFUSED = "origin_refused"

    /** How a command reached the shell. Only the WebMessage listener (origin rule + main frame) may carry walletCredential. */
    enum class Channel { WEB_MESSAGE, JS_INTERFACE }

    /** Every input of the shell's trust decision (§25.52Y.38 item 2 (a)-(g)). */
    data class TrustInputs(
        /** Capability bits of the embedded PWA package, from the build manifest only (BuildConfig.PWA_CAPABILITIES). */
        val manifestCapabilities: Set<String>,
        /** zip_sha256 of the manifest the bits came from (BuildConfig.PWA_CAPABILITIES_ZIP_SHA256). */
        val manifestZipSha256: String,
        /** zip_sha256 this APK was built to load (BuildConfig.PWA_ZIP_SHA256, from pwa-embed.lock). */
        val buildZipSha256: String,
        /** The running native SDK build's own capability list (item 2 (e)). */
        val sdkCapabilities: Set<String>,
        /** zip_sha256 of the bundle whose bytes active/ provably holds now (null = not verified this process, or differs). */
        val verifiedActiveZipSha256: String?,
        val channel: Channel,
        val isMainFrame: Boolean,
        val sourceOrigin: String?,
    )

    /** The verdict names are what the logs print (no values). */
    enum class Verdict {
        TRUSTED,
        CHANNEL_REFUSED,
        FRAME_REFUSED,
        ORIGIN_REFUSED,
        NO_MANIFEST_CAPABILITY,
        MANIFEST_NOT_BOUND,
        SDK_NOT_DECLARED,
        BUNDLE_NOT_VERIFIED,
    }

    private val SHA256 = Regex("^[0-9a-f]{64}$")

    /** Verdicts that are a source or frame mismatch (r3os): answered origin_refused. */
    val SOURCE_REFUSALS: Set<Verdict> = setOf(Verdict.CHANNEL_REFUSED, Verdict.FRAME_REFUSED, Verdict.ORIGIN_REFUSED)

    /**
     * Order: channel, frame, origin (first filter only), then the build manifest, the native declaration and the bundle.
 * [requireCapability] false (shellRecordRead this round, spec r3nt §25.52Y.43 item 6 (i)): no capability
     * check on either side; the bundle must still be the verified bytes of the hash this APK was built to load.
     */
    fun evaluate(i: TrustInputs, requireCapability: Boolean = true, passcode: Boolean = false): Verdict {
        if (i.channel != Channel.WEB_MESSAGE) return Verdict.CHANNEL_REFUSED
        if (!i.isMainFrame) return Verdict.FRAME_REFUSED
        val origin = ChatOriginGate.originOf(i.sourceOrigin) ?: i.sourceOrigin?.trimEnd('/')
        if (origin != ChatOriginGate.TRUSTED) return Verdict.ORIGIN_REFUSED
        if (passcode) {
            // Passcode commands (protocol v1 §一第 5 条): the SDK must report wallet.passcode.v1 (fail closed), and the bundle must be
            // verified. The manifest capability bits are not used here; the shell declares nothing.
            if (PASSCODE_CAPABILITY !in i.sdkCapabilities) return Verdict.SDK_NOT_DECLARED
            return if (i.verifiedActiveZipSha256?.lowercase()?.let { SHA256.matches(it) } == true) Verdict.TRUSTED else Verdict.BUNDLE_NOT_VERIFIED
        }
        if (!requireCapability) {
            // r3oj (h): the embedded bundle verified against the lock, or a download verified against the published
            // update.json; the store returns a hash only for one of those two.
            return if (i.verifiedActiveZipSha256?.lowercase()?.let { SHA256.matches(it) } == true) Verdict.TRUSTED else Verdict.BUNDLE_NOT_VERIFIED
        }
        if (CAPABILITY !in i.manifestCapabilities) return Verdict.NO_MANIFEST_CAPABILITY
        val m = i.manifestZipSha256.lowercase()
        if (!SHA256.matches(m) || m != i.buildZipSha256.lowercase()) return Verdict.MANIFEST_NOT_BOUND
        if (CAPABILITY !in i.sdkCapabilities) return Verdict.SDK_NOT_DECLARED
        if (i.verifiedActiveZipSha256?.lowercase() != m) return Verdict.BUNDLE_NOT_VERIFIED
        return Verdict.TRUSTED
    }

    /** BuildConfig.PWA_CAPABILITIES is a comma-separated list written by build.gradle.kts from the manifest. */
    fun parseCapabilities(csv: String): Set<String> =
        csv.split(',').map { it.trim() }.filter { it.isNotEmpty() }.toSet()

    // ---- request (§25.52Y.38 item 3 (c)) ----

    /**
     * Key field names refused on the bridge (item 3 (c), item 14; field names compared case-insensitively). `mnemonicPhrase`
     * and `recoveryWords` are not in this set: their existing, separately ruled carriers (nativeAccountCreateResult r3ji;
     * recovery results; shellRecordRead behind [shellRecordReadVerdict]) stay as they are.
     */
    val KEY_FIELDS: Set<String> = setOf(
        "mnemonic", "eoaprivatekey", "privatekeyhex", "privatekey", "walletprivatekey", "pgpprivatekeyarmored", "privatekeyarmored", "seed",
    )

    /**
     * Item 14 for every other chat command: the two credential field names this command introduces (`mnemonic`,
     * `eoaPrivateKey`, the names of item 11 (a)) are refused in requests and replies. No existing command carries either
     * name, so no existing traffic changes; the SDK's own key_over_bridge_refused list (NativeOpenRules) stays as is.
     */
    val OTHER_COMMAND_KEY_FIELDS: Set<String> = setOf("mnemonic", "eoaprivatekey")

    /** Names that must not appear in any passcode-command reply (lower case): key material and the old/new passcode fields. */
    private val PASSCODE_REPLY_REFUSED: Set<String> = KEY_FIELDS + setOf("phrase", "oldpasscode", "newpasscode")
    private val PASSCODE_STATUS_WORD = Regex("^[a-z_]{1,24}$")

    /**
     * A reply's `passcode` field (the SDK's status, e.g. `set`) must be a status word; a digit string or any other value is a
     * leaked passcode and fails the reply (protocol v1 §3, §4: no passcode value leaves the shell).
     */
    fun passcodeStatusOnly(v: Any?): Boolean {
        fun walk(x: Any?, depth: Int): Boolean {
            if (depth > 32) return false
            return when (x) {
                is JSONObject -> x.keys().asSequence().all { k ->
                    val value = x.opt(k)
                    (k.lowercase() != "passcode" || (value is String && PASSCODE_STATUS_WORD.matches(value))) && walk(value, depth + 1)
                }
                is JSONArray -> (0 until x.length()).all { walk(x.opt(it), depth + 1) }
                else -> true
            }
        }
        return walk(v, 0)
    }

    private val REQUEST_FIELDS = setOf("type", "reqId")
    private val UNSEAL_FIELDS = setOf("type", "reqId", "mode", "blob")

    sealed class RequestCheck {
        object Pass : RequestCheck()
        /** Answer `{type:"ack", reqId, ok:false, error}` once; nothing reaches the SDK. */
        class Refuse(val reqId: Any?, val error: String, val fieldNames: List<String> = emptyList()) : RequestCheck()
    }

    /**
     * Shell checks of one walletCredential or walletEoaAddress request, before the SDK: reqId, trust, key fields, then the
     * field shape (walletEoaAddress takes only `{type, reqId}`). [verdict] is [evaluate] for this request.
     */
    fun checkRequest(body: JSONObject, verdict: Verdict): RequestCheck {
        // r3os: a source or frame mismatch on either channel answers origin_refused exactly once, before
        // any other check, whatever the command and reqId (null when invalid). The JS-interface path cannot see the frame,
        // so it counts as a frame mismatch. not_trusted is only for an allowed source whose bundle or capability fails.
        if (verdict in SOURCE_REFUSALS) return RequestCheck.Refuse(BridgeReqId.valid(body.opt("reqId")), SHELL_RECORD_ORIGIN_REFUSED)
        val reqId = BridgeReqId.valid(body.opt("reqId")) ?: return RequestCheck.Refuse(null, BAD_REQUEST)
        if (verdict != Verdict.TRUSTED) return RequestCheck.Refuse(reqId, NOT_TRUSTED)
        val keyHits = keyFieldNames(body, KEY_FIELDS)
        if (keyHits.isNotEmpty()) return RequestCheck.Refuse(reqId, KEY_OVER_BRIDGE_REFUSED, keyHits)
        val names = body.keys().asSequence().toSet()
        // Passcode commands: their own credential names (per command) and their own field list only (protocol v1 §一第 6 条).
        PageSyncRoute.allowedFieldsFor(body.optString("type"))?.let { allowed ->
            val passcodeHits = keyFieldNames(body, PageSyncRoute.forbiddenFieldsFor(body.optString("type")))
            if (passcodeHits.isNotEmpty()) return RequestCheck.Refuse(reqId, KEY_OVER_BRIDGE_REFUSED, passcodeHits)
            return if (names.all { it in allowed }) RequestCheck.Pass else RequestCheck.Refuse(reqId, BAD_REQUEST)
        }
        val shapeOk = when {
            body.optString("type") == ADDRESS_COMMAND -> names == REQUEST_FIELDS
            !body.has("mode") -> names == REQUEST_FIELDS
            else -> names == UNSEAL_FIELDS && body.opt("mode") == "unseal" && (body.opt("blob") as? String)?.isNotEmpty() == true
        }
        if (!shapeOk) return RequestCheck.Refuse(reqId, BAD_REQUEST)
        return RequestCheck.Pass
    }

    // ---- response (§25.52Y.38 item 3 (e), item 12 (c), item 14 W-N3) ----

    private val EOA = Regex("^0x[0-9a-f]{40}$")
    private val MNEMONIC = Regex("^[a-z]+( [a-z]+){11}$|^[a-z]+( [a-z]+){23}$")
    private val RESULT_MNEMONIC = setOf("eoa", "credentialKind", "mnemonic")

    /**
     * Whether the SDK's ack for [command] may go to the page as is; when false it is replaced by
     * `{type:"ack", reqId, ok:false, error:"key_over_bridge_refused"}` (no field of it passes).
     * A failure ack passes only without a result and with no key field.
 * walletCredential success: the mnemonic path only (§25.52Y.42 item 5 (b): an eoa_key account answers
     * `unavailable`, so a reply with `eoaPrivateKey` never passes). walletEoaAddress success: `result` is exactly `{eoa}`.
     */
    fun responseAllowed(event: JSONObject, command: String = COMMAND): Boolean {
        // Passcode replies (protocol v1): no key field and no passcode or phrase name anywhere in the reply; the result shape is the
        // SDK's own (passcode:"set", eoa, verifiedAddress, ...), not the walletCredential mnemonic shape.
        if (command in PageSyncRoute.PASSCODE_ALLOWED) return keyFieldNames(event, PASSCODE_REPLY_REFUSED).isEmpty() && passcodeStatusOnly(event)
        if (event.optString("type") != "ack") return keyFieldNames(event, KEY_FIELDS).isEmpty()
        if (event.opt("ok") != true) return !event.has("result") && keyFieldNames(event, KEY_FIELDS).isEmpty()
        val r = event.optJSONObject("result") ?: return false
        val outside = JSONObject(event.toString()).apply { remove("result") }
        if (keyFieldNames(outside, KEY_FIELDS).isNotEmpty()) return false
        val names = r.keys().asSequence().toSet()
        if (!EOA.matches(r.optString("eoa"))) return false
        if (command == ADDRESS_COMMAND) return names == setOf("eoa")
        val core = names - "blob"
        if ("blob" in names && r.opt("blob") !is String) return false
        return r.optString("credentialKind") == "mnemonic" && core == RESULT_MNEMONIC && MNEMONIC.matches(r.optString("mnemonic"))
    }

    /**
 * W-L5 on the shell side (r3oh §25.52Y.38 item 8 (8e)): a walletCredential ack with
     * `credentialKind = "eoa_key"`, or an `eoaPrivateKey` field with no `mnemonic`, becomes `unavailable`, never reaching
     * the page, whatever the SDK did.
     */
    fun eoaKeyReply(event: JSONObject): Boolean =
        event.optJSONObject("result")?.optString("credentialKind") == "eoa_key" ||
            (keyFieldNames(event, setOf("eoaprivatekey")).isNotEmpty() && keyFieldNames(event, setOf("mnemonic")).isEmpty())
    // A reply with both mnemonic and eoaPrivateKey is W-N3, not W-L5: it fails responseAllowed and answers
    // key_over_bridge_refused (§25.52Y.38 item 3 (c); same as the iOS shell).

    // ---- other commands (§25.52Y.38 item 14: rules unchanged, walletCredential is the single exception) ----

    /** Names (lower case, sorted) of key fields anywhere in [v]; empty when there are none. Values are never read out. */
    fun keyFieldNames(v: Any?, names: Set<String>): List<String> {
        val out = sortedSetOf<String>()
        fun walk(x: Any?, depth: Int) {
            if (depth > 32) return
            when (x) {
                is JSONObject -> x.keys().forEach { k -> if (k.lowercase() in names) out += k.lowercase(); walk(x.opt(k), depth + 1) }
                is JSONArray -> for (n in 0 until x.length()) walk(x.opt(n), depth + 1)
            }
        }
        walk(v, 0)
        return out.toList()
    }

    /** W-N1: another chat command's request may reach the SDK only without `mnemonic` / `eoaPrivateKey`. */
    fun otherCommandRequestKeyFields(body: JSONObject): List<String> = keyFieldNames(body, OTHER_COMMAND_KEY_FIELDS)

    /** W-N2: an SDK payload for another command may reach the page only without `mnemonic` / `eoaPrivateKey`. */
    fun otherCommandPayloadKeyFields(payload: JSONObject): List<String> = keyFieldNames(payload, OTHER_COMMAND_KEY_FIELDS)

    // ---- shellRecordRead (§25.52Y.41) ----

    /** W-class read-back fields (§25.52P.2): profiles[*].privateKeyArmor, top-level mnemonicPhrase and recoveryWords. */
    val W_FIELDS: Set<String> = setOf("privateKeyArmor", "mnemonicPhrase", "recoveryWords")

    /** Names of non-empty W fields anywhere in a shellRecordRead reply (field names only). */
    fun wFieldNames(reply: String): List<String> {
        val root = runCatching { JSONObject(reply) }.getOrNull() ?: return emptyList()
        val out = sortedSetOf<String>()
        fun nonEmpty(x: Any?) = when (x) {
            null, JSONObject.NULL -> false
            is String -> x.isNotEmpty()
            is JSONArray -> x.length() > 0
            is JSONObject -> x.length() > 0
            else -> true
        }
        fun walk(x: Any?, depth: Int) {
            if (depth > 32) return
            when (x) {
                is JSONObject -> x.keys().forEach { k -> if (k in W_FIELDS && nonEmpty(x.opt(k))) out += k; walk(x.opt(k), depth + 1) }
                is JSONArray -> for (n in 0 until x.length()) walk(x.opt(n), depth + 1)
            }
        }
        walk(root, 0)
        return out.toList()
    }

    /**
     * §25.52Y.41 items 1-7: a shellRecordRead reply that carries any W field goes to the page only when the request passed
     * the trust gate (origin, main frame, verified bundle; the capability part joins later, §25.52Y.43 item 6 (ii));
     * otherwise the whole reply becomes `not_trusted` (no partial fields). A reply without W fields is unchanged (item 4).
     */
    fun gateShellRecordRead(request: String, reply: String, verdict: () -> Verdict): ShellRecordGateResult {
        if (runCatching { JSONObject(request).optString("type") }.getOrNull() != SHELL_RECORD_READ) return ShellRecordGateResult(reply, null, emptyList())
        val names = wFieldNames(reply)
        if (names.isEmpty()) return ShellRecordGateResult(reply, null, names)
        val v = verdict() // evaluated only when W fields would go out (hashing active/ is the costly step)
        if (v == Verdict.TRUSTED) return ShellRecordGateResult(reply, v, names)
        // r3ow §25.52Y.41 item 6 : for shellRecordRead / shellRecordWrite both a source/frame
        // mismatch and a bundle failure answer origin_refused (exception to r3os item 4: the PWA does not handle
        // not_trusted yet). not_trusted is only for the two new commands.
        return ShellRecordGateResult(shellRecordRefusal(BridgeReqId.fromJsonText(request)), v, names)
    }

    /** [reply] goes to the page; [verdict] is null when no W field was involved; [wFields] are names only. */
    class ShellRecordGateResult(val reply: String, val verdict: Verdict?, val wFields: List<String>)

    /**
     * The shellRecordRead answer for logical not_trusted: the envelope-level error `{type:"ack", reqId, ok:false,
     * error:"origin_refused"}` (r3ok §25.52D.6 note, §25.52AB.3, §25.52CJ.3), never inside `result.code`. No record.
     */
    fun shellRecordRefusal(reqId: Any?): String = refusal(reqId, SHELL_RECORD_ORIGIN_REFUSED).toString()

    /** r3oo storage-error shape for an exception in the read-back gate: `{ok:true, result:{code:"error", sub:"record_unreadable"}}`. */
    fun shellRecordUnreadable(reqId: Any?): String =
        JSONObject().put("type", "ack").put("reqId", reqId ?: JSONObject.NULL).put("ok", true)
            .put("result", JSONObject().put("code", "error").put("sub", "record_unreadable")).toString()

    /**
     * r3os: the window channel's first check, before JSON parsing or anything else: a message that is not from the main
     * frame of the allowed origin answers origin_refused exactly once (reqId echoed when the text is JSON with a valid
     * reqId, else null). Null when the source is allowed.
     */
    fun windowSourceRefusal(data: String?, isMainFrame: Boolean, sourceOrigin: String?): String? {
        val origin = ChatOriginGate.originOf(sourceOrigin) ?: sourceOrigin?.trimEnd('/')
        if (isMainFrame && origin == ChatOriginGate.TRUSTED) return null
        return shellRecordRefusal(data?.let { BridgeReqId.fromJsonText(it) })
    }

    /**
 * r3ok / (§25.52Y.42 item 5 (d)): walletEoaAddress checks origin, main frame and the bundle hash only, no
     * capability bit; walletCredential keeps the dual capability check (§25.52Y.38 item 2).
     */
    fun requiresCapability(command: String): Boolean = command != ADDRESS_COMMAND

    fun refusal(reqId: Any?, error: String): JSONObject =
        JSONObject().put("type", "ack").put("reqId", reqId ?: JSONObject.NULL).put("ok", false).put("error", error)

    // ---- window channel (BeamioShellRecord): walletEoaAddress / walletCredential ----

    /** [reply] goes to the page; [logs] are names, verdicts, codes and durations only. */
    class WindowResult(val reply: String, val logs: List<String>)

    /**
     * The window-channel path of a gated command (the SDK answers walletEoaAddress on the window channel, behind the same
 * boundary as shellRecord in the SDK). Shell side, in order: reqId; trust [verdict] (manifest bit,
     * native declaration, verified bundle, origin, main frame: §25.52Y.42 item 5 (d) = §25.52Y.38 item 2); request shape
     * and key fields; then [sdk]; then the reply check (walletCredential eoa_key -> unavailable, W-L5; otherwise
     * [responseAllowed] for the command, else key_over_bridge_refused). Refusals use `{type:"ack", reqId, ok:false, error}`
     * (the SDK's own window-channel shape for these commands). [sdk] runs only for a trusted, well-formed request.
     */
    fun windowCredential(body: JSONObject, verdict: () -> Verdict, sdk: () -> String, clock: () -> Long): WindowResult {
        val started = clock()
        val command = body.optString("type")
        val rid = BridgeReqId.valid(body.opt("reqId"))
        val logs = mutableListOf<String>()
        fun done(ev: JSONObject, raw: String? = null, names: List<String> = emptyList()): WindowResult {
            logs += replyLine(command, ev, clock() - started, names) // log point 2
            return WindowResult(raw ?: ev.toString(), logs)
        }
        return try {
            val v = verdict()
            logs += entryLine(command, rid, v) // log point 1
            // r3or §25.52Y.44 item 4 (source first): on the window channel a frame or origin mismatch answers
            // origin_refused exactly once (reqId echoed when valid, else null), before any other check.
            if (v in SOURCE_REFUSALS) return done(refusal(rid, SHELL_RECORD_ORIGIN_REFUSED))
            if (rid == null) return done(refusal(null, BAD_REQUEST))
            when (val c = checkRequest(body, v)) {
                is RequestCheck.Refuse -> done(refusal(c.reqId, c.error), names = c.fieldNames)
                RequestCheck.Pass -> {
                    val raw = sdk()
                    val ev = runCatching { JSONObject(raw) }.getOrNull() ?: return done(refusal(rid, UNAVAILABLE))
                    when {
                        command == COMMAND && eoaKeyReply(ev) -> done(refusal(rid, UNAVAILABLE))
                        BridgeReqId.valid(ev.opt("reqId")) != rid -> done(refusal(rid, UNAVAILABLE))
                        !responseAllowed(ev, command) -> done(refusal(rid, KEY_OVER_BRIDGE_REFUSED))
                        else -> done(ev, raw)
                    }
                }
            }
        } catch (e: Exception) {
            logs += errorLine(command, rid, e) // log point 3
            done(refusal(rid, UNAVAILABLE))
        }
    }

    // ---- log lines (§25.52Y.38 item 11 (c) points 1-3) ----

    /** Point 1, request entry: command name, reqId, origin/trust verdict. */
    fun entryLine(command: String, reqId: Any?, verdict: Verdict): String =
        "entry cmd=$command reqId=${reqId ?: "null"} verdict=$verdict"

    /** Point 2, reply sent: command name, reqId, ok, error code, duration; never result or blob. */
    fun replyLine(command: String, event: JSONObject, ms: Long, fieldNames: List<String> = emptyList()): String {
        val ok = event.opt("ok") == true
        val err = if (ok) "" else event.optString("error").takeIf { it.matches(Regex("^[a-z_]{1,40}$")) } ?: "<other>"
        val fields = if (fieldNames.isEmpty()) "" else " fields=$fieldNames"
        return "reply cmd=$command reqId=${BridgeReqId.valid(event.opt("reqId")) ?: "null"} ok=$ok error=$err ms=$ms$fields"
    }

    /** Point 3, error filter: what an exception on this path may log (class name only, never message or stack values). */
    fun errorLine(command: String, reqId: Any?, e: Throwable): String =
        "error cmd=$command reqId=${reqId ?: "null"} exception=${e.javaClass.simpleName}"
}
