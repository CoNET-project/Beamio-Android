package com.beamio.app.credential

import com.beamio.app.ChatOriginGate
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Contract v3.3 §十一 and errata E1 (shell side): pwaWalletSync / nativeMnemonicPreread, flat or nested, meet the trust gate
 * before anything else. An untrusted source is answered untrusted_source and never reaches the SDK, even when the body also
 * carries credential fields or the page's own trustedOrigin.
 */
class PageSyncRouteTest {
    private val eoa = "0x" + "a".repeat(40)

    private fun flat(type: String, extra: Map<String, Any> = emptyMap()): String {
        val o = JSONObject().put("type", type).put("reqId", 7)
        extra.forEach { (k, v) -> o.put(k, v) }
        return o.toString()
    }

    private fun nested(type: String): String =
        JSONObject().put("command", JSONObject().put("type", type).put("reqId", 7).put("seq", 3)).toString()

    // Routing: both shapes reach the gate; other commands keep their path

    @Test
    fun flatAndNestedPageSyncRequestsAreRouted() {
        assertEquals("pwaWalletSync", PageSyncRoute.normalize(flat("pwaWalletSync"))?.optString("type"))
        assertEquals("nativeMnemonicPreread", PageSyncRoute.normalize(nested("nativeMnemonicPreread"))?.optString("type"))
        assertEquals("pwaWalletSync", PageSyncRoute.normalize(nested("pwaWalletSync"))?.optString("type"))
    }

    @Test
    fun otherCommandsAreNotRoutedToThePageSyncGate() {
        assertNull(PageSyncRoute.normalize(flat("chatSend")))
        assertNull(PageSyncRoute.normalize(JSONObject().put("command", JSONObject().put("type", "chatSend")).toString()))
        assertNull(PageSyncRoute.normalize("not json"))
    }

    // Untrusted source: untrusted_source, nothing forwarded, page trustedOrigin ignored

    @Test
    fun untrustedPwaWalletSyncAnswersUntrustedSource() {
        val refusal = PageSyncRoute.refusalBeforeSdk(JSONObject(flat("pwaWalletSync", mapOf("phrase" to "w w"))), trusted = false)
        assertEquals("untrusted_source", refusal?.optString("error"))
        assertEquals(false, refusal?.optBoolean("ok"))
        assertEquals(7, refusal?.optInt("reqId"))
    }

    @Test
    fun untrustedPrereadAnswersUntrustedSourceEvenWithPageTrustedOriginTrue() {
        val body = JSONObject(flat("nativeMnemonicPreread", mapOf("trustedOrigin" to true, "seq" to 3)))
        assertEquals("untrusted_source", PageSyncRoute.refusalBeforeSdk(body, trusted = false)?.optString("error"))
    }

    @Test
    fun untrustedNestedRequestAnswersUntrustedSource() {
        val nestedBody = JSONObject(nested("nativeMnemonicPreread")).getJSONObject("command")
        assertEquals("untrusted_source", PageSyncRoute.refusalBeforeSdk(nestedBody, trusted = false)?.optString("error"))
    }

    @Test
    fun trustFirstEvenWhenCredentialFieldsArePresent() {
        val body = JSONObject(flat("nativeMnemonicPreread", mapOf("mnemonic" to "x")))
        assertEquals("untrusted_source", PageSyncRoute.refusalBeforeSdk(body, trusted = false)?.optString("error"))
    }

    // Trusted source: credential fields refused, clean requests forwarded

    @Test
    fun trustedPrereadWithAnyCredentialFieldIsRefused() {
        for (field in listOf("phrase", "mnemonic", "privateKeyHex", "recoveryCode", "pin", "password")) {
            val body = JSONObject(flat("nativeMnemonicPreread", mapOf(field to "x", "seq" to 3)))
            assertEquals(field, "key_over_bridge_refused", PageSyncRoute.refusalBeforeSdk(body, trusted = true)?.optString("error"))
        }
    }

    @Test
    fun trustedPwaWalletSyncAllowsPhraseOnly() {
        val ok = JSONObject(flat("pwaWalletSync", mapOf("phrase" to "w w", "eoa" to eoa, "seq" to 3)))
        assertNull(PageSyncRoute.refusalBeforeSdk(ok, trusted = true))
        val bad = JSONObject(flat("pwaWalletSync", mapOf("privateKeyHex" to "x", "phrase" to "w w")))
        assertEquals("key_over_bridge_refused", PageSyncRoute.refusalBeforeSdk(bad, trusted = true)?.optString("error"))
    }

    @Test
    fun trustedPreadWithSeqZeroIsForwardedToTheSdk() {
        // E3: seq 0 is a legal non-negative integer; the shell does not judge seq (the SDK does).
        val body = JSONObject(flat("nativeMnemonicPreread", mapOf("seq" to 0)))
        assertNull(PageSyncRoute.refusalBeforeSdk(body, trusted = true))
    }

    @Test
    fun nestedCredentialFieldIsRefusedWhenTrusted() {
        val body = JSONObject().put("type", "nativeMnemonicPreread").put("reqId", 7).put("seq", 1)
            .put("nested", JSONObject().put("pin", "1234")).toString()
        assertEquals("key_over_bridge_refused", PageSyncRoute.refusalBeforeSdk(JSONObject(body), trusted = true)?.optString("error"))
    }

    @Test
    fun forbiddenFieldSetsDiffer() {
        assertFalse(PageSyncRoute.forbiddenFieldsFor("pwaWalletSync").contains("phrase"))
        assertTrue(PageSyncRoute.forbiddenFieldsFor("nativeMnemonicPreread").contains("phrase"))
    }

    // E6 (contract v3.3.1 errata E6, vectors E6-add): restricted return of nativeMnemonicPreread

    private val phraseSynthetic = "synthetic one two three"

    /** NE-04 / NE-05 (child frame or untrusted origin): untrusted_source, no phrase, and the SDK is not called. */
    @Test
    fun ne04ne05ChildFrameOrUntrustedOriginGetsUntrustedSourceWithNoPhrase() {
        val body = JSONObject(flat("nativeMnemonicPreread", mapOf("seq" to 4, "trustedOrigin" to true)))
        val refusal = PageSyncRoute.refusalBeforeSdk(body, trusted = false)
        assertEquals("untrusted_source", refusal?.optString("error"))
        assertEquals(false, refusal?.optBoolean("ok"))
        assertFalse(refusal.toString().contains("phrase"))
        assertFalse(refusal!!.has("result"))
    }

    /** Positive (PE-01): a trusted top frame may reach the SDK; the SDK's valid answer passes the shell's filter unchanged. */
    @Test
    fun trustedTopFramePrereadReachesTheSdkAndItsAnswerPasses() {
        val body = JSONObject(flat("nativeMnemonicPreread", mapOf("seq" to 1)))
        assertNull("forwarded to the SDK", PageSyncRoute.refusalBeforeSdk(body, trusted = true))
        val sdkAnswer = JSONObject()
            .put("type", "ack").put("reqId", 21).put("ok", true)
            .put("result", JSONObject().put("state", "valid").put("eoa", eoa).put("phrase", phraseSynthetic))
        val filtered = SdkPayloadFilter { 0L }.filter(JSONObject().put("action", "chatModuleEvent").put("event", sdkAnswer))
        val event = filtered.payload?.optJSONObject("event")
        assertEquals("valid", event?.optJSONObject("result")?.optString("state"))
        assertEquals(phraseSynthetic, event?.optJSONObject("result")?.optString("phrase"))
    }

    /** NE-07: the shell's log lines for these paths carry the command, trust outcome, reqId and error code, never the reply. */
    @Test
    fun ne07ShellLogLinesNeverCarryTheReply() {
        val lines = listOf(
            PageSyncRoute.logLine("nativeMnemonicPreread", trusted = false, reqId = 24, error = "untrusted_source"),
            PageSyncRoute.logLine("nativeMnemonicPreread", trusted = true, reqId = 21, error = null),
            PageSyncRoute.logLine("pwaWalletSync", trusted = true, reqId = null, error = "stale_seq"),
        )
        for (line in lines) {
            assertFalse(line, line.contains(phraseSynthetic))
            assertFalse(line, line.contains(eoa))
            assertFalse(line, line.contains("phrase"))
        }
        assertEquals("nativeMnemonicPreread gate trusted=false reqId=24 error=untrusted_source", lines[0])
    }

    // Channel verdicts: the page-sync trust outcome comes from the real channel, frame and origin.
    // The JS interface cannot tell the frame, so it is never trusted; a child frame or another origin on WebMessage is refused.

    private val sha = "a".repeat(64)

    private fun inputs(channel: WalletCredentialGate.Channel, isMainFrame: Boolean, origin: String?) =
        WalletCredentialGate.TrustInputs(
            manifestCapabilities = setOf(WalletCredentialGate.CAPABILITY), manifestZipSha256 = sha, buildZipSha256 = sha,
            sdkCapabilities = setOf(WalletCredentialGate.CAPABILITY), verifiedActiveZipSha256 = sha,
            channel = channel, isMainFrame = isMainFrame, sourceOrigin = origin,
        )

    @Test
    fun jsInterfaceIsNeverTrustedEvenOnTheMainFrame() {
        val v = WalletCredentialGate.evaluate(inputs(WalletCredentialGate.Channel.JS_INTERFACE, true, ChatOriginGate.TRUSTED), requireCapability = false)
        assertEquals(WalletCredentialGate.Verdict.CHANNEL_REFUSED, v)
        val body = JSONObject(flat("pwaWalletSync", mapOf("phrase" to "w w")))
        assertEquals("untrusted_source", PageSyncRoute.refusalBeforeSdk(body, trusted = v == WalletCredentialGate.Verdict.TRUSTED)?.optString("error"))
    }

    @Test
    fun webMessageChildFrameAndOtherOriginAreRefused() {
        val child = WalletCredentialGate.evaluate(inputs(WalletCredentialGate.Channel.WEB_MESSAGE, false, ChatOriginGate.TRUSTED), requireCapability = false)
        assertEquals(WalletCredentialGate.Verdict.FRAME_REFUSED, child)
        val other = WalletCredentialGate.evaluate(inputs(WalletCredentialGate.Channel.WEB_MESSAGE, true, "https://evil.example"), requireCapability = false)
        assertEquals(WalletCredentialGate.Verdict.ORIGIN_REFUSED, other)
    }

    @Test
    fun webMessageTrustedMainFrameIsTrusted() {
        val v = WalletCredentialGate.evaluate(inputs(WalletCredentialGate.Channel.WEB_MESSAGE, true, ChatOriginGate.TRUSTED), requireCapability = false)
        assertEquals(WalletCredentialGate.Verdict.TRUSTED, v)
    }

    // ShellRecordChannel (BeamioShellRecord WebMessage) answers: synthetic values only

    private fun sdkBareAck(reqId: Int) = JSONObject()
        .put("type", "ack").put("reqId", reqId).put("ok", true)
        .put("result", JSONObject().put("state", "valid").put("eoa", eoa).put("phrase", phraseSynthetic))

    /** Trusted main frame: the request reaches the SDK once with the shell's marker, and the SDK's bare ack comes back unchanged. */
    @Test
    fun trustedChannelRequestReachesTheSdkAndReturnsItsAck() {
        val body = JSONObject(flat("nativeMnemonicPreread", mapOf("seq" to 2, "trustedOrigin" to false)))
        var calls = 0
        var seen: JSONObject? = null
        val answer = PageSyncRoute.channelAnswer(body, trusted = true) { b -> calls++; seen = JSONObject(b.toString()); sdkBareAck(7) }
        assertEquals(1, calls)
        assertEquals(true, seen?.optBoolean("trustedOrigin"))
        assertEquals(7, answer?.optInt("reqId"))
        assertEquals(true, answer?.optBoolean("ok"))
    }

    /** Pwa-supplied trustedOrigin is never the source of trust: an untrusted request is refused and the SDK is not called. */
    @Test
    fun untrustedRequestsNeverReachTheSdkEvenWithAPageTrustedOrigin() {
        for (kind in listOf("child-frame", "other-origin", "js-interface")) {
            val body = JSONObject(flat("pwaWalletSync", mapOf("trustedOrigin" to true, "phrase" to "w w", "seq" to 3)))
            var calls = 0
            val answer = PageSyncRoute.channelAnswer(body, trusted = false) { calls++; sdkBareAck(7) }
            assertEquals(kind, 0, calls)
            assertEquals(kind, "untrusted_source", answer?.optString("error"))
            assertFalse(kind, answer.toString().contains("phrase"))
        }
    }

    /** The JS interface verdict is CHANNEL_REFUSED even on the main frame, so the same untrusted path applies. */
    @Test
    fun jsInterfaceVerdictLeadsToUntrustedSourceWithoutSdk() {
        val v = WalletCredentialGate.evaluate(inputs(WalletCredentialGate.Channel.JS_INTERFACE, true, ChatOriginGate.TRUSTED), requireCapability = false)
        var calls = 0
        val answer = PageSyncRoute.channelAnswer(JSONObject(flat("nativeMnemonicPreread", mapOf("seq" to 1))), trusted = v == WalletCredentialGate.Verdict.TRUSTED) { calls++; sdkBareAck(7) }
        assertEquals(0, calls)
        assertEquals("untrusted_source", answer?.optString("error"))
    }

    /** Nested request shape is accepted the same way on the channel. */
    @Test
    fun nestedRequestOnTheChannelIsRoutedAndTrusted() {
        val nestedBody = JSONObject(nested("nativeMnemonicPreread")).getJSONObject("command")
        var calls = 0
        val answer = PageSyncRoute.channelAnswer(nestedBody, trusted = true) { calls++; sdkBareAck(7) }
        assertEquals(1, calls)
        assertEquals(true, answer?.optBoolean("ok"))
    }

    /** NE-07 on the channel: the log line for the answered request carries no phrase and no address. */
    @Test
    fun channelLogLineCarriesNoReplyContent() {
        val answer = PageSyncRoute.channelAnswer(JSONObject(flat("nativeMnemonicPreread", mapOf("seq" to 2))), trusted = true) { sdkBareAck(7) }
        val line = PageSyncRoute.logLine("nativeMnemonicPreread", true, 7, answer?.optString("error")?.takeIf { it.isNotEmpty() })
        assertFalse(line, line.contains(phraseSynthetic))
        assertFalse(line, line.contains(eoa))
        assertEquals("nativeMnemonicPreread gate trusted=true reqId=7 error=none", line)
    }

    // pwaEmptySignal (changes native state): same trust gate. Synthetic values only.

    @Test
    fun pwaEmptySignalIsRoutedFlatAndNested() {
        assertEquals("pwaEmptySignal", PageSyncRoute.normalize(flat("pwaEmptySignal"))?.optString("type"))
        assertEquals("pwaEmptySignal", PageSyncRoute.normalize(nested("pwaEmptySignal"))?.optString("type"))
    }

    /** Positive: a trusted main frame reaches the SDK once; its bare ack comes back unchanged. */
    @Test
    fun trustedPwaEmptySignalReachesTheSdk() {
        var calls = 0
        val answer = PageSyncRoute.channelAnswer(JSONObject(flat("pwaEmptySignal", mapOf("seq" to 9))), trusted = true) {
            calls++
            JSONObject().put("type", "ack").put("reqId", 7).put("ok", true)
        }
        assertEquals(1, calls)
        assertEquals(true, answer?.optBoolean("ok"))
    }

    /** Negative: child frame, other origin and the JS interface are refused before the SDK, whatever the page claims. */
    @Test
    fun untrustedPwaEmptySignalNeverReachesTheSdk() {
        val cases = listOf(
            "child-frame" to WalletCredentialGate.evaluate(inputs(WalletCredentialGate.Channel.WEB_MESSAGE, false, ChatOriginGate.TRUSTED), requireCapability = false),
            "other-origin" to WalletCredentialGate.evaluate(inputs(WalletCredentialGate.Channel.WEB_MESSAGE, true, "https://evil.example"), requireCapability = false),
            "js-interface" to WalletCredentialGate.evaluate(inputs(WalletCredentialGate.Channel.JS_INTERFACE, true, ChatOriginGate.TRUSTED), requireCapability = false),
        )
        for ((kind, verdict) in cases) {
            var calls = 0
            val answer = PageSyncRoute.channelAnswer(
                JSONObject(flat("pwaEmptySignal", mapOf("trustedOrigin" to true, "seq" to 9))),
                trusted = verdict == WalletCredentialGate.Verdict.TRUSTED,
            ) { calls++; JSONObject().put("type", "ack").put("ok", true) }
            assertEquals(kind, 0, calls)
            assertEquals(kind, "untrusted_source", answer?.optString("error"))
        }
    }

    /** Negative: a trusted pwaEmptySignal carrying a credential field is refused (no phrase on this command). */
    @Test
    fun trustedPwaEmptySignalWithCredentialFieldIsRefused() {
        val body = JSONObject(flat("pwaEmptySignal", mapOf("phrase" to "x", "seq" to 9)))
        assertEquals("key_over_bridge_refused", PageSyncRoute.refusalBeforeSdk(body, trusted = true)?.optString("error"))
    }

    // M6, method Y (passcode-preserving unlock sync, passcode-unlock-sync-vectors.v1.json gateCases).
    // Synthetic shape-only values: the shell never opens the envelope; nothing here is a real phrase, passcode or key.

    private val synthPasscode = "246813"
    private fun v3Envelope(): JSONObject = JSONObject().put("v", 3).put("mode", "passcode").put("eoa", eoa)
        .put("kdf", "argon2id/m=32768/t=3/p=1/dkLen=32").put("salt", "c2FsdA").put("iv", "aXY").put("alg", "AES-256-GCM").put("ct", "Y3Q")

    private fun mgSync(vararg fields: Pair<String, Any?>): JSONObject {
        val o = JSONObject().put("type", "pwaWalletSync").put("reqId", 11)
        fields.forEach { (k, v) -> o.put(k, v ?: JSONObject.NULL) }
        return JSONObject(o.toString()) // as the page's JSON text arrives
    }

    private fun mgRefusal(body: JSONObject): String? = PageSyncRoute.refusalBeforeSdk(body, trusted = true)?.optString("error")

    private val hashMg = "b".repeat(64)
    private fun mgInputs(sdk: Set<String>, verified: String? = hashMg, origin: String? = ChatOriginGate.TRUSTED, mainFrame: Boolean = true) =
        WalletCredentialGate.TrustInputs(
            manifestCapabilities = emptySet(), manifestZipSha256 = "", buildZipSha256 = hashMg, sdkCapabilities = sdk,
            verifiedActiveZipSha256 = verified, channel = WalletCredentialGate.Channel.WEB_MESSAGE, isMainFrame = mainFrame, sourceOrigin = origin,
        )

    /** The shell's own path (ShellRecordChannel): verdict with requireCapability=false, then channelAnswer. */
    private fun mgAnswer(body: JSONObject, inputs: WalletCredentialGate.TrustInputs): Pair<JSONObject?, JSONObject?> {
        val cmd = body.optString("type")
        val trusted = WalletCredentialGate.evaluate(inputs, requireCapability = false, passcode = cmd in PageSyncRoute.PASSCODE_ALLOWED) ==
            WalletCredentialGate.Verdict.TRUSTED
        var forwarded: JSONObject? = null
        val answer = PageSyncRoute.channelAnswer(body, trusted) { fwd -> forwarded = JSONObject(fwd.toString()); sdkBareAck(11) }
        return answer to forwarded
    }

    @Test
    fun mg01CipherWithSixDigitPasscodeIsForwardedWithTheShellMarkerOnly() {
        val body = mgSync("eoa" to eoa, "cipher" to v3Envelope(), "passcode" to synthPasscode, "seq" to 4)
        assertNull(mgRefusal(JSONObject(body.toString())))
        val (_, fwd) = mgAnswer(body, mgInputs(setOf("identity.native-keys.v1")))
        assertTrue(fwd != null)
        assertEquals(setOf("type", "reqId", "eoa", "cipher", "passcode", "seq", "trustedOrigin"), fwd!!.keys().asSequence().toSet())
        assertEquals(true, fwd.opt("trustedOrigin"))
    }

    @Test
    fun mg02ForwardedWhetherOrNotTheHelloDeclaresWalletPasscode() {
        for (declared in listOf(true, false)) {
            val sdk = if (declared) setOf("identity.native-keys.v1", WalletCredentialGate.PASSCODE_CAPABILITY) else setOf("identity.native-keys.v1")
            val (answer, fwd) = mgAnswer(mgSync("eoa" to eoa, "cipher" to v3Envelope(), "passcode" to synthPasscode, "seq" to 4), mgInputs(sdk))
            assertTrue("declared=$declared", fwd != null)
            assertEquals("declared=$declared", true, answer?.optBoolean("ok"))
        }
    }

    @Test
    fun mg03PasscodeWithPhraseAndNoCipherIsRefused() {
        assertEquals("key_over_bridge_refused", mgRefusal(mgSync("eoa" to eoa, "phrase" to "w w", "passcode" to synthPasscode, "seq" to 4)))
    }

    @Test
    fun mg04PasscodeAloneIsRefused() {
        assertEquals("key_over_bridge_refused", mgRefusal(mgSync("eoa" to eoa, "passcode" to synthPasscode, "seq" to 4)))
    }

    @Test
    fun mg05CipherTogetherWithPhraseIsRefused() {
        assertEquals("key_over_bridge_refused", mgRefusal(mgSync("eoa" to eoa, "cipher" to v3Envelope(), "phrase" to "w w", "seq" to 4)))
        assertEquals("key_over_bridge_refused",
            mgRefusal(mgSync("eoa" to eoa, "cipher" to v3Envelope(), "phrase" to "w w", "passcode" to synthPasscode, "seq" to 4)))
    }

    @Test
    fun mg06PasscodeThatIsNotASixDigitStringIsBadRequest() {
        for (p in listOf<Any?>("12345", "1234567", "abcdef", 123456, null)) {
            val (answer, fwd) = mgAnswer(mgSync("eoa" to eoa, "cipher" to v3Envelope(), "passcode" to p, "seq" to 4), mgInputs(emptySet()))
            assertEquals("passcode=$p", "bad_request", answer?.optString("error"))
            assertEquals("passcode=$p", false, answer?.optBoolean("ok", true))
            assertNull("passcode=$p forwarded", fwd)
        }
    }

    @Test
    fun mg07CipherThatIsNotAV3PasscodeEnvelopeIsBadRequest() {
        val notV3 = listOf<Any?>("text", 1, null, org.json.JSONArray(), JSONObject().put("v", 2),
            v3Envelope().put("v", "3"), v3Envelope().put("mode", "plain"), v3Envelope().apply { remove("ct") })
        for (c in notV3) {
            val (answer, fwd) = mgAnswer(mgSync("eoa" to eoa, "cipher" to c, "passcode" to synthPasscode, "seq" to 4), mgInputs(emptySet()))
            assertEquals("cipher=$c", "bad_request", answer?.optString("error"))
            assertNull("cipher=$c forwarded", fwd)
        }
    }

    @Test
    fun mg08AnyOtherCredentialFieldIsRefusedWithOrWithoutCipher() {
        for (k in listOf("privateKey", "mnemonic", "recoveryCode", "privateKeyHex", "walletPrivateKey", "seed", "pin", "password")) {
            assertEquals(k, "key_over_bridge_refused",
                mgRefusal(mgSync("eoa" to eoa, "cipher" to v3Envelope(), "passcode" to synthPasscode, k to "x", "seq" to 4)))
            assertEquals(k, "key_over_bridge_refused", mgRefusal(mgSync("eoa" to eoa, "phrase" to "w w", k to "x", "seq" to 4)))
        }
        // A passcode hidden below the top level is not the allowed field.
        val nested = mgSync("eoa" to eoa, "cipher" to v3Envelope().put("passcode", synthPasscode), "passcode" to synthPasscode, "seq" to 4)
        assertEquals("key_over_bridge_refused", mgRefusal(nested))
    }

    @Test
    fun mg09UntrustedSourceOrUnverifiedBundleIsRefusedForEveryForm() {
        val forms = listOf(
            mgSync("eoa" to eoa, "cipher" to v3Envelope(), "passcode" to synthPasscode, "seq" to 4),
            mgSync("eoa" to eoa, "passcode" to synthPasscode, "seq" to 4),
            mgSync("eoa" to eoa, "cipher" to v3Envelope(), "passcode" to "1", "seq" to 4),
        )
        val bad = listOf(
            mgInputs(setOf(WalletCredentialGate.PASSCODE_CAPABILITY), verified = null),
            mgInputs(setOf(WalletCredentialGate.PASSCODE_CAPABILITY), origin = "https://evil.example"),
            mgInputs(setOf(WalletCredentialGate.PASSCODE_CAPABILITY), mainFrame = false),
        )
        for (f in forms) for (i in bad) {
            val (answer, fwd) = mgAnswer(JSONObject(f.toString()), i)
            assertEquals("untrusted_source", answer?.optString("error"))
            assertNull(fwd)
        }
    }

    @Test
    fun mg10OtherPasscodeCommandsStillNeedWalletPasscode() {
        val cmds = mapOf(
            "passcodeProvision" to JSONObject().put("eoa", eoa).put("phrase", "w w").put("passcode", synthPasscode),
            "passcodeUnlock" to JSONObject().put("eoa", eoa).put("passcode", synthPasscode),
            "passcodeChange" to JSONObject().put("eoa", eoa).put("oldPasscode", synthPasscode).put("newPasscode", "135792"),
            "passcodeDisable" to JSONObject().put("eoa", eoa).put("passcode", synthPasscode),
        )
        for ((type, fields) in cmds) {
            val body = JSONObject(fields.toString()).put("type", type).put("reqId", 11)
            val (refused, notFwd) = mgAnswer(JSONObject(body.toString()), mgInputs(setOf("identity.native-keys.v1")))
            assertEquals(type, "untrusted_source", refused?.optString("error"))
            assertNull(type, notFwd)
            val (_, fwd) = mgAnswer(JSONObject(body.toString()), mgInputs(setOf(WalletCredentialGate.PASSCODE_CAPABILITY)))
            assertTrue(type, fwd != null)
        }
    }

    /**
     * SC-04 (M6 v2, passcode-unlock-sync-vectors.v2 securityCases): the shell validates the passcode's shape and passes the
     * object on in memory only. Every shell log line built for these requests (PageSyncRoute.logLine and the ReqCorrelation
     * lines ShellRecordChannel writes), every refusal envelope and every refused answer carry neither the passcode nor the
     * phrase nor the envelope's ciphertext. Log-scan patterns: the synthetic passcode, the phrase and the ct value.
     */
    @Test
    fun sc04ShellLogLinesAndRefusalsNeverCarryThePasscodeOrPhrase() {
        val secrets = listOf(synthPasscode, "w w", "Y3Q")
        val forms = listOf(
            mgSync("eoa" to eoa, "cipher" to v3Envelope(), "passcode" to synthPasscode, "seq" to 4),
            mgSync("eoa" to eoa, "passcode" to synthPasscode, "seq" to 4),
            mgSync("eoa" to eoa, "phrase" to "w w", "passcode" to synthPasscode, "seq" to 4),
            mgSync("eoa" to eoa, "cipher" to v3Envelope(), "phrase" to "w w", "seq" to 4),
            mgSync("eoa" to eoa, "cipher" to v3Envelope().put("v", 2), "passcode" to synthPasscode, "seq" to 4),
            mgSync("eoa" to eoa, "cipher" to v3Envelope(), "passcode" to "24681", "seq" to 4),
        )
        val sdkWithoutSecrets = JSONObject().put("type", "ack").put("reqId", 11).put("ok", true)
            .put("result", JSONObject().put("code", "ok").put("decrypted", true).put("stored", true).put("readback", "match"))
        for (trusted in listOf(true, false)) for (f in forms) {
            val body = JSONObject(f.toString())
            val answer = PageSyncRoute.channelAnswer(body, trusted) { sdkWithoutSecrets }
            val lines = mutableListOf(
                PageSyncRoute.logLine(body.optString("type"), trusted, com.beamio.app.BridgeReqId.valid(body.opt("reqId")),
                    answer?.optString("error")?.takeIf { it.isNotEmpty() }),
            )
            com.beamio.app.ReqCorrelation.head(f.toString())?.let { (t, r) ->
                lines += com.beamio.app.ReqCorrelation.enqueued("bridge", t, r)
                lines += com.beamio.app.ReqCorrelation.started("bridge", t, r, 1)
                com.beamio.app.ReqCorrelation.replyText("bridge", t, r, 5, answer?.toString())?.let { lines += it }
            }
            val refusal = PageSyncRoute.refusalBeforeSdk(JSONObject(f.toString()), trusted)?.toString().orEmpty()
            for (s in secrets) {
                lines.forEach { assertFalse("trusted=$trusted log line carries a secret", it.contains(s)) }
                assertFalse("trusted=$trusted refusal carries a secret", refusal.contains(s))
                if (answer?.optBoolean("ok", true) == false) assertFalse("trusted=$trusted answer carries a secret", answer.toString().contains(s))
            }
        }
    }
}
