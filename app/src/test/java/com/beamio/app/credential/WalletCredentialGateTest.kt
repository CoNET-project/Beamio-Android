package com.beamio.app.credential

import com.beamio.app.BuildConfig
import com.beamio.app.ChatOriginGate
import com.beamio.app.credential.WalletCredentialGate.Channel
import com.beamio.app.credential.WalletCredentialGate.RequestCheck
import com.beamio.app.credential.WalletCredentialGate.TrustInputs
import com.beamio.app.credential.WalletCredentialGate.Verdict
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.SecureRandom

/**
 * Spec r3np §25.52Y.38 (items 2, 3, 11, 14: W-N1 to W-N4) and r3nq §25.52Y.41 (item 9 (a)-(f)), shell side.
 * Test values only: a random 32-byte key and words generated in memory per run; nothing on chain, nothing on disk.
 */
class WalletCredentialGateTest {
    private val rnd = SecureRandom()
    private val sha = hex(32)
    private val testKey = "0x" + hex(32)
    private val testEoa = "0x" + hex(20)
    private val words = (1..12).joinToString(" ") { w -> (1..5).map { ('a' + rnd.nextInt(26)) }.joinToString("") + ('a' + w % 26) }

    private fun hex(n: Int) = ByteArray(n).also { rnd.nextBytes(it) }.joinToString("") { "%02x".format(it) }

    private fun trusted(
        channel: Channel = Channel.WEB_MESSAGE,
        isMainFrame: Boolean = true,
        origin: String? = ChatOriginGate.TRUSTED,
        caps: Set<String> = setOf(WalletCredentialGate.CAPABILITY),
        sdk: Set<String> = setOf(WalletCredentialGate.CAPABILITY),
        manifestSha: String = sha,
        active: String? = sha,
    ) = TrustInputs(caps, manifestSha, sha, sdk, active, channel, isMainFrame, origin)

    private fun req(vararg kv: Pair<String, Any>) = JSONObject().put("type", "walletCredential").put("reqId", 7).apply { kv.forEach { put(it.first, it.second) } }

    // ---- trust (item 2) ----

    @Test
    fun trustedOnlyWhenEveryConditionHolds() {
        assertEquals(Verdict.TRUSTED, WalletCredentialGate.evaluate(trusted()))
        assertEquals(Verdict.TRUSTED, WalletCredentialGate.evaluate(trusted(origin = ChatOriginGate.TRUSTED + "/")))
        assertEquals(Verdict.CHANNEL_REFUSED, WalletCredentialGate.evaluate(trusted(channel = Channel.JS_INTERFACE)))
        assertEquals(Verdict.FRAME_REFUSED, WalletCredentialGate.evaluate(trusted(isMainFrame = false)))
        for (o in listOf("https://beamio.ca", "http://appassets.androidplatform.net", "https://appassets.androidplatform.net.evil.test", "file://", null)) {
            assertEquals("origin $o", Verdict.ORIGIN_REFUSED, WalletCredentialGate.evaluate(trusted(origin = o)))
        }
        // (a) bits from the manifest only; the page's hello is not an input at all.
        assertEquals(Verdict.NO_MANIFEST_CAPABILITY, WalletCredentialGate.evaluate(trusted(caps = emptySet())))
        assertEquals(Verdict.NO_MANIFEST_CAPABILITY, WalletCredentialGate.evaluate(trusted(caps = setOf("identity.native-keys.v1"))))
        // (g) bits of another package (manifest zip_sha256 differs from the lock) do not count.
        assertEquals(Verdict.MANIFEST_NOT_BOUND, WalletCredentialGate.evaluate(trusted(manifestSha = hex(32))))
        assertEquals(Verdict.MANIFEST_NOT_BOUND, WalletCredentialGate.evaluate(trusted(manifestSha = "")))
        // (e) the native SDK build must declare it too.
        assertEquals(Verdict.SDK_NOT_DECLARED, WalletCredentialGate.evaluate(trusted(sdk = emptySet())))
        // (b)(c)(g) active/ must hold the verified bundled bytes (old bundle, OTA bundle, changed file: null or another hash).
        assertEquals(Verdict.BUNDLE_NOT_VERIFIED, WalletCredentialGate.evaluate(trusted(active = null)))
        assertEquals(Verdict.BUNDLE_NOT_VERIFIED, WalletCredentialGate.evaluate(trusted(active = hex(32))))
    }

    @Test
    fun capabilityListParsing() {
        assertEquals(emptySet<String>(), WalletCredentialGate.parseCapabilities(""))
        assertEquals(setOf("a.v1", "wallet.credential.v1"), WalletCredentialGate.parseCapabilities("a.v1, wallet.credential.v1,"))
    }

    /**
     * The capability bits come only from the lock-bound manifest of this build (0.53.1 QA manifest: wallet.credential.v1),
     * bound to the embedded zip; the store build type never gets QA-manifest bits (PM R2042).
     */
    @Test
    fun buildCapabilitiesAreBoundToTheEmbeddedZipAndNeverInStore() {
        if (BuildConfig.PWA_CAPABILITIES.isEmpty()) {
            assertEquals("", BuildConfig.PWA_CAPABILITIES_ZIP_SHA256)
        } else {
            assertEquals(setOf(WalletCredentialGate.CAPABILITY), WalletCredentialGate.parseCapabilities(BuildConfig.PWA_CAPABILITIES))
            assertEquals(BuildConfig.PWA_ZIP_SHA256, BuildConfig.PWA_CAPABILITIES_ZIP_SHA256)
        }
        if (BuildConfig.BUILD_TYPE == "store") assertEquals("", BuildConfig.PWA_CAPABILITIES)
        val gradle = File("build.gradle.kts").readText()
        assertTrue(gradle.contains("if (!pwaCapabilitiesFromFreeze) {"))
    }

    // ---- request (item 3 (c)); W-N4 ----

    @Test
    fun wN4_keyFieldInWalletCredentialRequestIsKeyOverBridgeRefused() {
        for (k in listOf("mnemonic", "eoaPrivateKey", "privateKeyHex", "privateKey", "walletPrivateKey", "MNEMONIC", "seed")) {
            val c = WalletCredentialGate.checkRequest(req(k to testKey), Verdict.TRUSTED) as RequestCheck.Refuse
            assertEquals(WalletCredentialGate.KEY_OVER_BRIDGE_REFUSED, c.error)
            assertEquals(7, c.reqId)
            assertEquals(listOf(k.lowercase()), c.fieldNames)
            val answer = WalletCredentialGate.refusal(c.reqId, c.error).toString() + WalletCredentialGate.replyLine("walletCredential", WalletCredentialGate.refusal(c.reqId, c.error), 3, c.fieldNames)
            assertFalse("value never echoed", answer.contains(testKey))
        }
        // nested too
        val nested = WalletCredentialGate.checkRequest(req("x" to JSONObject().put("mnemonic", words)), Verdict.TRUSTED) as RequestCheck.Refuse
        assertEquals(WalletCredentialGate.KEY_OVER_BRIDGE_REFUSED, nested.error)
    }

    @Test
    fun requestShape() {
        assertTrue(WalletCredentialGate.checkRequest(req(), Verdict.TRUSTED) is RequestCheck.Pass)
        assertTrue(WalletCredentialGate.checkRequest(req("mode" to "unseal", "blob" to "b64"), Verdict.TRUSTED) is RequestCheck.Pass)
        for (bad in listOf(req("extra" to 1), req("mode" to "unseal"), req("mode" to "other", "blob" to "x"), req("blob" to "x"), req("mode" to "unseal", "blob" to ""))) {
            assertEquals(bad.toString(), WalletCredentialGate.BAD_REQUEST, (WalletCredentialGate.checkRequest(bad, Verdict.TRUSTED) as RequestCheck.Refuse).error)
        }
        val noReqId = WalletCredentialGate.checkRequest(JSONObject().put("type", "walletCredential").put("reqId", -1), Verdict.TRUSTED) as RequestCheck.Refuse
        assertEquals(WalletCredentialGate.BAD_REQUEST, noReqId.error); assertNull(noReqId.reqId)
    }

    /** r3os: source/frame mismatch (incl. the JS-interface path) -> origin_refused first; bundle/capability -> not_trusted. */
    @Test
    fun untrustedIsRefusedBeforeAnyOtherCheck() {
        for (v in Verdict.values().filter { it != Verdict.TRUSTED }) {
            val expected = if (v in WalletCredentialGate.SOURCE_REFUSALS) "origin_refused" else WalletCredentialGate.NOT_TRUSTED
            for (r in listOf(req(), req("mnemonic" to words), req("extra" to 1))) {
                assertEquals("$v $r", expected, (WalletCredentialGate.checkRequest(r, v) as RequestCheck.Refuse).error)
            }
        }
        val badId = WalletCredentialGate.checkRequest(JSONObject().put("type", "walletCredential").put("reqId", -1), Verdict.FRAME_REFUSED) as RequestCheck.Refuse
        assertEquals("origin_refused", badId.error); assertNull(badId.reqId)
        assertEquals(setOf(Verdict.CHANNEL_REFUSED, Verdict.FRAME_REFUSED, Verdict.ORIGIN_REFUSED), WalletCredentialGate.SOURCE_REFUSALS)
    }

    // ---- reply (item 3 (e), item 12 (c)); W-N3 ----

    private fun ack(result: JSONObject?) = JSONObject().put("type", "ack").put("reqId", 7).put("ok", result != null).apply { if (result != null) put("result", result) else put("error", "unavailable") }

    @Test
    fun replyWithExactlyOneCredentialPasses() {
        assertTrue(WalletCredentialGate.responseAllowed(ack(JSONObject().put("eoa", testEoa).put("credentialKind", "mnemonic").put("mnemonic", words))))
        assertTrue(WalletCredentialGate.responseAllowed(ack(JSONObject().put("eoa", testEoa).put("credentialKind", "mnemonic").put("mnemonic", words).put("blob", "c2VhbGVk"))))
        assertTrue(WalletCredentialGate.responseAllowed(ack(null)))
        // 930988d does not know the command yet: unknown_command passes as a plain failure.
        assertTrue(WalletCredentialGate.responseAllowed(JSONObject().put("type", "ack").put("reqId", 7).put("ok", false).put("error", "unknown_command")))
    }

    @Test
    fun wN3_replyWithBothMnemonicAndKeyIsRefused() {
        val both = ack(JSONObject().put("eoa", testEoa).put("credentialKind", "mnemonic").put("mnemonic", words).put("eoaPrivateKey", testKey))
        assertFalse(WalletCredentialGate.responseAllowed(both))
        val f = SdkPayloadFilter { 10L }
        f.expectCredentialReply(7)
        val r = f.filter(SdkPayloadFilter.event(both))
        assertTrue(r.credentialReply)
        val out = r.payload.toString()
        // W-N3: refused as key_over_bridge_refused (§25.52Y.38 item 3 (c)), distinct from W-L5's unavailable; same as iOS
        assertEquals(WalletCredentialGate.KEY_OVER_BRIDGE_REFUSED, r.payload!!.getJSONObject("event").getString("error"))
        for (secret in listOf(words, testKey, testEoa, "mnemonic", "eoaPrivateKey", "result")) assertFalse(secret, out.contains(secret))
        // both credentials without the key field name being eoaPrivateKey is still caught by the shape rule
        assertFalse(WalletCredentialGate.responseAllowed(ack(JSONObject().put("eoa", testEoa).put("credentialKind", "mnemonic").put("mnemonic", words).put("privateKeyHex", testKey))))
        assertFalse(r.logLine!!.contains(words) || r.logLine!!.contains(testKey))
    }

    /** W-L5 shell side (PM R1904; r3oh §25.52Y.38 item 8 (8e)): eoa_key or eoaPrivateKey -> unavailable, nothing else. */
    @Test
    fun wL5_eoaKeyReplyBecomesUnavailable() {
        val cases = listOf(
            ack(JSONObject().put("eoa", testEoa).put("credentialKind", "eoa_key").put("eoaPrivateKey", testKey)),
            ack(JSONObject().put("eoa", testEoa).put("credentialKind", "eoa_key")),
            ack(JSONObject().put("eoa", testEoa).put("eoaPrivateKey", testKey)), // key without a kind
            JSONObject().put("type", "ack").put("reqId", 7).put("ok", false).put("error", "x").put("eoaPrivateKey", testKey),
        )
        for (c in cases) {
            val f = SdkPayloadFilter { 0L }
            f.expectCredentialReply(7)
            val r = f.filter(SdkPayloadFilter.event(c))
            val ev = r.payload!!.getJSONObject("event")
            assertEquals(c.toString(), "unavailable", ev.getString("error")); assertEquals(false, ev.getBoolean("ok"))
            assertEquals(setOf("type", "reqId", "ok", "error"), ev.keys().asSequence().toSet())
            for (secret in listOf(testKey, words, "eoaPrivateKey", "mnemonic")) assertFalse(secret, r.payload.toString().contains(secret) || r.logLine!!.contains(secret))
        }
        // positive: a mnemonic reply still passes unchanged; walletEoaAddress is not affected by this rule
        val f = SdkPayloadFilter { 0L }
        f.expectCredentialReply(7)
        val good = SdkPayloadFilter.event(ack(JSONObject().put("eoa", testEoa).put("credentialKind", "mnemonic").put("mnemonic", words)))
        assertTrue(f.filter(good).payload === good)
        f.expectCredentialReply(7, WalletCredentialGate.ADDRESS_COMMAND)
        val addr = SdkPayloadFilter.event(ack(JSONObject().put("eoa", testEoa)))
        assertTrue(f.filter(addr).payload === addr)
    }

    @Test
    fun malformedRepliesAreRefused() {
        val cases = listOf(
            JSONObject().put("eoa", testEoa).put("credentialKind", "eoa_key").put("mnemonic", words), // kind/field mismatch
            JSONObject().put("eoa", testEoa.uppercase().replace("0X", "0x")).put("credentialKind", "mnemonic").put("mnemonic", words),
            JSONObject().put("eoa", testEoa).put("credentialKind", "mnemonic").put("mnemonic", words.uppercase()),
            JSONObject().put("eoa", testEoa).put("credentialKind", "mnemonic").put("mnemonic", words).put("pgpPrivateKeyArmored", "x"),
            JSONObject().put("eoa", testEoa).put("credentialKind", "eoa_key").put("eoaPrivateKey", testKey.drop(2)),
            // PM R1884 / §25.52Y.42 item 5 (b): an eoa_key account answers unavailable; a key reply never passes
            JSONObject().put("eoa", testEoa).put("credentialKind", "eoa_key").put("eoaPrivateKey", testKey),
            JSONObject().put("credentialKind", "mnemonic").put("mnemonic", words),
        )
        for (c in cases) assertFalse(c.toString(), WalletCredentialGate.responseAllowed(ack(c)))
        // a failure carrying a key field anywhere
        assertFalse(WalletCredentialGate.responseAllowed(JSONObject().put("type", "ack").put("reqId", 7).put("ok", false).put("error", "x").put("mnemonic", words)))
    }

    // ---- walletEoaAddress (§25.52Y.42 item 5 (c)(d); PM R1896 (3)) ----

    private fun addrReq(vararg kv: Pair<String, Any>) = JSONObject().put("type", "walletEoaAddress").put("reqId", 8).apply { kv.forEach { put(it.first, it.second) } }

    @Test
    fun eoaAddressRequestTakesTheSameGateAndOnlyTypeAndReqId() {
        assertTrue(WalletCredentialGate.ADDRESS_COMMAND in WalletCredentialGate.GATED_COMMANDS)
        assertTrue(WalletCredentialGate.checkRequest(addrReq(), Verdict.TRUSTED) is RequestCheck.Pass)
        for (v in Verdict.values().filter { it != Verdict.TRUSTED }) {
            val expected = if (v in WalletCredentialGate.SOURCE_REFUSALS) "origin_refused" else WalletCredentialGate.NOT_TRUSTED
            assertEquals(expected, (WalletCredentialGate.checkRequest(addrReq(), v) as RequestCheck.Refuse).error)
        }
        assertEquals(WalletCredentialGate.KEY_OVER_BRIDGE_REFUSED, (WalletCredentialGate.checkRequest(addrReq("eoaPrivateKey" to testKey), Verdict.TRUSTED) as RequestCheck.Refuse).error)
        for (bad in listOf(addrReq("mode" to "unseal", "blob" to "x"), addrReq("extra" to 1))) {
            assertEquals(WalletCredentialGate.BAD_REQUEST, (WalletCredentialGate.checkRequest(bad, Verdict.TRUSTED) as RequestCheck.Refuse).error)
        }
    }

    @Test
    fun eoaAddressReplyCarriesOnlyEoa() {
        val a = WalletCredentialGate.ADDRESS_COMMAND
        assertTrue(WalletCredentialGate.responseAllowed(ack(JSONObject().put("eoa", testEoa)), a))
        assertTrue(WalletCredentialGate.responseAllowed(ack(null), a)) // unavailable / no_key / locked
        for (bad in listOf(
            JSONObject().put("eoa", testEoa).put("eoaPrivateKey", testKey),
            JSONObject().put("eoa", testEoa).put("mnemonic", words),
            JSONObject().put("eoa", testEoa).put("credentialKind", "eoa_key"),
            JSONObject().put("eoa", "0x1234"),
            JSONObject(),
        )) assertFalse(bad.toString(), WalletCredentialGate.responseAllowed(ack(bad), a))
        // the filter applies the address rule to an address reqId, and logs the address command name
        val f = SdkPayloadFilter { 0L }
        f.expectCredentialReply(7, a)
        val r = f.filter(SdkPayloadFilter.event(ack(JSONObject().put("eoa", testEoa).put("mnemonic", words))))
        assertEquals(WalletCredentialGate.KEY_OVER_BRIDGE_REFUSED, r.payload!!.getJSONObject("event").getString("error"))
        assertTrue(r.logLine!!.startsWith("reply cmd=walletEoaAddress")); assertFalse(r.payload.toString().contains(words))
        f.expectCredentialReply(7, a)
        val ok = f.filter(SdkPayloadFilter.event(ack(JSONObject().put("eoa", testEoa))))
        assertTrue(ok.credentialReply); assertEquals(testEoa, ok.payload!!.getJSONObject("event").getJSONObject("result").getString("eoa"))
        assertFalse("address not logged", ok.logLine!!.contains(testEoa))
    }

    // ---- window channel (PM R1911; SDK answers walletEoaAddress on BeamioShellRecord) ----

    @Test
    fun windowChannelGatesWalletEoaAddressBeforeAndAfterTheSdk() {
        var calls = 0
        fun run(body: JSONObject, v: Verdict, reply: String): JSONObject {
            val r = WalletCredentialGate.windowCredential(body, { v }, { calls++; reply }, { 0L })
            for (l in r.logs) for (secret in listOf(testEoa, testKey, words)) assertFalse("$l has $secret", l.contains(secret))
            return JSONObject(r.reply)
        }
        val okReply = ack(JSONObject().put("eoa", testEoa)).put("reqId", 8).toString()
        // r3or §25.52Y.44 item 4: frame or origin mismatch -> origin_refused (even with a bad reqId, then reqId null);
        // other untrusted verdicts -> not_trusted; the SDK is not called
        for (v in WalletCredentialGate.SOURCE_REFUSALS) {
            val o = run(addrReq(), v, okReply)
            assertEquals("origin_refused", o.getString("error")); assertEquals(false, o.getBoolean("ok")); assertEquals(8, o.getInt("reqId"))
            assertEquals(setOf("type", "reqId", "ok", "error"), o.keys().asSequence().toSet())
            val bad = run(JSONObject().put("type", "walletEoaAddress").put("reqId", -1), v, okReply)
            assertEquals("origin_refused", bad.getString("error")); assertTrue(bad.isNull("reqId"))
        }
        for (v in Verdict.values().filter { it != Verdict.TRUSTED && it !in WalletCredentialGate.SOURCE_REFUSALS }) {
            assertEquals("not_trusted", run(addrReq(), v, okReply).getString("error"))
        }
        assertEquals(0, calls)
        // malformed: refused before the SDK
        assertEquals("bad_request", run(addrReq("extra" to 1), Verdict.TRUSTED, okReply).getString("error"))
        assertEquals("key_over_bridge_refused", run(addrReq("eoaPrivateKey" to testKey), Verdict.TRUSTED, okReply).getString("error"))
        assertEquals("bad_request", run(JSONObject().put("type", "walletEoaAddress").put("reqId", -1), Verdict.TRUSTED, okReply).getString("error"))
        assertEquals(0, calls)
        // trusted: the SDK's {eoa} passes unchanged
        val ok = run(addrReq(), Verdict.TRUSTED, okReply)
        assertEquals(testEoa, ok.getJSONObject("result").getString("eoa")); assertEquals(1, calls)
        // SDK failures pass as failures (1b33f00 today answers unknown_command on this channel)
        assertEquals("unknown_command", run(addrReq(), Verdict.TRUSTED, JSONObject().put("reqId", 8).put("ok", false).put("error", "unknown_command").toString()).getString("error"))
        assertEquals("no_key", run(addrReq(), Verdict.TRUSTED, JSONObject().put("type", "ack").put("reqId", 8).put("ok", false).put("error", "no_key").toString()).getString("error"))
        // a reply with more than the address, another reqId, or not JSON never reaches the page
        assertEquals("key_over_bridge_refused", run(addrReq(), Verdict.TRUSTED, ack(JSONObject().put("eoa", testEoa).put("eoaPrivateKey", testKey)).put("reqId", 8).toString()).getString("error"))
        assertEquals("unavailable", run(addrReq(), Verdict.TRUSTED, ack(JSONObject().put("eoa", testEoa)).put("reqId", 9).toString()).getString("error"))
        assertEquals("unavailable", run(addrReq(), Verdict.TRUSTED, "not json").getString("error"))
        // walletCredential on this channel: eoa_key -> unavailable (W-L5)
        assertEquals("unavailable", run(req(), Verdict.TRUSTED, ack(JSONObject().put("eoa", testEoa).put("credentialKind", "eoa_key").put("eoaPrivateKey", testKey)).toString()).getString("error"))
        // an exception in the SDK call: unavailable, error line with the class name only
        val r = WalletCredentialGate.windowCredential(addrReq(), { Verdict.TRUSTED }, { throw IllegalStateException("x $testEoa") }, { 0L })
        assertEquals("unavailable", JSONObject(r.reply).getString("error"))
        assertTrue(r.logs.any { it.startsWith("error cmd=walletEoaAddress") }); assertFalse(r.logs.any { it.contains(testEoa) })
    }

    /** r3ok / PM R1912: walletEoaAddress needs no capability bit (origin, frame, bundle); walletCredential does. */
    @Test
    fun capabilityRequirementPerCommand() {
        assertFalse(WalletCredentialGate.requiresCapability("walletEoaAddress"))
        assertTrue(WalletCredentialGate.requiresCapability("walletCredential"))
        val noBits = trusted(caps = emptySet(), sdk = emptySet(), manifestSha = "")
        assertEquals(Verdict.TRUSTED, WalletCredentialGate.evaluate(noBits, WalletCredentialGate.requiresCapability("walletEoaAddress")))
        assertEquals(Verdict.NO_MANIFEST_CAPABILITY, WalletCredentialGate.evaluate(noBits, WalletCredentialGate.requiresCapability("walletCredential")))
        assertEquals(Verdict.BUNDLE_NOT_VERIFIED, WalletCredentialGate.evaluate(noBits.copy(verifiedActiveZipSha256 = null), false))
        assertEquals(Verdict.BUNDLE_NOT_VERIFIED, WalletCredentialGate.evaluate(noBits.copy(verifiedActiveZipSha256 = "x"), false))
        val main = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        assertTrue(main.contains("requireCapability = WalletCredentialGate.requiresCapability(command)"))
    }

    @Test
    fun windowChannelWiring() {
        val src = File("src/main/java/com/beamio/app/legacy/ShellRecordChannel.kt").readText()
        val route = src.indexOf("body!!.optString(\"type\") in WalletCredentialGate.GATED_COMMANDS")
        assertTrue(route > 0)
        // full trust (capability required: default) and the SDK call only inside the gate
        assertTrue(src.contains("requireCapability = WalletCredentialGate.requiresCapability(body.optString(\"type\"))"))
        assertTrue(src.contains("sdk = { handler.handle(embedded, data, size) }"))
        // the PGP exit assertion still runs on whatever the path produced
        assertTrue(src.indexOf("LegacyRecord.pgpPrivateHits(out.toCharArray())") > route)
    }

    // ---- other commands (item 14); W-N1, W-N2 ----

    @Test
    fun wN1_otherCommandRequestWithMnemonicIsRefused() {
        for (t in listOf("init", "send", "walletStatus", "shellRecordWrite")) {
            val body = JSONObject().put("type", t).put("reqId", 1).put("mnemonic", words)
            assertEquals(listOf("mnemonic"), WalletCredentialGate.otherCommandRequestKeyFields(body))
            assertEquals(listOf("eoaprivatekey"), WalletCredentialGate.otherCommandRequestKeyFields(JSONObject().put("type", t).put("a", JSONArray().put(JSONObject().put("eoaPrivateKey", testKey)))))
        }
        // existing, separately ruled names are not newly refused here (the SDK's own list stays as is)
        assertEquals(emptyList<String>(), WalletCredentialGate.otherCommandRequestKeyFields(JSONObject().put("type", "x").put("mnemonicPhrase", "y").put("recoveryWords", "z")))
        // the activity refuses before the QA guard and the SDK, and never hands walletCredential's exception to others
        val main = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        val h = main.substringAfter("private fun handleChatCommand(json: String, channel: WalletCredentialGate.Channel").substringBefore("\n    private var qaEvalReceiver")
        assertTrue(h.indexOf("otherCommandRequestKeyFields(body)") in 1 until h.indexOf("QaWriteGuard.sdkCommandAllowed(body.optString(\"type\"))"))
        assertTrue(h.indexOf("otherCommandRequestKeyFields(body)") < h.indexOf("BeamioConetChatModule.handleCommand(applicationContext, body, sdkDeliver(deliver))"))
    }

    @Test
    fun wN2_otherCommandReplyWithMnemonicIsRefused() {
        val f = SdkPayloadFilter { 0L }
        val withId = SdkPayloadFilter.event(JSONObject().put("type", "ack").put("reqId", 9).put("ok", true).put("result", JSONObject().put("mnemonic", words)))
        val r = f.filter(withId)
        assertFalse(r.credentialReply)
        assertEquals(WalletCredentialGate.KEY_OVER_BRIDGE_REFUSED, r.payload!!.getJSONObject("event").getString("error"))
        assertFalse(r.payload.toString().contains(words))
        // an async event without reqId is dropped
        assertNull(f.filter(SdkPayloadFilter.event(JSONObject().put("type", "ready").put("eoaPrivateKey", testKey))).payload)
        // a pending walletCredential reqId does not cover another reqId
        f.expectCredentialReply(1)
        assertFalse(f.filter(withId).credentialReply)
        // r3ji: nativeAccountCreateResult may carry mnemonicPhrase; unchanged
        val create = SdkPayloadFilter.event(JSONObject().put("type", "nativeAccountCreateResult").put("reqId", 4).put("code", "ok").put("mnemonicPhrase", words))
        assertTrue(f.filter(create).payload === create)
    }

    // ---- §25.52Y.41 shellRecordRead ----

    private val readReq = JSONObject().put("type", "shellRecordRead").put("reqId", 11).toString()
    private fun readReply(record: JSONObject) = JSONObject().put("type", "ack").put("reqId", 11).put("ok", true).put("result", JSONObject().put("code", "ok").put("rev", 3).put("record", record)).toString()
    private val wRecord = JSONObject().put("mnemonicPhrase", words).put("recoveryWords", "w1 w2").put("profiles", JSONArray().put(JSONObject().put("keyID", testEoa).put("privateKeyArmor", "armor")))

    /**
     * (a) as ruled for this round (r3nt §25.52Y.43 item 6 (i), PM R1863): read-back checks no capability bit, but an old or
     * unverified package (bundle not the verified bytes of the hash this APK loads) is not_trusted, with no partial fields.
     */
    @Test
    fun y41a_unverifiedPackageIsNotTrustedWithNoPartialFields() {
        assertEquals(Verdict.TRUSTED, WalletCredentialGate.evaluate(trusted(caps = emptySet(), sdk = emptySet(), manifestSha = ""), requireCapability = false))
        assertEquals(Verdict.BUNDLE_NOT_VERIFIED, WalletCredentialGate.evaluate(trusted(caps = emptySet(), active = null), requireCapability = false))
        // r3oj (h): a verified download (its own published hash) is trusted for the no-capability path, never for walletCredential
        val otaSha = hex(32)
        assertEquals(Verdict.TRUSTED, WalletCredentialGate.evaluate(trusted(caps = emptySet(), active = otaSha), requireCapability = false))
        assertEquals(Verdict.BUNDLE_NOT_VERIFIED, WalletCredentialGate.evaluate(trusted(active = otaSha)))
        val v = WalletCredentialGate.evaluate(trusted(active = null), requireCapability = false)
        val out = WalletCredentialGate.gateShellRecordRead(readReq, readReply(wRecord.put("nickname", "n"))) { v }
        assertEquals(Verdict.BUNDLE_NOT_VERIFIED, out.verdict)
        val o = JSONObject(out.reply)
        // r3ow (PM R1970/R1974): for shellRecordRead a bundle failure also answers origin_refused, envelope-level; no record
        assertEquals("origin_refused", o.getString("error")); assertEquals(false, o.getBoolean("ok")); assertEquals(11, o.getInt("reqId"))
        assertEquals(setOf("type", "reqId", "ok", "error"), o.keys().asSequence().toSet())
        assertEquals(listOf("mnemonicPhrase", "privateKeyArmor", "recoveryWords"), out.wFields)
    }

    /**
     * r3ow §25.52Y.41 item 6 (PM R1974): shellRecordRead answers origin_refused for a bundle failure as well as for a source
     * mismatch (the PWA does not handle not_trusted yet); not_trusted stays for the two new commands only.
     */
    @Test
    fun y41_readBackRefusalIsOriginRefusedForBundleAndSource() {
        val v = WalletCredentialGate.evaluate(trusted(active = null), requireCapability = false)
        assertEquals(Verdict.BUNDLE_NOT_VERIFIED, v)
        val o = JSONObject(WalletCredentialGate.gateShellRecordRead(readReq, readReply(wRecord)) { v }.reply)
        assertEquals("origin_refused", o.getString("error")); assertEquals(false, o.getBoolean("ok"))
        // the new commands still answer not_trusted for a bundle failure
        assertEquals("not_trusted", JSONObject(WalletCredentialGate.windowCredential(addrReq(), { v }, { "" }, { 0L }).reply).getString("error"))
        assertEquals(setOf("type", "reqId", "ok", "error"), o.keys().asSequence().toSet())
        for (sv in WalletCredentialGate.SOURCE_REFUSALS) {
            assertEquals("origin_refused", JSONObject(WalletCredentialGate.gateShellRecordRead(readReq, readReply(wRecord)) { sv }.reply).getString("error"))
        }
    }

    /** Reviewer (R1969): an exception in the read-back gate answers the r3oo storage-error shape, not origin_refused. */
    @Test
    fun y41_gateExceptionAnswersRecordUnreadable() {
        val o = JSONObject(WalletCredentialGate.shellRecordUnreadable(11))
        assertEquals(true, o.getBoolean("ok")); assertEquals(11, o.getInt("reqId"))
        assertEquals("error", o.getJSONObject("result").getString("code")); assertEquals("record_unreadable", o.getJSONObject("result").getString("sub"))
        assertFalse(o.getJSONObject("result").has("record"))
        val src = File("src/main/java/com/beamio/app/legacy/ShellRecordChannel.kt").readText()
        val catchBlock = src.substringAfter("} catch (e: Exception) {\n                    log(WalletCredentialGate.errorLine(WalletCredentialGate.SHELL_RECORD_READ").substringBefore("}")
        assertTrue(catchBlock.contains("shellRecordUnreadable(")); assertFalse(catchBlock.contains("shellRecordRefusal("))
    }

    /** Reviewer (R1969) on 039e736c: source/frame is checked before parsing; an iframe's unparsable text is origin_refused. */
    @Test
    fun windowSourceCheckRunsBeforeParsing() {
        for ((data, frame, origin) in listOf(
            Triple("not json", false, ChatOriginGate.TRUSTED),
            Triple(null, false, ChatOriginGate.TRUSTED),
            Triple("{\"type\":\"walletEoaAddress\",\"reqId\":\"r9\"}", false, ChatOriginGate.TRUSTED),
            Triple("not json", true, "https://beamio.ca"),
        )) {
            val o = JSONObject(WalletCredentialGate.windowSourceRefusal(data, frame, origin)!!)
            assertEquals("origin_refused", o.getString("error")); assertEquals(false, o.getBoolean("ok"))
            if (data?.startsWith("{") == true) assertEquals("r9", o.getString("reqId")) else assertTrue(o.isNull("reqId"))
        }
        assertNull(WalletCredentialGate.windowSourceRefusal("not json", true, ChatOriginGate.TRUSTED))
        assertNull(WalletCredentialGate.windowSourceRefusal("x", true, ChatOriginGate.TRUSTED + "/"))
        val src = File("src/main/java/com/beamio/app/legacy/ShellRecordChannel.kt").readText()
        val first = src.indexOf("WalletCredentialGate.windowSourceRefusal(message.data, isMainFrame, sourceOrigin.toString())")
        assertTrue(first > 0)
        assertTrue(first < src.indexOf("val data = message.data ?: run { reply.postMessage(BAD_REQUEST)"))
        assertTrue(first < src.indexOf("var out = if (!parsed) BAD_REQUEST"))
    }

    @Test
    fun y41b_iframeAndRemoteOriginsAreNotTrusted() {
        for (i in listOf(trusted(isMainFrame = false), trusted(origin = "https://beamio.ca"), trusted(channel = Channel.JS_INTERFACE))) {
            val v = WalletCredentialGate.evaluate(i, requireCapability = false)
            assertEquals("origin_refused", JSONObject(WalletCredentialGate.gateShellRecordRead(readReq, readReply(wRecord)) { v }.reply).getString("error"))
        }
    }

    @Test
    fun y41c_trustedReadBackPassesUnchanged() {
        val reply = readReply(wRecord)
        val out = WalletCredentialGate.gateShellRecordRead(readReq, reply) { WalletCredentialGate.evaluate(trusted(caps = emptySet(), sdk = emptySet()), requireCapability = false) }
        assertEquals(reply, out.reply); assertEquals(Verdict.TRUSTED, out.verdict)
    }

    @Test
    fun y41_readBackWithoutWFieldsIsUnchangedAndCostsNoTrustCheck() {
        val reply = readReply(JSONObject().put("nickname", "n").put("mnemonicPhrase", "").put("profiles", JSONArray().put(JSONObject().put("keyID", "k"))))
        var called = false
        val out = WalletCredentialGate.gateShellRecordRead(readReq, reply) { called = true; Verdict.NO_MANIFEST_CAPABILITY }
        assertEquals(reply, out.reply); assertNull(out.verdict); assertFalse(called)
        // other request types are never touched
        val w = JSONObject().put("type", "shellRecordWrite").put("reqId", 2).toString()
        assertEquals(readReply(wRecord), WalletCredentialGate.gateShellRecordRead(w, readReply(wRecord)) { Verdict.NO_MANIFEST_CAPABILITY }.reply)
    }

    /** (d) PGP fields stay refused: the existing exit assertion runs first and its fallback carries no record. */
    @Test
    fun y41d_pgpExitAssertionRunsBeforeTheGate() {
        val src = File("src/main/java/com/beamio/app/legacy/ShellRecordChannel.kt").readText()
        val pgp = src.indexOf("LegacyRecord.pgpPrivateHits(out.toCharArray())")
        val gate = src.indexOf("WalletCredentialGate.gateShellRecordRead(data, out)")
        assertTrue(pgp in 1 until gate)
        assertTrue(src.indexOf("main.post { runCatching { reply.postMessage(out) } }") > gate)
        assertTrue(src.contains("ShellCredentialTrust.verdict(WalletCredentialGate.Channel.WEB_MESSAGE, isMainFrame, origin, requireCapability = false)"))
    }

    /** (e) other commands with W fields: W-N1 to W-N4 above. (f) logs carry names, verdicts and codes, never values. */
    @Test
    fun y41f_and_item11_logLinesCarryNoValues() {
        val lines = listOf(
            WalletCredentialGate.entryLine("walletCredential", 7, Verdict.TRUSTED),
            WalletCredentialGate.replyLine("walletCredential", ack(JSONObject().put("eoa", testEoa).put("credentialKind", "mnemonic").put("mnemonic", words).put("blob", "BLOBVALUE")), 12),
            WalletCredentialGate.replyLine("shellRecordRead", JSONObject(readReply(wRecord)), 5, listOf("mnemonicPhrase")),
            WalletCredentialGate.replyLine("walletCredential", JSONObject().put("type", "ack").put("reqId", 7).put("ok", false).put("error", words), 1),
            WalletCredentialGate.errorLine("walletCredential", 7, IllegalStateException("boom $testKey $words")),
        )
        for (l in lines) for (secret in listOf(words, testKey, testEoa, "BLOBVALUE", "armor", "w1 w2", "boom")) assertFalse("$l has $secret", l.contains(secret))
        // log-scan pattern of item 11 (a): field name + value, zero hits
        val pattern = Regex("""(eoaPrivateKey|mnemonic)["'\s]*[:=]\s*["']?(0x[0-9a-f]{64}|[a-z]+( [a-z]+){11})""")
        for (l in lines) assertFalse(l, pattern.containsMatchIn(l))
    }

    /** Item 11 (c) points 1-3 and item 2 (d): where the shell logs, and that only the WebMessage path can be trusted. */
    @Test
    fun wiringOfLogPointsAndChannels() {
        val main = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        assertTrue(main.contains("onCommand = { json, deliver -> handleChatCommand(json, WalletCredentialGate.Channel.WEB_MESSAGE, deliver) }"))
        assertTrue(main.contains("handleChatCommand(json, WalletCredentialGate.Channel.JS_INTERFACE) { payload ->"))
        assertTrue(main.contains("WalletCredentialGate.entryLine(command, rid, verdict)) // log point 1"))
        assertTrue(main.contains("if (body.optString(\"type\") in WalletCredentialGate.GATED_COMMANDS) {"))
        assertEquals(2, Regex("WalletCredentialGate.replyLine\\(command, refused").findAll(main).count() +
            Regex("r.logLine\\?.let \\{ Log.i\\(CREDENTIAL_TAG, it\\) \\} // log point 2").findAll(main).count())
        assertTrue(main.contains("WalletCredentialGate.errorLine(command, rid, e)) // log point 3"))
        // every credential-tag log line is built from names, codes, verdicts and durations only
        Regex("Log\\.[iwe]\\(CREDENTIAL_TAG, ([^\\n]*)").findAll(main).forEach { m ->
            val arg = m.groupValues[1]
            assertFalse(arg, arg.contains("toString()") || arg.contains("body)") || arg.contains("\$body") || arg.contains("optString(\"mnemonic") || arg.contains("result"))
        }
        // a walletCredential reply never reaches the debug event summary
        assertTrue(main.contains("if (!r.credentialReply) debugSdkEvent(payload)"))
        // the trust inputs: manifest bits from BuildConfig, SDK bits from the SDK, bundle from the store record
        val trust = File("src/main/java/com/beamio/app/credential/ShellCredentialTrust.kt").readText()
        for (s in listOf("BuildConfig.PWA_CAPABILITIES", "BeamioConetChatProtocol.CAPABILITIES", "EmbeddedPwaBundleStore.currentVerifiedActiveZipSha256()")) assertTrue(s, trust.contains(s))
        // no shell constant grants the bit: the name appears only as the gate's comparison constant
        val mainSrc = File("src/main/java").walkTopDown().filter { it.isFile && it.extension == "kt" }
        val holders = mainSrc.filter { it.readText().contains("\"wallet.credential.v1\"") }.map { it.name }.toList()
        assertEquals(listOf("WalletCredentialGate.kt"), holders)
        val gradle = File("build.gradle.kts").readText()
        assertFalse(gradle.contains("wallet.credential.v1"))
        assertTrue(gradle.contains("val raw = manifest[\"capabilities\"]"))
    }
}
