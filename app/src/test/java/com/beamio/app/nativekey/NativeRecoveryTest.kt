package com.beamio.app.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class NativeRecoveryTest {
    private class FakeBackend(val outcome: RecoveryOutcome, override val supported: Boolean = true) : NativeRecoveryBackend {
        var seen: String? = null
        var seenAccount: String? = null
        var seenPassword: String? = null
        override fun recover(recoveryCode: CharArray): RecoveryOutcome {
            seen = String(recoveryCode)
            return outcome
        }
        override fun recoverWithPassword(accountName: String, password: CharArray): RecoveryOutcome {
            seenAccount = accountName
            seenPassword = String(password)
            return outcome
        }
    }

    private val goodCode = "Ab3dEf6hIj9kLm2nOp5qRs"
    private val eoa = "0x" + "a".repeat(40)

    private fun open(reqId: Int = 7) = JSONObject().put("type", "nativeRecoveryOpen").put("reqId", reqId)

    @Test
    fun withoutSdkRecoveryTheOpenIsAnsweredNotSupportedAndNoPageOpens() {
        val out = mutableListOf<JSONObject>()
        var opened = false
        val handled = NativeRecoveryFlow.intercept(open(), { out += it }, { opened = true; true }, NativeRecoveryBackend.Unavailable)
        assertTrue(handled)
        assertFalse(opened)
        assertEquals(1, out.size)
        // Same envelope as SDK module events, or the page ignores it.
        assertEquals("chatModuleEvent", out[0].getString("action"))
        val a = out[0].getJSONObject("event")
        assertEquals("ack", a.getString("type"))
        assertEquals(7, a.getInt("reqId"))
        assertFalse(a.getBoolean("ok"))
        assertEquals("not_supported", a.getString("error"))
    }

    @Test
    fun withRecoveryTheOpenAcksOkAndOpensThePage() {
        val out = mutableListOf<JSONObject>()
        var opened = false
        NativeRecoveryFlow.intercept(open(9), { out += it }, { opened = true; true }, FakeBackend(RecoveryOutcome(RecoveryCode.OK, eoa)))
        assertTrue(opened)
        val e = out.single().getJSONObject("event")
        assertTrue(e.getBoolean("ok"))
        assertEquals(9, e.getInt("reqId"))
        // The ack carries no data: no result, no code, no address.
        assertFalse(e.has("result") || e.has("eoa") || e.has("code"))
    }

    @Test
    fun pageThatCannotOpenIsNotAvailable() {
        val out = mutableListOf<JSONObject>()
        NativeRecoveryFlow.intercept(open(), { out += it }, { false }, FakeBackend(RecoveryOutcome(RecoveryCode.OK, eoa)))
        assertEquals("not_available", out.single().getJSONObject("event").getString("error"))
    }

    /** nativeImportOpen (private key import) and every other command go to the SDK as before. */
    @Test
    fun otherCommandsAreNotIntercepted() {
        for (t in listOf("nativeImportOpen", "hello", "init", "send", "")) {
            var emitted = false
            val handled = NativeRecoveryFlow.intercept(JSONObject().put("type", t).put("reqId", 1), { emitted = true }, { true },
                FakeBackend(RecoveryOutcome(RecoveryCode.OK, eoa)))
            assertFalse(t, handled)
            assertFalse(t, emitted)
        }
    }

    @Test
    fun resultEventCarriesOnlyCodeAndPublicFields() {
        val ok = NativeRecoveryFlow.resultEvent(7, RecoveryOutcome(RecoveryCode.OK, eoa, cooldownSec = 30))
        assertEquals("nativeRecoveryResult", ok.getString("type"))
        assertEquals("ok", ok.getString("code"))
        assertEquals(eoa, ok.getString("eoa"))
        assertFalse(ok.has("cooldownSec"))
        assertEquals(setOf("type", "reqId", "code", "eoa"), ok.keys().asSequence().toSet())
        assertEquals(7, ok.getInt("reqId"))

        val fail = NativeRecoveryFlow.resultEvent(7, RecoveryOutcome(RecoveryCode.NOT_FOUND, eoa))
        assertFalse(fail.has("eoa"))
        val back = NativeRecoveryFlow.resultEvent(7, RecoveryOutcome(RecoveryCode.BACKOFF, cooldownSec = 60))
        assertEquals(60, back.getInt("cooldownSec"))
        val badAddr = NativeRecoveryFlow.resultEvent(7, RecoveryOutcome(RecoveryCode.OK, "not-an-address"))
        assertFalse(badAddr.has("eoa"))
    }

    @Test
    fun codesMatchThePwaList() {
        assertEquals(
            listOf("ok", "cancelled", "invalid_format", "bad_pin", "backoff", "not_found", "network_error", "already_exists",
                "record_invalid", "write_failed", "readback_failed",
                // SDK 0.2.11 adds legacy_record; the PWA list does not have it yet (the page ignores it).
                "legacy_record"),
            RecoveryCode.values().map { it.wire },
        )
    }

    @Test
    fun submitChecksShapeCallsBackendAndWipesTheCode() {
        val b = FakeBackend(RecoveryOutcome(RecoveryCode.OK, eoa))
        val arr = goodCode.toCharArray()
        val o = NativeRecoveryFlow.submit(arr, b)
        assertEquals(RecoveryCode.OK, o.code)
        assertEquals(goodCode, b.seen)
        assertTrue(arr.all { it == '\u0000' })

        val bad = "short".toCharArray()
        val b2 = FakeBackend(RecoveryOutcome(RecoveryCode.OK, eoa))
        assertEquals(RecoveryCode.INVALID_FORMAT, NativeRecoveryFlow.submit(bad, b2).code)
        assertNull(b2.seen)
        assertTrue(bad.all { it == '\u0000' })

        assertEquals(RecoveryCode.INVALID_FORMAT, NativeRecoveryFlow.submit("abc-def/ghi+jkl=mnopqr".toCharArray(), b2).code)
        assertEquals(RecoveryCode.RECORD_INVALID, NativeRecoveryFlow.submit(goodCode.toCharArray(), NativeRecoveryBackend.Unavailable).code)
    }

    @Test
    fun backendExceptionBecomesRecordInvalidAndStillWipes() {
        val boom = object : NativeRecoveryBackend {
            override val supported = true
            override fun recover(recoveryCode: CharArray): RecoveryOutcome = throw IllegalStateException("x")
        }
        val arr = goodCode.toCharArray()
        assertEquals(RecoveryCode.RECORD_INVALID, NativeRecoveryFlow.submit(arr, boom).code)
        assertTrue(arr.all { it == '\u0000' })
    }

    /**
     * The SDK (0.2.10) owns the protocol: MainActivity no longer intercepts the command; the SDK binding registers the
     * recovery page as NativeRecoveryHost.launcher (its own route, never the import route); the page is FLAG_SECURE.
     */
    @Test
    fun sdkOwnsTheProtocolAndRecoveryNeverOpensTheImportPage() {
        val main = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        assertFalse(main.contains("NativeRecoveryFlow.intercept("))
        assertTrue(main.contains("NativeRecoveryRoute.register("))
        val binding = File("src/nativekeySdk/java/com/beamio/app/nativekey/NativeKeySdkBinding.kt").readText()
        assertTrue(binding.contains("NativeRecoveryHost.launcher = { NativeRecoveryRoute.open() }"))
        // SDK 0.2.27 (spec r2.3 41(1)): the native import page is removed; no import launcher is set any more.
        assertFalse(binding.contains("NativeImportHost.launcher ="))
        assertFalse(Regex("NativeRecoveryHost\\.launcher[^\\n]*Import").containsMatchIn(binding))
        val page = File("src/main/java/com/beamio/app/nativekey/NativeRecoveryActivity.kt").readText()
        assertTrue(page.contains("FLAG_SECURE") && page.contains("configureSecureInput"))
        assertFalse(page.contains("Log."))
        assertFalse(page.contains("NativeKeyImportRoute") || page.contains("nativeImportOpen"))
    }

    @Test
    fun formatIsExactly22AlphanumericAfterTrim() {
        assertTrue(NativeRecoveryFlow.formatOk("  $goodCode ".toCharArray()))
        assertFalse(NativeRecoveryFlow.formatOk(goodCode.dropLast(1).toCharArray()))
        assertFalse(NativeRecoveryFlow.formatOk((goodCode + "x").toCharArray()))
        assertFalse(NativeRecoveryFlow.formatOk(goodCode.replaceRange(3, 4, "\u00e9").toCharArray()))
    }

    @Test
    fun wireCodesMapBack() {
        for (c in RecoveryCode.values()) assertEquals(c, RecoveryCode.fromWire(c.wire))
        assertEquals(RecoveryCode.RECORD_INVALID, RecoveryCode.fromWire("unknown"))
    }

    @Test
    fun routeDoesNotOpenWithoutAnEngine() {
        val before = NativeRecoveryBackends.current
        try {
            NativeRecoveryBackends.current = NativeRecoveryBackend.Unavailable
            var opened = false
            val o: () -> Boolean = { opened = true; true }
            NativeRecoveryRoute.register(o)
            assertFalse(NativeRecoveryRoute.open())
            assertFalse(opened)
            NativeRecoveryRoute.unregister(o)
        } finally {
            NativeRecoveryBackends.current = before
        }
    }

    /** Path B: account name passed as typed (engine trims), password wiped, empty input stops before the engine. */
    @Test
    fun pathBChecksEmptyInputCallsTheEngineAndWipesThePassword() {
        val b = FakeBackend(RecoveryOutcome(RecoveryCode.BAD_PIN))
        val pw = "Pw-Example-9".toCharArray()
        val o = NativeRecoveryFlow.submitPassword("  @Some.Tag ", pw, b)
        assertEquals(RecoveryCode.BAD_PIN, o.code)
        assertEquals("  @Some.Tag ", b.seenAccount)
        assertEquals("Pw-Example-9", b.seenPassword)
        assertTrue(pw.all { it == '\u0000' })

        val b2 = FakeBackend(RecoveryOutcome(RecoveryCode.OK, eoa))
        val pw2 = "x".toCharArray()
        assertEquals(RecoveryCode.INVALID_FORMAT, NativeRecoveryFlow.submitPassword("   ", pw2, b2).code)
        assertTrue(pw2.all { it == '\u0000' })
        assertEquals(RecoveryCode.INVALID_FORMAT, NativeRecoveryFlow.submitPassword("tag", "  ".toCharArray(), b2).code)
        assertNull(b2.seenAccount)
    }

    /**
     * Spec §25.52Y.27 (r3na): no nativeRecoveryResult without reqId. The shell's builder takes reqId as a required argument,
     * the dead result sink is gone, and no other main-source code builds the event (the SDK's emit carries reqId).
     */
    @Test
    fun noRecoveryResultWithoutReqId() {
        val e = NativeRecoveryFlow.resultEvent("w3", RecoveryOutcome(RecoveryCode.NOT_FOUND))
        assertEquals("w3", e.getString("reqId"))
        val src = java.io.File("src/main/java/com/beamio/app/nativekey/NativeRecovery.kt").readText()
        assertTrue(src.contains("fun resultEvent(reqId: Any, o: RecoveryOutcome): JSONObject"))
        assertTrue(src.contains(".put(\"type\", NativeRecoveryProtocol.RESULT_EVENT).put(\"reqId\", reqId)"))
        assertFalse("dead result sink removed", src.contains("NativeRecoveryResultSink"))
        val builders = java.io.File("src/main/java").walkTopDown().filter { it.isFile && it.extension == "kt" }
            .flatMap { f -> f.readLines().map { it.trim() }.filterNot { it.startsWith("*") || it.startsWith("//") || it.startsWith("/*") }.filter { it.contains("RESULT_EVENT") || it.contains("\"nativeRecoveryResult\"") }.map { f.name + ": " + it } }
            .filterNot { it.contains("const val RESULT_EVENT") }.toList()
        assertEquals("only the reqId-carrying builder: $builders", 1, builders.size)
        assertTrue(builders.single().contains(".put(\"reqId\", reqId)"))
    }

    @Test
    fun backoffCarriesCooldownOnly() {
        val e = NativeRecoveryFlow.resultEvent(7, RecoveryOutcome(RecoveryCode.BACKOFF, eoa, 30))
        assertEquals(30, e.getInt("cooldownSec"))
        assertFalse(e.has("eoa"))
    }
}
