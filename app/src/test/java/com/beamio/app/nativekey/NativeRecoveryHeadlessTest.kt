package com.beamio.app.nativekey

import com.beamio.app.BeamioShellChannel
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.util.concurrent.Executor

/**
 * 192 (spec r3sc R3/R4/R5, plan A / P1): the headless recovery session and the window.BeamioShell actions that feed it.
 * Synthetic values only (no account). The engine is a fake; the SDK is not called.
 */
class NativeRecoveryHeadlessTest {
    private val goodCode = "Ab3dEf6hIj9kLm2nOp5qRs"
    private val eoa = "0x" + "b".repeat(40)

    private class Engine(var outcome: RecoveryOutcome, override val supported: Boolean = true) : NativeRecoveryBackend {
        var codeCalls = 0
        var accountCalls = 0
        var cancels = 0
        var seenCode: String? = null
        var seenName: String? = null
        var seenPassword: String? = null
        var heldCode: CharArray? = null
        override fun recover(recoveryCode: CharArray): RecoveryOutcome {
            codeCalls++; seenCode = String(recoveryCode); heldCode = recoveryCode; return outcome
        }
        override fun recoverWithPassword(accountName: String, password: CharArray): RecoveryOutcome {
            accountCalls++; seenName = accountName; seenPassword = String(password); return outcome
        }
        override fun cancel() { cancels++ }
    }

    /** Holds tasks so a submission can be kept "in flight". */
    private class Held : Executor {
        val tasks = ArrayDeque<Runnable>()
        override fun execute(command: Runnable) { tasks.addLast(command) }
        fun runAll() { while (tasks.isNotEmpty()) tasks.removeFirst().run() }
    }

    private val held = Held()
    private lateinit var saved: Executor

    @Before
    fun setUp() {
        saved = NativeRecoveryHeadless.executor
        NativeRecoveryHeadless.executor = held
        NativeRecoveryHeadless.onOutcome = null
        NativeRecoveryHeadless.cancel(Engine(RecoveryOutcome(RecoveryCode.OK)))
    }

    @After
    fun tearDown() {
        NativeRecoveryHeadless.cancel(Engine(RecoveryOutcome(RecoveryCode.OK)))
        held.runAll()
        NativeRecoveryHeadless.executor = saved
        NativeRecoveryHeadless.onOutcome = null
    }

    private fun submitArgs(vararg kv: Pair<String, Any>) = JSONObject().apply { kv.forEach { (k, v) -> put(k, v) } }

    private fun answer(action: String, args: JSONObject, e: Engine, trusted: Boolean = true) =
        NativeRecoveryShellAction.answer(action, 5, args, trusted = { trusted }, backend = e)

    @Test
    fun openNeedsAnEngineAndShowsNothing() {
        assertFalse(NativeRecoveryHeadless.open(NativeRecoveryBackend.Unavailable))
        assertFalse(NativeRecoveryHeadless.isOpen())
        assertTrue(NativeRecoveryHeadless.open(Engine(RecoveryOutcome(RecoveryCode.OK))))
        assertTrue(NativeRecoveryHeadless.isOpen())
    }

    @Test
    fun submitWithoutASessionIsNotAvailableWipedAndTheEngineIsNotCalled() {
        val e = Engine(RecoveryOutcome(RecoveryCode.OK, eoa))
        val code = goodCode.toCharArray()
        assertEquals(NativeRecoveryHeadless.NOT_AVAILABLE, NativeRecoveryHeadless.submitCode(code, e))
        assertTrue(code.all { it == '\u0000' })
        held.runAll()
        assertEquals(0, e.codeCalls)
    }

    @Test
    fun codeSubmissionRunsTheEngineWipesAndOkEndsTheSession() {
        val e = Engine(RecoveryOutcome(RecoveryCode.OK, eoa))
        val outcomes = mutableListOf<RecoveryOutcome>()
        NativeRecoveryHeadless.onOutcome = { outcomes += it }
        NativeRecoveryHeadless.open(e)
        val code = goodCode.toCharArray()
        assertNull(NativeRecoveryHeadless.submitCode(code, e))
        held.runAll()
        assertEquals(1, e.codeCalls)
        assertEquals(goodCode, e.seenCode)
        assertTrue(code.all { it == '\u0000' })
        assertEquals(RecoveryCode.OK, outcomes.single().code)
        assertFalse(NativeRecoveryHeadless.isOpen())
    }

    @Test
    fun failureKeepsTheSessionOpenForARetryAndOneSubmissionAtATime() {
        val e = Engine(RecoveryOutcome(RecoveryCode.BAD_PIN))
        NativeRecoveryHeadless.open(e)
        assertNull(NativeRecoveryHeadless.submitAccount("@some.tag", "Pw-Example-9".toCharArray(), e))
        // still running: a second submission is refused and wiped
        val second = "Pw-Example-0".toCharArray()
        assertEquals(NativeRecoveryHeadless.NOT_AVAILABLE, NativeRecoveryHeadless.submitAccount("@some.tag", second, e))
        assertTrue(second.all { it == '\u0000' })
        held.runAll()
        assertEquals(1, e.accountCalls)
        assertEquals("Pw-Example-9", e.seenPassword)
        assertTrue(NativeRecoveryHeadless.isOpen())
        // retry after the failure
        assertNull(NativeRecoveryHeadless.submitAccount("@some.tag", "Pw-Example-9".toCharArray(), e))
        held.runAll()
        assertEquals(2, e.accountCalls)
    }

    /** spec r3sc E2: an existing native account answers already_exists from the engine; the session is not ended, nothing is switched. */
    @Test
    fun alreadyExistsComesFromTheEngineAndDoesNotEndTheSession() {
        val e = Engine(RecoveryOutcome(RecoveryCode.ALREADY_EXISTS))
        NativeRecoveryHeadless.open(e)
        assertNull(NativeRecoveryHeadless.submitCode(goodCode.toCharArray(), e))
        held.runAll()
        assertTrue(NativeRecoveryHeadless.isOpen())
    }

    @Test
    fun cancelTellsTheEngineOnlyForAnOpenSession() {
        val e = Engine(RecoveryOutcome(RecoveryCode.OK))
        NativeRecoveryHeadless.cancel(e)
        assertEquals(0, e.cancels)
        NativeRecoveryHeadless.open(e)
        NativeRecoveryHeadless.cancel(e)
        assertEquals(1, e.cancels)
        assertFalse(NativeRecoveryHeadless.isOpen())
    }

    @Test
    fun untrustedSourceIsOriginRefusedTheEngineIsNotCalledAndTheSecretIsDropped() {
        val e = Engine(RecoveryOutcome(RecoveryCode.OK, eoa))
        NativeRecoveryHeadless.open(e)
        val args = submitArgs("path" to "code", "code" to goodCode)
        val ack = answer(NativeRecoveryShellAction.SUBMIT, args, e, trusted = false)
        assertFalse(ack.getBoolean("ok"))
        assertEquals("origin_refused", ack.getString("error"))
        assertFalse(args.has("code"))
        assertFalse(ack.toString().contains(goodCode))
        held.runAll()
        assertEquals(0, e.codeCalls)
        val cancel = answer(NativeRecoveryShellAction.CANCEL, JSONObject(), e, trusted = false)
        assertEquals("origin_refused", cancel.getString("error"))
        assertEquals(0, e.cancels)
    }

    private fun ascii(n: Int) = "a".repeat(n)
    private fun cjk(n: Int) = "\u5bc6".repeat(n)            // 3 UTF-8 bytes each
    private fun astral(n: Int) = "\uD83D\uDE00".repeat(n)  // 4 UTF-8 bytes each (one code point, two chars)
    private fun lone(n: Int) = "\uD800".repeat(n)           // unpaired surrogate: U+FFFD, 3 bytes each

    /** Vectors RP-05, RP-06, RN-18, RN-20 to RN-24 (pub3, R3SB-5): bad_args, the engine is not called, nothing is echoed. */
    @Test
    fun badArgsOnlyForShapeAndByteLimits() {
        val e = Engine(RecoveryOutcome(RecoveryCode.OK, eoa))
        NativeRecoveryHeadless.open(e)
        val bad = listOf(
            // RP-05 variants
            submitArgs(), submitArgs("path" to JSONObject.NULL), submitArgs("path" to "other"),
            submitArgs("path" to "code", "code" to "x", "name" to "n"),
            submitArgs("path" to "account", "name" to "n"), submitArgs("path" to "account", "password" to "p"),
            submitArgs("path" to "code", "code" to 1), submitArgs("path" to "code"),
            // RP-06: extra field
            submitArgs("path" to "code", "code" to goodCode, "mnemonic" to "m"),
            // RN-18: far over
            submitArgs("path" to "code", "code" to ascii(300)),
            submitArgs("path" to "account", "name" to ascii(200), "password" to "p"),
            submitArgs("path" to "account", "name" to "n", "password" to ascii(300)),
            // RN-20: ASCII limit + 1
            submitArgs("path" to "code", "code" to ascii(65)),
            submitArgs("path" to "account", "name" to ascii(129), "password" to "p"),
            submitArgs("path" to "account", "name" to "n", "password" to ascii(257)),
            // RN-21: 86 CJK = 258 bytes; RN-22: 17 astral = 68 bytes; RN-23: 22 lone surrogates = 66 bytes
            submitArgs("path" to "account", "name" to "n", "password" to cjk(86)),
            submitArgs("path" to "code", "code" to astral(17)),
            submitArgs("path" to "code", "code" to lone(22)),
            // RN-24: the limit is on the raw string: a leading space makes 129 bytes
            submitArgs("path" to "account", "name" to " " + ascii(128), "password" to "p"),
        )
        for (args in bad) {
            val shown = args.toString().take(80)
            val ack = answer(NativeRecoveryShellAction.SUBMIT, args, e)
            assertEquals(shown, "bad_args", ack.optString("error"))
            assertFalse(shown, args.has("code") || args.has("password") || args.has("name"))
            assertFalse(shown, ack.toString().contains("aaaa") || ack.toString().contains("\u5bc6"))
        }
        assertEquals("bad_args", answer(NativeRecoveryShellAction.CANCEL, submitArgs("x" to 1), e).getString("error"))
        held.runAll()
        assertEquals(0, e.codeCalls + e.accountCalls)
        assertTrue(NativeRecoveryHeadless.isOpen())
    }

    /** Vectors RP-17 to RP-22: within the byte limit everything goes to the engine (ok:true), empty and blank values included. */
    @Test
    fun withinTheLimitEverythingGoesToTheEngine() {
        val accepted = listOf(
            submitArgs("path" to "code", "code" to "abcdefghij"),                                  // RP-17: 10 characters
            submitArgs("path" to "code", "code" to ""),                                            // RP-18
            submitArgs("path" to "account", "name" to "@t", "password" to ""),
            submitArgs("path" to "account", "name" to "   ", "password" to "p"),
            submitArgs("path" to "code", "code" to "   "),
            submitArgs("path" to "code", "code" to ascii(64)),                                     // RP-19
            submitArgs("path" to "account", "name" to ascii(128), "password" to "p"),
            submitArgs("path" to "account", "name" to "n", "password" to ascii(256)),
            submitArgs("path" to "account", "name" to "n", "password" to cjk(85)),                 // RP-20: 255 bytes
            submitArgs("path" to "code", "code" to astral(16)),                                    // RP-21: 64 bytes
            submitArgs("path" to "code", "code" to lone(21)),                                      // RP-22: 63 bytes
        )
        var calls = 0
        for (args in accepted) {
            val e = Engine(RecoveryOutcome(RecoveryCode.INVALID_FORMAT))
            NativeRecoveryHeadless.open(e)
            val shown = args.toString().take(60)
            val ack = answer(NativeRecoveryShellAction.SUBMIT, args, e)
            assertTrue(shown, ack.getBoolean("ok"))
            held.runAll()
            assertEquals(shown, 1, e.codeCalls + e.accountCalls)
            calls++
            assertTrue(shown, NativeRecoveryHeadless.isOpen()) // invalid_format keeps the session open
        }
        assertEquals(accepted.size, calls)
    }

    @Test
    fun utf8ByteCount() {
        assertEquals(64, NativeRecoveryShellAction.utf8Bytes(ascii(64)))
        assertEquals(255, NativeRecoveryShellAction.utf8Bytes(cjk(85)))
        assertEquals(64, NativeRecoveryShellAction.utf8Bytes(astral(16)))
        assertEquals(63, NativeRecoveryShellAction.utf8Bytes(lone(21)))
        assertEquals(2, NativeRecoveryShellAction.utf8Bytes("\u00e9"))
        assertEquals(6, NativeRecoveryShellAction.utf8Bytes("\uDE00\uD800")) // reversed pair: two unpaired surrogates
        assertEquals(0, NativeRecoveryShellAction.utf8Bytes(""))
    }

    /** Vector RN-01 (r3se R4(b)): the JavaScriptInterface answers origin_refused for the three names and never reads the args. */
    @Test
    fun javascriptInterfaceRefusesTheNames() {
        for (body in listOf(
            JSONObject().put("action", "nativeRecoverySubmit").put("reqId", 4).put("args", JSONObject().put("path", "code").put("code", goodCode)),
            JSONObject().put("type", "nativeRecoverySubmit").put("reqId", 4).put("path", "code").put("code", goodCode),
            JSONObject().put("command", JSONObject().put("type", "nativeRecoveryCancel")).put("reqId", 4),
            JSONObject().put("action", "shellCapabilities").put("reqId", 4),
        )) {
            val r = NativeRecoveryShellAction.jsInterfaceRefusal(body.toString())!!
            assertEquals("origin_refused", r.getString("error"))
            assertFalse(r.toString().contains(goodCode))
        }
        assertNull(NativeRecoveryShellAction.jsInterfaceRefusal(JSONObject().put("type", "hello").put("reqId", 1).toString()))
        assertNull(NativeRecoveryShellAction.jsInterfaceRefusal("not json"))
        val main = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        val chat = main.substring(main.indexOf("open fun chatModuleCommand(json: String) {")).take(400)
        assertTrue(chat.contains("NativeRecoveryShellAction.jsInterfaceRefusal(json)"))
    }

    @Test
    fun acceptedSubmissionAcksOkWithNoDataAndTheResultIsTheEnginesEvent() {
        val e = Engine(RecoveryOutcome(RecoveryCode.OK, eoa))
        NativeRecoveryHeadless.open(e)
        val ack = answer(NativeRecoveryShellAction.SUBMIT, submitArgs("path" to "account", "name" to "@some.tag", "password" to "Pw-Example-9"), e)
        assertTrue(ack.getBoolean("ok"))
        assertEquals(setOf("type", "action", "reqId", "ok"), ack.keys().asSequence().toSet())
        held.runAll()
        assertEquals("@some.tag", e.seenName)
        val noSession = answer(NativeRecoveryShellAction.SUBMIT, submitArgs("path" to "code", "code" to goodCode), e)
        assertEquals("not_available", noSession.getString("error"))
    }

    @Test
    fun capabilityIsDeclaredOnlyWithAnEngine() {
        assertEquals(0, NativeRecoveryShellAction.capabilities(NativeRecoveryBackend.Unavailable).getJSONArray("capabilities").length())
        val caps = NativeRecoveryShellAction.capabilities(Engine(RecoveryOutcome(RecoveryCode.OK))).getJSONArray("capabilities")
        assertEquals("recovery.page-input.v1", caps.getString(0))
    }

    /** r3sc R9: a child frame or another origin is refused by the channel before any handler; the secret field is never echoed. */
    @Test
    fun channelRefusesChildFramesAndOtherOrigins() {
        val msg = JSONObject().put("action", "nativeRecoverySubmit").put("reqId", 3)
            .put("args", JSONObject().put("path", "code").put("code", goodCode)).toString()
        for ((origin, main) in listOf(
            "https://appassets.androidplatform.net" to false,
            "https://evil.example" to true,
            "null" to true,
            "https://appassets.androidplatform.net.evil.example" to true,
            "file://" to true,
        )) {
            val d = BeamioShellChannel.decide(msg, origin, main)
            assertTrue("$origin $main", d is BeamioShellChannel.Decision.Answer)
            val ack = (d as BeamioShellChannel.Decision.Answer).ack
            assertEquals("origin_refused", ack.getString("error"))
            assertFalse(ack.toString().contains(goodCode))
        }
        val ok = BeamioShellChannel.decide(msg, "https://appassets.androidplatform.net", true)
        assertTrue(ok is BeamioShellChannel.Decision.Call)
        ok as BeamioShellChannel.Decision.Call
        assertEquals(BeamioShellChannel.Arg.SECRET, ok.kind)
        assertEquals("", ok.arg) // the secret is never turned into the call's text form
        assertTrue(ok.action in BeamioShellChannel.OFF_MAIN)
    }

    /** r3sc R4: no JavascriptInterface carries the actions; the handlers never log; the only shell log line has no argument. */
    @Test
    fun actionsAreOnlyOnTheWebMessageChannelAndNothingLogsAnArgument() {
        val roots = listOf("src/main/java", "src/nativekeySdk/java", "src/nativekeyNone/java")
        val files = roots.map { File(it) }.filter { it.isDirectory }.flatMap { d -> d.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList() }
        val users = files.filter { it.readText().contains("nativeRecoverySubmit") }.map { it.name }.toSet()
        assertEquals(setOf("BeamioShellChannel.kt", "NativeRecoveryShellAction.kt", "NativeRecovery.kt", "MainActivity.kt"), users)
        val main = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        assertFalse(Regex("@JavascriptInterface[^\\n]*\\n?\\s*(?:open\\s+|override\\s+)?fun\\s+nativeRecovery").containsMatchIn(main))
        for (f in listOf("src/main/java/com/beamio/app/nativekey/NativeRecoveryShellAction.kt", "src/main/java/com/beamio/app/nativekey/NativeRecovery.kt")) {
            val src = File(f).readText()
            assertFalse(f, src.contains("Log.") || src.contains("println"))
        }
        val logLine = Regex("private fun answerRecoveryAction\\(.*?\\n    \\}\\n", RegexOption.DOT_MATCHES_ALL).find(main)!!.value
        assertFalse(logLine.contains("call.args}") || logLine.contains("call.arg}") || logLine.contains("\$args"))
    }
}
