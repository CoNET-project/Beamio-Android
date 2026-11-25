package com.beamio.app.nativekey

import com.beamio.app.BeamioShellChannel
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** 193 (spec r3si/r3sj item 63, vectors CP-02, CP-15, CP-16, CN-01 to CN-08). Synthetic values only; the SDK is a fake. */
class ShellAccountCreateActionTest {
    private val tag = "qasyntheticz"
    private val pw = "Synthetic-Pw-1"

    private fun args() = JSONObject().put("tag", tag).put("password", pw)

    private class Sdk(val answer: JSONObject?) {
        var calls = 0
        var seen: JSONObject? = null
        fun run(body: JSONObject): JSONObject? { calls++; seen = JSONObject(body.toString()); return answer }
    }

    @Test
    fun trustedRegisterForwardsTheArgsAndReturnsTheSdkResultInTheShellEnvelope() {
        val result = JSONObject().put("accountName", tag).put("wallet", "0x" + "c".repeat(40)).put("signMessage", "s")
            .put("recover", JSONArray().put("r1")).put("recoverCodeBase58", "SyntheticCode")
        val sdk = Sdk(JSONObject().put("type", "ack").put("reqId", 9).put("ok", true).put("result", result))
        val a = args()
        val ack = ShellAccountCreateAction.register(9, a, trusted = { true }, sdk = sdk::run)
        assertEquals(1, sdk.calls)
        assertEquals(setOf("type", "reqId", "tag", "password"), sdk.seen!!.keys().asSequence().toSet())
        assertEquals("accountCreateRegister", sdk.seen!!.getString("type"))
        assertEquals(9, sdk.seen!!.getInt("reqId"))
        assertEquals("ack", ack.getString("type")); assertEquals("accountCreateRegister", ack.getString("action"))
        assertTrue(ack.getBoolean("ok"))
        assertEquals(setOf("accountName", "wallet", "signMessage", "recover", "recoverCodeBase58"), ack.getJSONObject("result").keys().asSequence().toSet())
        assertFalse(a.has("password"))
        assertFalse(ack.toString().contains(pw))
    }

    @Test
    fun sdkRefusalsPassThroughAndATimeoutIsNotReady() {
        for (code in listOf("not_ready", "not_available", "tag_taken", "already_registered")) {
            val sdk = Sdk(JSONObject().put("type", "ack").put("reqId", 1).put("ok", false).put("error", code))
            val ack = ShellAccountCreateAction.register(1, args(), { true }, sdk::run)
            assertEquals(code, ack.getString("error"))
        }
        assertEquals("not_ready", ShellAccountCreateAction.register(1, args(), { true }, Sdk(null)::run).getString("error"))
    }

    /** CN-03/CN-04: untrusted source is origin_refused and the SDK is not called; the password is dropped. */
    @Test
    fun untrustedIsOriginRefusedAndTheSdkIsNotCalled() {
        val sdk = Sdk(null)
        val a = args()
        val ack = ShellAccountCreateAction.register(2, a, trusted = { false }, sdk = sdk::run)
        assertEquals("origin_refused", ack.getString("error"))
        assertEquals(0, sdk.calls)
        assertFalse(a.has("password"))
        assertFalse(ack.toString().contains(pw))
        // the page cannot replace the envelope fields
        val bad = ShellAccountCreateAction.register(3, args().put("type", "x"), { true }, sdk::run)
        assertEquals("bad_args", bad.getString("error")); assertEquals(0, sdk.calls)
    }

    /** CP-16, CN-06, CN-07: secureScreen takes exactly {on: boolean}. */
    @Test
    fun secureScreenArgs() {
        var state: Boolean? = null
        assertTrue(ShellAccountCreateAction.secureScreen(4, JSONObject().put("on", true), { true }) { state = it }.getBoolean("ok"))
        assertEquals(true, state)
        assertTrue(ShellAccountCreateAction.secureScreen(4, JSONObject().put("on", false), { true }) { state = it }.getBoolean("ok"))
        assertEquals(false, state)
        state = null
        for (bad in listOf(JSONObject(), JSONObject().put("on", "true"), JSONObject().put("on", 1), JSONObject().put("on", true).put("x", 1))) {
            assertEquals("bad_args", ShellAccountCreateAction.secureScreen(4, bad, { true }) { state = it }.getString("error"))
        }
        assertEquals("origin_refused", ShellAccountCreateAction.secureScreen(4, JSONObject().put("on", true), { false }) { state = it }.getString("error"))
        assertNull(state)
    }

    /** CP-15: both capabilities when both engines are mounted; each only with its engine. */
    @Test
    fun capabilities() {
        val rec = object : NativeRecoveryBackend { override val supported = true; override fun recover(recoveryCode: CharArray) = RecoveryOutcome(RecoveryCode.OK) }
        val create = object : NativeAccountCreateBackend { override val supported = true; override fun confirm(done: (CreateCode) -> Unit) = done(CreateCode.OK) }
        val both = NativeRecoveryShellAction.capabilities(rec, create).getJSONArray("capabilities")
        assertEquals(listOf("recovery.page-input.v1", "account.page-create.v1"), (0 until both.length()).map { both.getString(it) })
        assertEquals(0, NativeRecoveryShellAction.capabilities(NativeRecoveryBackend.Unavailable, NativeAccountCreateBackend.Unavailable).getJSONArray("capabilities").length())
    }

    /** CN-01, CN-02: the JavaScript interface and window.BeamioChat answer origin_refused for both names. */
    @Test
    fun otherChannelsRefuse() {
        for (body in listOf(
            JSONObject().put("type", "accountCreateRegister").put("reqId", 5).put("tag", tag).put("password", pw),
            JSONObject().put("action", "accountCreateRegister").put("reqId", 5).put("args", args()),
            JSONObject().put("action", "secureScreen").put("reqId", 5).put("args", JSONObject().put("on", true)),
        )) {
            val r = NativeRecoveryShellAction.jsInterfaceRefusal(body.toString())
            assertNotNull(r); assertEquals("origin_refused", r!!.getString("error")); assertFalse(r.toString().contains(pw))
        }
        val main = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        val chat = main.substring(main.indexOf("private fun handleChatCommand(")).take(400)
        assertTrue(chat.contains("NativeRecoveryShellAction.jsInterfaceRefusal(json)"))
        // the channel: both actions are off the main thread, the register args are never turned into text
        assertTrue("accountCreateRegister" in BeamioShellChannel.OFF_MAIN && "secureScreen" in BeamioShellChannel.OFF_MAIN)
        assertEquals(BeamioShellChannel.Arg.SECRET, BeamioShellChannel.ACTIONS["accountCreateRegister"])
        val src = File("src/main/java/com/beamio/app/nativekey/ShellAccountCreateAction.kt").readText()
        assertFalse(src.contains("Log.") || src.contains("println"))
    }

    /** CP-22 (independent review B): a repeated on:true does not restart the 10-minute timer; it counts from the first on. */
    @Test
    fun repeatedSecureScreenOnKeepsTheFirstTimer() {
        assertEquals(ShellAccountCreateAction.SecureTimer.START, ShellAccountCreateAction.secureTimerFor(wasOn = false, on = true))
        assertEquals(ShellAccountCreateAction.SecureTimer.KEEP, ShellAccountCreateAction.secureTimerFor(wasOn = true, on = true))
        assertEquals(ShellAccountCreateAction.SecureTimer.STOP, ShellAccountCreateAction.secureTimerFor(wasOn = true, on = false))
        assertEquals(ShellAccountCreateAction.SecureTimer.STOP, ShellAccountCreateAction.secureTimerFor(wasOn = false, on = false))
        val main = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        val body = Regex("private fun answerSecureScreen\\(.*?\\n    \\}\\n", RegexOption.DOT_MATCHES_ALL).find(main)!!.value
        assertTrue(body.contains("ShellAccountCreateAction.secureTimerFor(secureScreenRequested, on)"))
        assertTrue(body.contains("SecureTimer.KEEP -> Unit"))
        // the state is read before it is updated, so a second on sees wasOn = true
        assertTrue(body.indexOf("secureTimerFor(secureScreenRequested, on)") < body.indexOf("secureScreenRequested = on"))
    }
}
