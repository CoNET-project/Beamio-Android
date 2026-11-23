package com.beamio.app

import org.json.JSONException
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Log hygiene: page console text and exception messages stay out of release and store logcat. */
class ReleaseLogPolicyTest {
    private val main = File("src/main/java/com/beamio/app/MainActivity.kt").readText()

    @Test
    fun releaseConsumesConsoleMessagesAndDebugKeepsTheDefault() {
        assertTrue("release/store (BuildConfig.DEBUG=false) must consume", ReleaseLogPolicy.consumeConsoleMessage(debug = false))
        assertFalse("debug/debugqa keep the WebView default", ReleaseLogPolicy.consumeConsoleMessage(debug = true))
    }

    @Test
    fun onConsoleMessageReturnsThePolicyForThisBuild() {
        val fn = main.substringAfter("override fun onConsoleMessage(consoleMessage: android.webkit.ConsoleMessage?): Boolean {")
            .substringBefore("\n        }\n")
        assertTrue(fn.contains("return ReleaseLogPolicy.consumeConsoleMessage(BuildConfig.DEBUG)"))
        // The only other return is the null guard, which has no text to log.
        assertEquals(listOf("return false", "return ReleaseLogPolicy.consumeConsoleMessage(BuildConfig.DEBUG)"),
            Regex("return [^\\n]+").findAll(fn).map { it.value.trim() }.toList())
    }

    @Test
    fun releaseExceptionDetailIsTheClassOnlyEvenWhenTheMessageEchoesTheInput() {
        val input = "{\"callId\":\"SYNTH-CALL\",\"armor\":\"SYNTH-ARMOR\""
        val error = runCatching { JSONObject(input) }.exceptionOrNull()!!
        assertTrue(error is JSONException)
        assertEquals("JSONException", ReleaseLogPolicy.exceptionDetail(error, debug = false))
        assertFalse(ReleaseLogPolicy.exceptionDetail(error, debug = false).contains("SYNTH"))
    }

    @Test
    fun theThreeJsonParseSitesLogTheClassOnlyInRelease() {
        assertFalse(main.contains("Log.w(TAG, \"postPgpCiphertext failed: \${error.message}\")"))
        assertFalse(main.contains("Log.w(TAG, \"notifyVoiceMicReady parse failed: \${error.message}\")"))
        assertTrue(main.contains("postPgpCiphertext failed: \${ReleaseLogPolicy.exceptionDetail(error, BuildConfig.DEBUG)}"))
        assertTrue(main.contains("notifyVoiceMicReady parse failed: \${ReleaseLogPolicy.exceptionDetail(error, BuildConfig.DEBUG)}"))
        val report = main.substringAfter("open fun reportIncomingSystemCall(json: String) {").substringBefore("val callId = body.optString(\"callId\")")
        assertTrue(report.contains("if (BuildConfig.DEBUG) Log.e(\"BeamioVoiceCall\", \"Invalid reportIncomingSystemCall JSON\", it)"))
        assertTrue(report.contains("else Log.e(\"BeamioVoiceCall\", \"Invalid reportIncomingSystemCall JSON: \${it.javaClass.simpleName}\")"))
    }
}
