package com.beamio.app.legacy

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Null-hook contract (2026-11-22, condition 1). The channel answers through [shellRecordAnswer]; with no hook
 * the answer must equal the pre-change expression byte for byte, for shellRecordRead and for other types, both when the
 * SDK answers and when it throws (fallback). The debugqa hook itself is covered in src/qaHooks.
 */
class QaReadFaultHookTest {
    private val readBody = """{"type":"shellRecordRead","reqId":"r-1"}"""
    private val otherBody = """{"type":"shellRecordWrite","reqId":"w-2"}"""

    @After fun restoreDefault() { QaReadFaults.current = null }

    /** The pre-change expression, copied from ShellRecordChannel before this change. */
    private fun before(sdk: () -> String, data: String): String =
        try { sdk() } catch (e: Exception) { ShellRecordReplies.fallback(data) }

    @Test fun defaultHookIsNullInEveryBuildWithoutQaHooks() {
        assertNull(QaReadFaults.current)
    }

    @Test fun nullHookSdkAnswerIsByteIdenticalForReadAndOtherTypes() {
        QaReadFaults.current = null
        for (data in listOf(readBody, otherBody)) {
            val sdk = { """{"type":"ack","reqId":"x","ok":true,"result":{"code":"ok"}}""" }
            val old = before(sdk, data)
            val now = shellRecordAnswer(QaReadFaults.current, org.json.JSONObject(data).optString("type"), data, sdk)
            assertEquals(old, now)
        }
    }

    @Test fun nullHookThrowingSdkFallsBackByteIdentically() {
        QaReadFaults.current = null
        for (data in listOf(readBody, otherBody)) {
            val boom = { throw IllegalStateException("sdk down") }
            val old = before(boom, data)
            // Same shape as the channel call: the try/catch lives inside the normal-path lambda.
            val now = shellRecordAnswer(QaReadFaults.current, org.json.JSONObject(data).optString("type"), data) {
                try { boom() } catch (e: Exception) { ShellRecordReplies.fallback(data) }
            }
            assertEquals(old, now)
            assertEquals(ShellRecordReplies.fallback(data), now)
        }
    }

    @Test fun installedHookAnswersOnlyWhenItReturnsNonNull() {
        val hook = object : QaReadFault {
            override fun replyFor(type: String, data: String): String? = if (type == "shellRecordRead") "HOOK" else null
        }
        val sdk = { "SDK" }
        assertEquals("HOOK", shellRecordAnswer(hook, "shellRecordRead", readBody, sdk))
        assertEquals("SDK", shellRecordAnswer(hook, "shellRecordWrite", otherBody, sdk))
    }

    /** Four shellRecordRead inputs (QA read-fault spec, item 1): ok, no_key stripped, record_unreadable, timeout. Fixed fixtures. */
    private fun fixtureFor(kind: String, reqId: String): () -> String = when (kind) {
        "ok" -> { { """{"type":"ack","reqId":"$reqId","ok":true,"result":{"code":"ok","rev":1,"schemaVersion":1,"record":{"schemaVersion":2,"rev":1,"profiles":[]}}}""" } }
        "no_key" -> { { """{"type":"ack","reqId":"$reqId","ok":false,"error":"no_key"}""" } }
        "record_unreadable" -> { { ShellRecordReplies.fallback("""{"type":"shellRecordRead","reqId":"$reqId"}""") } }
        "timeout" -> { { throw java.util.concurrent.TimeoutException("reply after window") } }
        else -> error("unknown fixture $kind")
    }

    @Test fun nullHookFourShellRecordReadInputsAreByteIdenticalToBefore() {
        QaReadFaults.current = null
        for (kind in listOf("ok", "no_key", "record_unreadable", "timeout")) {
            val data = """{"type":"shellRecordRead","reqId":"fx-$kind"}"""
            val sdk = fixtureFor(kind, "fx-$kind")
            val old = before(sdk, data)
            val now = shellRecordAnswer(QaReadFaults.current, "shellRecordRead", data) {
                try { sdk() } catch (e: Exception) { ShellRecordReplies.fallback(data) }
            }
            assertEquals("kind=$kind", old, now)
        }
    }
}
