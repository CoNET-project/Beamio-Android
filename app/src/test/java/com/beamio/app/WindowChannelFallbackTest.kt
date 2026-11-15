package com.beamio.app

import com.beamio.app.legacy.ShellRecordReplies
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** window.BeamioShellRecord shell fallbacks (spec r3ef §25.52CF, r3eg §25.52CH) and reqId rules (§25.52AW.1). */
class WindowChannelFallbackTest {
    /** Spec r3ef §25.52CF.3 / r3eg §25.52CH: one answer, reqId echoed. r3ok: read's record_unreadable is envelope-level. */
    @Test
    fun windowChannelFallbacksFollowCf() {
        val r = JSONObject(ShellRecordReplies.fallback("{\"type\":\"shellRecordRead\",\"reqId\":7}"))
        assertEquals("ack", r.getString("type")); assertEquals(7, r.getInt("reqId")); assertFalse(r.getBoolean("ok"))
        assertEquals("record_unreadable", r.getString("error")); assertFalse(r.has("result"))
        val w = JSONObject(ShellRecordReplies.fallback("{\"type\":\"shellRecordWrite\",\"reqId\":\"w1\",\"record\":{}}"))
        assertEquals("w1", w.getString("reqId")); assertTrue(w.getBoolean("ok")); assertEquals("write_failed", w.getJSONObject("result").getString("code"))
        assertEquals(1, w.getJSONObject("result").length())
        // An invalid reqId never takes the fallback: envelope bad_request with reqId null.
        val bad = JSONObject(ShellRecordReplies.fallback("{\"type\":\"shellRecordRead\",\"reqId\":-1}"))
        assertTrue(bad.isNull("reqId")); assertFalse(bad.getBoolean("ok")); assertEquals("bad_request", bad.getString("error"))
        // Unknown type: envelope unknown_command (AU.1); never storage_locked as a generic fallback.
        val u = JSONObject(ShellRecordReplies.fallback("{\"type\":\"zz\",\"reqId\":3}"))
        assertEquals("unknown_command", u.getString("error"))
        for (x in listOf(r, w, bad, u)) assertFalse(x.toString().contains("storage_locked"))
        assertEquals("abc", ShellRecordReplies.validReqId("{\"reqId\":\"abc\"}"))
        assertNull(ShellRecordReplies.validReqId("{\"reqId\":\"\"}"))
    }

    @Test
    fun fallbackRefusesReqIdsOutsideAw1() {
        for (bad in listOf("-1", "9007199254740992", "1.5", "true", "\"\"", "\"" + "a".repeat(65) + "\"", "null")) {
            val r = JSONObject(ShellRecordReplies.fallback("{\"type\":\"shellRecordRead\",\"reqId\":$bad}"))
            assertTrue(bad, r.isNull("reqId")); assertEquals(bad, "bad_request", r.getString("error"))
        }
        // a request with no reqId key at all
        val none = JSONObject(ShellRecordReplies.fallback("{\"type\":\"shellRecordRead\"}"))
        assertTrue(none.isNull("reqId")); assertEquals("bad_request", none.getString("error"))
        val zero = JSONObject(ShellRecordReplies.fallback("{\"type\":\"shellRecordWrite\",\"reqId\":0}"))
        assertEquals(0, zero.getInt("reqId")); assertEquals("write_failed", zero.getJSONObject("result").getString("code"))
    }
}
