package com.beamio.app

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ReqCorrelationTest {
    @Test
    fun headNeedsTypeAndValidReqId() {
        assertEquals("hello" to 42, ReqCorrelation.head("{\"type\":\"hello\",\"reqId\":42}"))
        assertNull(ReqCorrelation.head("{\"type\":\"hello\"}"))
        assertNull(ReqCorrelation.head("{\"reqId\":1}"))
        assertNull(ReqCorrelation.head("not json"))
        assertNull(ReqCorrelation.head(null))
    }

    @Test
    fun replyCarriesOnlyNamesTimesAndCodes() {
        val ack = JSONObject("{\"type\":\"ack\",\"reqId\":42,\"ok\":true,\"eoa\":\"0x1234567890123456789012345678901234567890\",\"result\":{\"x\":1}}")
        val line = ReqCorrelation.reply("chat", "hello", 42L, 120, ack)!!
        assertEquals("channel=chat phase=reply cmd=hello reqId=42 ms=120 ok=true error=none", line)
        assertFalse(line.contains("0x12"))
    }

    @Test
    fun lateReplyIsMarkedAndUnsafeErrorIsDropped() {
        val ack = JSONObject("{\"type\":\"ack\",\"reqId\":7,\"ok\":false,\"error\":\"bad value with spaces 0xABC\"}")
        val line = ReqCorrelation.reply("chat", "hello", 7L, 9_890, ack)!!
        assertTrue(line.endsWith("ms=9890 ok=false error=none late=true"))
    }

    @Test
    fun unsafeCommandIsNotLoggedAndUnsafeReqIdIsInvalid() {
        assertNull(ReqCorrelation.head("{\"type\":\"hello world\",\"reqId\":1}"))
        assertNull(ReqCorrelation.head("{\"type\":\"${"a".repeat(65)}\",\"reqId\":1}"))
        assertEquals("invalid", ReqCorrelation.safeRid("0xabc with spaces"))
        assertEquals("invalid", ReqCorrelation.safeRid("x".repeat(41)))
        assertEquals("1796034832073", ReqCorrelation.safeRid(1796034832073L))
        assertEquals("pwa-7", ReqCorrelation.safeRid("pwa-7"))
    }

    @Test
    fun nonAckIsNotLogged() {
        assertNull(ReqCorrelation.reply("chat", "hello", 1L, 3, JSONObject("{\"type\":\"chatModuleEvent\",\"reqId\":1}")))
        assertTrue(ReqCorrelation.isAck(JSONObject("{\"event\":{\"type\":\"ack\"}}")))
    }
}
