package com.beamio.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Spec §25.52AW.1 boundaries for bridge reqIds. */
class BridgeReqIdTest {
    @Test
    fun integers() {
        assertEquals(0, BridgeReqId.valid(0))
        assertEquals(7, BridgeReqId.valid(7))
        assertNull(BridgeReqId.valid(-1))
        assertEquals(9_007_199_254_740_991L, BridgeReqId.valid(9_007_199_254_740_991L))
        assertNull(BridgeReqId.valid(9_007_199_254_740_992L))
        assertNull(BridgeReqId.valid(-5L))
        assertNull(BridgeReqId.valid(1.5))
        assertNull(BridgeReqId.valid(1.0))
    }

    @Test
    fun strings() {
        val s64 = "a".repeat(64)
        assertEquals(s64, BridgeReqId.valid(s64))
        assertNull(BridgeReqId.valid("a".repeat(65)))
        assertNull(BridgeReqId.valid(""))
        assertEquals("r-1 ~", BridgeReqId.valid("r-1 ~"))
        assertNull(BridgeReqId.valid("a\u0001b"))   // control character
        assertNull(BridgeReqId.valid("caf\u00e9"))  // non-ASCII
    }

    @Test
    fun otherTypesAndJsonText() {
        assertNull(BridgeReqId.valid(true))
        assertNull(BridgeReqId.valid(null))
        assertNull(BridgeReqId.valid(org.json.JSONObject.NULL))
        assertEquals(12, BridgeReqId.fromJsonText("{\"url\":\"https://x\",\"reqId\":12}"))
        assertNull(BridgeReqId.fromJsonText("{\"url\":\"https://x\",\"requestId\":\"abc\"}"))
        assertNull(BridgeReqId.fromJsonText("https://plain.example/url"))
    }
}
