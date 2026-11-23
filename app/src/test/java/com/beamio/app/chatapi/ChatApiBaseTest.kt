package com.beamio.app.chatapi

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 2026-11-17: the SDK's default API base (beamio.app) must never reach a request; the shell pins it on init. */
class ChatApiBaseTest {
    @Test
    fun initWithoutBaseGetsThePinnedBase() {
        val body = ChatApiBase.pin(JSONObject().put("type", "init").put("reqId", 1))
        assertEquals("https://beamio.ca/api", body.getString("apiBaseUrl"))
    }

    @Test
    fun initWithAnotherBaseIsOverriddenNotKept() {
        val body = ChatApiBase.pin(JSONObject().put("type", "init").put("apiBaseUrl", "https://beamio.app/api"))
        assertEquals("https://beamio.ca/api", body.getString("apiBaseUrl"))
    }

    @Test
    fun otherCommandWithoutTheFieldIsUnchanged() {
        val body = ChatApiBase.pin(JSONObject().put("type", "walletStatus").put("reqId", 2))
        assertFalse(body.has("apiBaseUrl"))
        assertEquals("walletStatus", body.getString("type"))
    }

    @Test
    fun otherCommandCarryingTheFieldIsPinnedToo() {
        val body = ChatApiBase.pin(JSONObject().put("type", "send").put("apiBaseUrl", "https://beamio.app/api"))
        assertEquals("https://beamio.ca/api", body.getString("apiBaseUrl"))
        assertTrue(body.has("type"))
    }

    @Test
    fun pinnedBaseIsNeverTheParkingHost() {
        assertFalse(ChatApiBase.PINNED.contains("beamio.app"))
        assertEquals("https://beamio.ca/api", ChatApiBase.PINNED)
    }
}
