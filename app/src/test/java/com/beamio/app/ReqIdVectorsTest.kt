package com.beamio.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Spec §25.52CO.3 / §25.52CQ.1 / §25.52CT.3: reqId vectors B-1 to B-18 (JSON-text entry) from
 * protocol/chat-route-decision-vectors.v1.json, sha256 9f9b7e8cc8df83d29d896c84d4d75687c9fd803b2cb283155e3dcc9fd9a35c2a
 * (r3et; B-1 to B-18 match r3eq 6d277789... except the added "entry" field). B-19 to B-21 are the structured (object body) entry, which
 * Android does not have: chatModuleCommand and BeamioChat.postMessage both take JSON text.
 */
class ReqIdVectorsTest {
    private val cases = listOf(
        Triple("B-1", "{\"type\":\"hello\",\"reqId\":\"r-1\"}", true),
        Triple("B-2", "{\"type\":\"hello\",\"reqId\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}", true),
        Triple("B-3", "{\"type\":\"hello\",\"reqId\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}", false),
        Triple("B-4", "{\"type\":\"hello\",\"reqId\":\"\"}", false),
        Triple("B-5", "{\"type\":\"hello\",\"reqId\":\"a\\nb\"}", false),
        Triple("B-6", "{\"type\":\"hello\",\"reqId\":\"\u8bf7\u6c42\"}", false),
        Triple("B-7", "{\"type\":\"hello\",\"reqId\":0}", true),
        Triple("B-8", "{\"type\":\"hello\",\"reqId\":9007199254740991}", true),
        Triple("B-9", "{\"type\":\"hello\",\"reqId\":9007199254740992}", false),
        Triple("B-10", "{\"type\":\"hello\",\"reqId\":1.5}", false),
        Triple("B-11", "{\"type\":\"hello\",\"reqId\":true}", false),
        Triple("B-12", "{\"type\":\"hello\",\"reqId\":{\"id\":1}}", false),
        Triple("B-13", "{\"type\":\"hello\"}", false),
        Triple("B-14", "{\"type\":\"hello\",\"reqId\":1.0}", false),
        Triple("B-15", "{\"type\":\"hello\",\"reqId\":1e0}", false),
        Triple("B-16", "{\"type\":\"hello\",\"reqId\":9007199254740991}", true),
        Triple("B-17", "{\"type\":\"hello\",\"reqId\":9007199254740992}", false),
        Triple("B-18", "{\"type\":\"hello\",\"reqId\":-1}", false),
    )

    @Test
    fun jsonTextVectors() {
        for ((id, body, ok) in cases) {
            val got = BridgeReqId.fromJsonText(body)
            if (ok) {
                val expected = org.json.JSONObject(body).get("reqId")
                assertEquals(id, expected.toString(), got.toString())
            } else {
                assertNull(id, got)
            }
        }
    }

    /** An invalid reqId through the new channel is bad_request in the shared path; BeamioChat only forwards JSON text. */
    @Test
    fun beamioChatForwardsTextUnchanged() {
        val d = BeamioChatChannel.decide("{\"type\":\"hello\",\"reqId\":1.0}", "https://appassets.androidplatform.net", true)
        assertEquals(true, d is BeamioChatChannel.Decision.Command)
        assertEquals("{\"type\":\"hello\",\"reqId\":1.0}", (d as BeamioChatChannel.Decision.Command).json)
    }
}
