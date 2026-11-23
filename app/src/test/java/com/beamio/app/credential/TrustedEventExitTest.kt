package com.beamio.app.credential

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Frozen passcode protocol v1 §一第 4 条: the last trusted reply proxy rules (window channel). */
class TrustedEventExitTest {
    private val sent = mutableListOf<Pair<String, String>>()
    private val post: (String, String) -> Unit = { p, s -> sent += p to s }

    @Test fun emptyProxyDropsWithDiagnosticCode() {
        val exit = TrustedEventExit<String>()
        assertEquals("no_event_target", exit.deliver("{}", post))
        assertTrue(sent.isEmpty())
    }

    @Test fun trustedRequestSetsProxyAndEventGoesThrough() {
        val exit = TrustedEventExit<String>()
        exit.onTrusted("main")
        assertNull(exit.deliver("{\"x\":1}", post))
        assertEquals(listOf("main" to "{\"x\":1}"), sent)
    }

    @Test fun untrustedRequestNeverSetsProxy() {
        val exit = TrustedEventExit<String>()
        // The caller calls onTrusted only after a trusted verdict; an untrusted request makes no call.
        assertFalse(exit.hasTarget())
        assertEquals("no_event_target", exit.deliver("{}", post))
    }

    @Test fun latestTrustedRequestReplacesProxy() {
        val exit = TrustedEventExit<String>()
        exit.onTrusted("first")
        exit.onTrusted("second")
        exit.deliver("e", post)
        assertEquals("second", sent.single().first)
    }

    @Test fun rebuildClearsProxy() {
        val exit = TrustedEventExit<String>()
        exit.onTrusted("main")
        exit.reset()
        assertFalse(exit.hasTarget())
        assertEquals("no_event_target", exit.deliver("{}", post))
        assertTrue(sent.isEmpty())
    }

    @Test fun envelopeIsChatModuleEvent() {
        val inner = JSONObject().put("type", "passcodeState").put("set", true).put("locked", true)
        val env = chatModuleEventEnvelope(inner)
        assertEquals("chatModuleEvent", env.optString("action"))
        assertEquals("passcodeState", env.optJSONObject("event")?.optString("type"))
    }
}
