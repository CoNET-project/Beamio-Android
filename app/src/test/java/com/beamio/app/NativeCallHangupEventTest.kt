package com.beamio.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class NativeCallHangupEventTest {
    @Test fun eventShapeIsLocalHangupWithoutSecrets() {
        val e = NativeCallHangupEvent.build("call-offer-0002", "sess-0002", 1700000000000L)
        assertEquals("nativeCallHangup", e.getString("type"))
        assertEquals("call-offer-0002", e.getString("callId"))
        assertEquals("sess-0002", e.getString("sessionId"))
        assertEquals("local_hangup", e.getString("reason"))
        assertEquals(1700000000000L, e.getLong("at"))
        assertFalse(e.has("voice_end_v1"))
        assertFalse(e.has("passcode"))
    }
}
