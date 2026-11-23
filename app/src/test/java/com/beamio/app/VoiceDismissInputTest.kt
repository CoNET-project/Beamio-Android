package com.beamio.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VoiceDismissInputTest {
    @Test fun validCallIdAndSession() {
        assertTrue(VoiceDismissInput.valid("call-offer-0002", "sess-0002"))
        assertTrue(VoiceDismissInput.valid("A".repeat(128), "s"))
    }

    @Test fun callIdLengthBounds() {
        assertFalse(VoiceDismissInput.validCallId("A".repeat(7)))
        assertTrue(VoiceDismissInput.validCallId("A".repeat(8)))
        assertTrue(VoiceDismissInput.validCallId("A".repeat(128)))
        assertFalse(VoiceDismissInput.validCallId("A".repeat(129)))
    }

    @Test fun callIdCharsetRejectsOthers() {
        assertFalse(VoiceDismissInput.validCallId("call.offer.0002"))
        assertFalse(VoiceDismissInput.validCallId("call:offer:0002"))
        assertFalse(VoiceDismissInput.validCallId("call offer 0002"))
    }

    @Test fun sessionIdMustBePresent() {
        assertFalse(VoiceDismissInput.valid("call-offer-0002", ""))
        assertFalse(VoiceDismissInput.valid("call-offer-0002", "s".repeat(257)))
    }
}
