package com.beamio.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Title/notification source (v116 §135): one verified address per call, never a claimed name or tag. */
class VerifiedCallerRegistryTest {
    private val from = "0x1111111111111111111111111111111111111111"
    private val callId = "call-0001-abcdef"
    private val sessionId = "sess-0001-abcdef"

    @Test fun storesOnlyAValidLowercaseAddress() {
        VerifiedCallerRegistry.put("c-invalid-0001", "s-invalid-0001", "not-an-address")
        assertEquals("", VerifiedCallerRegistry.addressFor("c-invalid-0001", "s-invalid-0001"))
        VerifiedCallerRegistry.put(callId, sessionId, from.uppercase().replaceFirst("0X", "0x"))
        assertEquals(from, VerifiedCallerRegistry.addressFor(callId, sessionId))
        VerifiedCallerRegistry.remove(callId, sessionId)
    }

    @Test fun lookupByCallIdOrSessionId() {
        VerifiedCallerRegistry.put(callId, sessionId, from)
        assertEquals(from, VerifiedCallerRegistry.addressFor(callId, ""))
        assertEquals(from, VerifiedCallerRegistry.addressFor("", sessionId))
        VerifiedCallerRegistry.remove(callId, sessionId)
    }

    @Test fun removeClearsTheCall() {
        VerifiedCallerRegistry.put(callId, sessionId, from)
        VerifiedCallerRegistry.remove(callId, sessionId)
        assertEquals("", VerifiedCallerRegistry.addressFor(callId, sessionId))
    }

    @Test fun titleComesFromTheVerifiedAddressOnly() {
        VerifiedCallerRegistry.put(callId, sessionId, from)
        val title = IncomingCallTitle.forCall(callId, sessionId)
        assertEquals(BeamioVoiceOfferIdentity.shortAddress(from), title)
        assertFalse(title.startsWith("@"))
        VerifiedCallerRegistry.remove(callId, sessionId)
    }

    @Test fun unknownCallGivesNoTitle() {
        assertEquals("", IncomingCallTitle.forCall("call-unknown-0001", "sess-unknown-0001"))
    }

    @Test fun claimedTagIsSecondaryOnlyAndLabelled() {
        val sub = IncomingCallTitle.secondary("@alice")
        assertEquals("@alice（未核验）", sub)
        assertTrue(sub!!.endsWith(IncomingCallTitle.UNVERIFIED_SUFFIX))
    }

    /** A rebuilt activity restores the same title from the window's verified extra (process death). */
    @Test fun restoredFromWindowExtraGivesTheSameTitle() {
        VerifiedCallerRegistry.put(callId, sessionId, from)
        val before = IncomingCallTitle.forCall(callId, sessionId)
        VerifiedCallerRegistry.remove(callId, sessionId)
        assertEquals("", IncomingCallTitle.forCall(callId, sessionId))
        // The window extra holds the verified from; restoring it reproduces the title.
        VerifiedCallerRegistry.put(callId, sessionId, from)
        assertEquals(before, IncomingCallTitle.forCall(callId, sessionId))
        VerifiedCallerRegistry.remove(callId, sessionId)
    }

    @Test fun restoreIgnoresAnInvalidExtra() {
        VerifiedCallerRegistry.put(callId, sessionId, "")
        assertEquals("", IncomingCallTitle.forCall(callId, sessionId))
    }
}
