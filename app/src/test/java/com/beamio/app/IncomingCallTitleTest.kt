package com.beamio.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IncomingCallTitleTest {
    private val addr = "0x1111111111111111111111111111111111111111"

    @Test fun titleIsTheVerifiedShortAddress() {
        val t = IncomingCallTitle.title(addr)
        assertEquals(BeamioVoiceOfferIdentity.shortAddress(addr), t)
        assertTrue(t.isNotBlank())
    }

    @Test fun noVerifiedAddressGivesNoTitle() {
        assertEquals("", IncomingCallTitle.title(""))
        assertEquals("", IncomingCallTitle.title("   "))
    }

    @Test fun claimedTagIsSecondaryAndLabelledNeverTheTitle() {
        val tag = "Alice"
        assertEquals("Alice（未核验）", IncomingCallTitle.secondary(tag))
        assertFalse(IncomingCallTitle.title(addr).contains(tag))
    }

    @Test fun blankTagGivesNoSecondaryLine() {
        assertNull(IncomingCallTitle.secondary(""))
        assertNull(IncomingCallTitle.secondary("  "))
    }
}
