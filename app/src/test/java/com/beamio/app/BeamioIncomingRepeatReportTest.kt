package com.beamio.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BeamioIncomingRepeatReportTest {
    @Test
    fun repeatBeforeTelecomHasTheCallOnlyKeepsTheCaller() {
        // Page reported, Telecom has not created the Connection yet, push lands.
        assertFalse(BeamioIncomingRepeatReport.refreshShownWindow(hasConnection = false, windowArmed = false))
    }

    @Test
    fun repeatAfterTheWindowIsUpRefreshesIt() {
        // Samsung 1.0.161 crash case: window and ring already up, push 0.3 s later.
        assertTrue(BeamioIncomingRepeatReport.refreshShownWindow(hasConnection = true, windowArmed = true))
        assertTrue(BeamioIncomingRepeatReport.refreshShownWindow(hasConnection = true, windowArmed = false))
        // CallStyle fallback armed without a Connection (Telecom watchdog).
        assertTrue(BeamioIncomingRepeatReport.refreshShownWindow(hasConnection = false, windowArmed = true))
    }
}
