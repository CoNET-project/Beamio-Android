package com.beamio.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class InCallToolsPanelTapTest {
    @Test
    fun collapsesOnlyWhenOpenOverPeerVideo() {
        assertTrue(InCallToolsPanelTap.collapses(peerVideoActive = true, toolsExpanded = true))
    }

    @Test
    fun audioOnlyPanelNeverCollapses() {
        assertFalse(InCallToolsPanelTap.collapses(peerVideoActive = false, toolsExpanded = true))
        assertFalse(InCallToolsPanelTap.collapses(peerVideoActive = false, toolsExpanded = false))
    }

    @Test
    fun alreadyCollapsedStaysCollapsed() {
        assertFalse(InCallToolsPanelTap.collapses(peerVideoActive = true, toolsExpanded = false))
    }
}
