package com.beamio.app.legacy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertSame
import org.junit.Test

/**
 * Attachment and the no-context answer (the SDK call itself needs a device, see the on-device checks).
 * Before the fix [PageBridgeHandlers.current] stayed null and the channel never attached.
 */
class ShellRecordBridgeAdapterTest {
    private val body = """{"type":"shellRecordRead","reqId":"r-1"}"""

    @Test fun installAssignsThePageBridge() {
        ShellRecordBridgeAdapter.install { null }
        assertNotNull(PageBridgeHandlers.current)
        assertSame(ShellRecordBridgeAdapter, PageBridgeHandlers.current)
    }

    @Test fun noContextAnswersWithTheChannelFallbackNeverAnEmptySuccess() {
        ShellRecordBridgeAdapter.install { null }
        val out = ShellRecordBridgeAdapter.handle(true, body, body.toByteArray().size)
        assertEquals(ShellRecordReplies.fallback(body), out)
    }
}
