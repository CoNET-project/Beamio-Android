package com.beamio.app.credential

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Defence in depth (2026-11-22): a page never supplies `trustedOrigin`. Ordinary chat commands and shellRecord
 * requests reach the SDK without it; page-sync commands get only the shell's own marker, set after ShellCredentialTrust.
 */
class TrustedOriginStripTest {

    @Test fun ordinaryChatCommandWithPageTrustedOriginIsStrippedBeforeTheSdk() {
        val page = """{"type":"sendMessage","reqId":4,"trustedOrigin":true,"text":"hi"}"""
        val out = JSONObject(PageSyncRoute.stripPageTrustedOriginText(page))
        assertFalse(out.has("trustedOrigin"))
        assertEquals("sendMessage", out.getString("type"))
        assertEquals("hi", out.getString("text"))
        assertEquals(4, out.getInt("reqId"))
    }

    @Test fun shellRecordRequestWithPageTrustedOriginIsStrippedBeforeTheSdk() {
        val page = """{"type":"shellRecordRead","reqId":9,"trustedOrigin":true}"""
        val out = JSONObject(PageSyncRoute.stripPageTrustedOriginText(page))
        assertFalse(out.has("trustedOrigin"))
        assertEquals("shellRecordRead", out.getString("type"))
    }

    @Test fun nestedCommandWithPageTrustedOriginIsStripped() {
        val page = """{"command":{"type":"sendMessage","reqId":2,"trustedOrigin":true}}"""
        val out = JSONObject(PageSyncRoute.stripPageTrustedOriginText(page))
        assertFalse(out.getJSONObject("command").has("trustedOrigin"))
    }

    @Test fun bodyWithoutTheFieldIsReturnedUnchanged() {
        val clean = """{"type":"sendMessage","reqId":4}"""
        assertSame(clean, PageSyncRoute.stripPageTrustedOriginText(clean))
    }

    @Test fun nonJsonIsReturnedUnchangedAndLeftToTheSdkToRefuse() {
        val bad = "not json"
        assertSame(bad, PageSyncRoute.stripPageTrustedOriginText(bad))
    }

    @Test fun objectFormStripsInPlace() {
        val body = JSONObject("""{"type":"walletCredential","reqId":1,"trustedOrigin":true}""")
        val same = PageSyncRoute.stripPageTrustedOrigin(body)
        assertSame(body, same)
        assertFalse(body.has("trustedOrigin"))
    }

    @Test fun pageSyncCommandStillGetsOnlyTheShellsOwnMarker() {
        // The page sends trustedOrigin:"forged" on a page-sync command; the shell removes it and, only when trusted, sets true.
        val page = JSONObject("""{"type":"nativeMnemonicPreread","reqId":3,"trustedOrigin":"forged"}""")
        var sdkSaw: JSONObject? = null
        PageSyncRoute.channelAnswer(page, trusted = true) { body -> sdkSaw = JSONObject(body.toString()); null }
        assertEquals(true, sdkSaw!!.get("trustedOrigin"))
    }

    @Test fun pageSyncCommandUntrustedNeverReachesTheSdkWithAMarker() {
        val page = JSONObject("""{"type":"nativeMnemonicPreread","reqId":3,"trustedOrigin":true}""")
        var called = false
        PageSyncRoute.channelAnswer(page, trusted = false) { called = true; null }
        assertFalse(called)
        assertTrue(!page.has("trustedOrigin") || page.get("trustedOrigin") != true)
    }
}
