package com.beamio.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**: NFC card links are deprecated; SUN URLs are blocked on any host containing beamio.app/beamio.ca. */
class BeamioNfcSunBlockTest {
    private val sunQuery = setOf("uid", "e", "c", "m")

    @Test
    fun sunUrlsAreBlockedOnBothDomainsSubdomainsAndLookalikes() {
        for (h in listOf(
            "beamio.app", "www.beamio.app", "pos.beamio.app", "beamio.ca", "www.beamio.ca", "pos.beamio.ca", "BEAMIO.CA",
            // block-only wide match, lookalikes included
            "beamio.app.evil.com", "beamio.ca.evil.com", "notbeamio.app", "xbeamio.ca", "evil-beamio.app.example",
        )) {
            assertTrue("$h /api/sun", BeamioNfcSunBlock.isBlockedSunUrl(h, "/api/sun", emptySet()))
            assertTrue("$h /sun", BeamioNfcSunBlock.isBlockedSunUrl(h, "/app/sun", emptySet()))
            assertTrue("$h query", BeamioNfcSunBlock.isBlockedSunUrl(h, "/app/", sunQuery + "ref"))
        }
    }

    /**: cashtrees.beamio.app and its subdomains stay exempt (exact names); lookalikes are blocked. */
    @Test
    fun cashtreesKeepsThePreMigrationExclusion() {
        for (h in listOf("cashtrees.beamio.app", "CASHTREES.BEAMIO.APP", "x.cashtrees.beamio.app")) {
            assertFalse(h, BeamioNfcSunBlock.isBlockedSunUrl(h, "/api/sun", sunQuery))
        }
        // the substring bypass is closed; lookalikes that contain the whole string are blocked.
        for (h in listOf("cashtrees.beamio.app.evil.example", "x-cashtrees.beamio.app.evil.com", "evilcashtrees.beamio.app", "cashtrees.beamio.app-evil.com", "cashtrees.beamio.ca")) {
            assertTrue(h, BeamioNfcSunBlock.isBlockedSunUrl(h, "/api/sun", sunQuery))
        }
        val src = File("src/main/java/com/beamio/app/BeamioNfcSunBlock.kt").readText()
        assertTrue(src.contains("if (h == \"cashtrees.beamio.app\" || h.endsWith(\".cashtrees.beamio.app\")) return false"))
        assertFalse("no substring exemption", src.contains("contains(\"cashtrees"))
    }

    @Test
    fun ordinaryLinksAndOtherHostsAreNotTouched() {
        assertFalse(BeamioNfcSunBlock.isBlockedSunUrl("beamio.ca", "/app/", setOf("invite")))
        assertFalse(BeamioNfcSunBlock.isBlockedSunUrl("beamio.ca", "/app/", setOf("uid", "e", "c")))
        assertFalse(BeamioNfcSunBlock.isBlockedSunUrl("example.com", "/api/sun", sunQuery))
        assertFalse(BeamioNfcSunBlock.isBlockedSunUrl(null, "/api/sun", sunQuery))
    }

    /** The wide match is for blocking only: the allow list stays exact . */
    @Test
    fun allowListDoesNotUseTheWideMatch() {
        for (h in listOf("beamio.app.evil.com", "pos.beamio.ca", "notbeamio.app")) assertFalse(h, BeamioWebHosts.isWebHost(h))
        val hosts = File("src/main/java/com/beamio/app/BeamioWebHosts.kt").readText()
        assertFalse(hosts.contains("BeamioNfcSunBlock.is"))
        val embedded = File("src/main/java/com/beamio/app/embedded/EmbeddedPwaHost.kt").readText()
        assertFalse(embedded.contains("BeamioNfcSunBlock"))
    }

    /** Source guard: every shell WebView blocks main-frame SUN requests; deep links drop them; NFC tags stay consumed. */
    @Test
    fun blockIsWiredInEveryWebViewAndNfcStaysDeprecated() {
        val main = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        assertTrue(main.contains("return BeamioNfcSunBlock.isBlockedSunUrl(u.host, u.path, names)"))
        assertTrue("embedded page and remote page navigation", Regex("""shouldBlockBeamioNdefTopLevelNavigation\(""").findAll(main).count() >= 5)
        assertTrue("in-app browser intercept", main.contains("sunBlockedMainFrameResponse(request) ?: QaWriteGuard.intercept(request, \"browser\")"))
        assertTrue("remote page intercept", main.contains("sunBlockedMainFrameResponse(request) ?: QaWriteGuard.intercept(request, \"remote\")"))
        assertTrue("embedded page intercept", main.contains("sunBlockedMainFrameResponse(request)?.let { return it }"))
        assertEquals("in-app browser overrides and popup route", 3, Regex("""isBlockedSunUri\(next\)""").findAll(main).count())
        // external launches. Bridge openURL refuses SUN; every startActivity passes the SUN gate first.
        val ext = main.substringAfter("private fun openExternalUrlFromBridge(raw: String) {").substringBefore("startActivity(")
        assertTrue("bridge openURL refuses SUN before any launch", ext.contains("isBlockedSunUri(uri)) return"))
        // Both external openers go through that function (and then through the startActivity gate).
        val leave = main.substringAfter("private fun leaveEmbeddedForExternal(url: String): Boolean {").substringBefore("\n    }\n")
        assertTrue("leaveEmbeddedForExternal opens externally only via openExternalUrlFromBridge", leave.contains("openExternalUrlFromBridge(url)") && !leave.contains("startActivity("))
        val openUrl = main.substringAfter("open fun openURL(url: String) {").substringBefore("\n        }\n")
        assertTrue("bridge openURL opens externally only via openExternalUrlFromBridge", openUrl.contains("openExternalUrlFromBridge(url)") && !openUrl.contains("startActivity("))
        assertEquals("both startActivity overrides gate SUN first", 2, Regex("""override fun startActivity\(intent: Intent[^)]*\) \{\n\s+if \(isSunExternalIntent\(intent\)\) return""").findAll(main).count())
        val gate = main.substringAfter("private fun isSunExternalIntent(intent: Intent?): Boolean {").substringBefore("\n    }\n")
        for (k in listOf("intent.data", "intent.selector?.data", "browser_fallback_url", "isBlockedSunUri(u)")) assertTrue("gate checks $k", gate.contains(k))
        // Main WebView has no popup path: no multiple windows and no onCreateWindow in its chrome client.
        val chrome = main.substringAfter("private val webChromeClient: WebChromeClient = object : WebChromeClient() {").substringBefore("\n    }\n")
        assertFalse("main WebView chrome client has no onCreateWindow", chrome.contains("onCreateWindow"))
        val base = main.substringAfter("private fun createBaseWebView(").substringBefore("\n    }\n")
        assertFalse("main WebView does not enable multiple windows", base.contains("setSupportMultipleWindows(true)"))
        val apply = main.substringAfter("private fun applyPendingDeepLinkIfReady() {").substringBefore("mapBeamioAppUrlToLocal(")
        assertTrue("deep links drop SUN URLs before any mapping", apply.contains("isBlockedSunUri(https)"))
        assertTrue("NFC tag intents still consumed", main.contains("// Card binding is removed (GAP-17): every NFC tag intent is consumed here and goes nowhere else."))
    }
}
