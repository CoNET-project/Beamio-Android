package com.beamio.app.net

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.net.Proxy
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.URI

/** 2026-11-17: no request to the legacy parking host beamio.app leaves the device; beamio.ca stays unchanged. */
class LegacyBeamioHostGuardTest {
    private val logs = mutableListOf<String>()
    private val delegateCalls = mutableListOf<String>()

    /** A stand-in for the previously installed selector: always NO_PROXY, records each host it was asked about. */
    private val delegate = object : ProxySelector() {
        override fun select(uri: URI?): List<Proxy> {
            delegateCalls += uri?.host ?: "?"
            return listOf(Proxy.NO_PROXY)
        }

        override fun connectFailed(uri: URI?, sa: SocketAddress?, ioe: java.io.IOException?) {
            delegateCalls += "failed:${uri?.host}"
        }
    }

    @Before
    fun setUp() {
        logs.clear()
        delegateCalls.clear()
        LegacyBeamioHostGuard.logSink = { logs += it }
    }

    @After
    fun tearDown() {
        LegacyBeamioHostGuard.logSink = { }
    }

    @Test
    fun legacyHostsAreRecognisedAndNothingElse() {
        assertTrue(LegacyBeamioHostGuard.isLegacyHost("beamio.app"))
        assertTrue(LegacyBeamioHostGuard.isLegacyHost("BEAMIO.APP"))
        assertTrue(LegacyBeamioHostGuard.isLegacyHost("www.beamio.app"))
        assertTrue(LegacyBeamioHostGuard.isLegacyHost("api.beamio.app."))
        assertFalse(LegacyBeamioHostGuard.isLegacyHost("beamio.ca"))
        assertFalse(LegacyBeamioHostGuard.isLegacyHost("www.beamio.ca"))
        assertFalse(LegacyBeamioHostGuard.isLegacyHost("beamio.app.evil.example"))
        assertFalse(LegacyBeamioHostGuard.isLegacyHost("notbeamio.app.example"))
        assertFalse(LegacyBeamioHostGuard.isLegacyHost(null))
    }

    @Test
    fun legacyRequestIsRoutedToTheDeadProxyAndNotDelegated() {
        val selector = LegacyBeamioHostGuard.selectorFor(delegate)
        val proxies = selector.select(URI("https://beamio.app/api/search-users?keyward=0xabc"))
        assertEquals(1, proxies.size)
        assertEquals(Proxy.Type.HTTP, proxies[0].type())
        assertEquals("127.0.0.1:9", proxies[0].address().toString().removePrefix("/"))
        assertTrue(delegateCalls.isEmpty())
    }

    @Test
    fun legacyBlockLogsHostAndPathPrefixOnlyNeverTheQuery() {
        val selector = LegacyBeamioHostGuard.selectorFor(delegate)
        selector.select(URI("https://www.beamio.app/api/receiveUsdc3009/extra?keyward=0xSECRET&token=abc"))
        assertEquals(listOf("blocked legacy host=www.beamio.app path=/api"), logs)
        assertFalse(logs.any { it.contains("SECRET") || it.contains("token") || it.contains("?") })
    }

    @Test
    fun beamioCaRequestsAreDelegatedUnchanged() {
        val selector = LegacyBeamioHostGuard.selectorFor(delegate)
        val proxies = selector.select(URI("https://beamio.ca/api/search-users?keyward=0xabc"))
        assertEquals(listOf(Proxy.NO_PROXY), proxies)
        assertEquals(listOf("beamio.ca"), delegateCalls)
        assertTrue(logs.isEmpty())
    }

    @Test
    fun manifestAndBundleOnBeamioCaAreNotBlocked() {
        val selector = LegacyBeamioHostGuard.selectorFor(delegate)
        assertEquals(listOf(Proxy.NO_PROXY), selector.select(URI("https://beamio.ca/app/update.json")))
        assertEquals(listOf(Proxy.NO_PROXY), selector.select(URI("https://beamio.ca/app/SilentPassUI-0.52.933.zip")))
        assertTrue(logs.isEmpty())
    }

    @Test
    fun connectFailedForLegacyHostIsSwallowedAndOthersAreDelegated() {
        val selector = LegacyBeamioHostGuard.selectorFor(delegate)
        selector.connectFailed(URI("https://beamio.app/x"), null, null)
        selector.connectFailed(URI("https://beamio.ca/x"), null, null)
        assertEquals(listOf("failed:beamio.ca"), delegateCalls)
    }

    @Test
    fun logLineHasOnlyTheHostAndTheFirstPathSegment() {
        assertEquals("blocked legacy host=beamio.app path=/", LegacyBeamioHostGuard.logLine("beamio.app", "/"))
        assertEquals("blocked legacy host=beamio.app path=/a", LegacyBeamioHostGuard.logLine("beamio.app", "/a/b/c/d"))
        assertEquals("blocked legacy host=beamio.app path=/cardMetadata", LegacyBeamioHostGuard.logLine("beamio.app", "/cardMetadata/0xSECRETID"))
    }

    /** Process start (push wake-ups included) installs the guard: the Application class is the manifest's application. */
    @Test
    fun guardIsInstalledByTheApplicationAtProcessStart() {
        val manifest = java.io.File("src/main/AndroidManifest.xml").readText()
        assertTrue(manifest.contains("android:name=\".BeamioGuardApplication\""))
        val app = java.io.File("src/main/java/com/beamio/app/BeamioGuardApplication.kt").readText()
        assertTrue(app.contains("LegacyBeamioHostGuard.install()"))
    }

    /** Navigation to a legacy host is cancelled unless mapped locally; beamio.ca navigation is not touched. */
    @Test
    fun legacyNavigationIsCancelledAndLogsOnlyHostAndFirstSegment() {
        assertTrue(LegacyBeamioHostGuard.cancelNavigation("beamio.app", "/cardMetadata/0xSECRET", mappedLocally = false))
        assertTrue(LegacyBeamioHostGuard.cancelNavigation("www.beamio.app", "/x", mappedLocally = false))
        assertEquals(listOf("blocked legacy host=beamio.app path=/cardMetadata", "blocked legacy host=www.beamio.app path=/x"), logs)
        assertFalse(LegacyBeamioHostGuard.cancelNavigation("beamio.app", "/app/index.html", mappedLocally = true))
        assertFalse(LegacyBeamioHostGuard.cancelNavigation("beamio.ca", "/app/", mappedLocally = false))
        assertFalse(LegacyBeamioHostGuard.cancelNavigation(null, null, mappedLocally = false))
    }

    /** The main WebView client cancels legacy navigation in both overrides (static wiring check). */
    @Test
    fun mainWebViewClientCancelsLegacyNavigationInBothOverrides() {
        val main = java.io.File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        assertTrue(main.split("LegacyBeamioHostGuard.cancelNavigation(").size - 1 >= 3)
    }

    /** The openURL bridge refuses legacy hosts before ACTION_VIEW (static wiring check) and beamio.ca is not refused there. */
    @Test
    fun openUrlBridgeRefusesLegacyHostBeforeStartActivity() {
        val main = java.io.File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        val start = main.indexOf("private fun openExternalUrlFromBridge")
        val fn = main.substring(start, start + 4000)
        val refuseAt = fn.indexOf("LegacyBeamioHostGuard.refuseExternal(scheme")
        val launchAt = fn.indexOf("startActivity(")
        assertTrue("refuse before any launch", refuseAt >= 0 && (launchAt < 0 || refuseAt < launchAt))
        logs.clear()
        assertTrue(LegacyBeamioHostGuard.refuseExternal("https", "beamio.app", "/x"))
        assertTrue(LegacyBeamioHostGuard.refuseExternal("https", "www.beamio.app", "/x"))
        assertFalse(LegacyBeamioHostGuard.refuseExternal("https", "beamio.ca", "/x"))
        assertEquals(2, logs.size)
    }

    /** Every WebView client that can load arbitrary URLs refuses legacy requests (static wiring check). */
    @Test
    fun everyArbitraryWebViewClientHasARequestRefusal() {
        val main = java.io.File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        assertTrue(main.split("override fun shouldInterceptRequest(").size - 1 >= 4)
        // The in-app and remote clients share legacyHostBlockedResponse(request); every client still refuses.
        val refusals = (main.split("LegacyBeamioHostGuard.blockedResponse()").size - 1) + (main.split("legacyHostBlockedResponse(request)").size - 1)
        assertTrue("refusal sites: $refusals", refusals >= 4)
    }

    // ---- external hand-off decisions (r8, 2026-11-17: positive and negative cases) ----

    /** N6 (openURL bridge), N2/N4 (subdomains) are refused; P5 (third-party https) and P6 (market / Play) are not. */
    @Test
    fun externalDecisionRefusesLegacyHttpsAndAllowsOthers() {
        assertTrue(LegacyBeamioHostGuard.isExternalRefused("https", "beamio.app"))
        assertTrue(LegacyBeamioHostGuard.isExternalRefused("https", "www.beamio.app"))
        assertTrue(LegacyBeamioHostGuard.isExternalRefused("https", "cashtrees.beamio.app"))
        assertTrue(LegacyBeamioHostGuard.isExternalRefused("http", "beamio.app"))
        assertFalse(LegacyBeamioHostGuard.isExternalRefused("https", "beamio.ca"))
        assertFalse(LegacyBeamioHostGuard.isExternalRefused("https", "basescan.org"))
        assertFalse(LegacyBeamioHostGuard.isExternalRefused("https", "play.google.com"))
        assertFalse(LegacyBeamioHostGuard.isExternalRefused("market", "details"))
        assertFalse(LegacyBeamioHostGuard.isExternalRefused("beamio", "open"))
        assertFalse(LegacyBeamioHostGuard.isExternalRefused("https", "notbeamio.app.example"))
        assertFalse(LegacyBeamioHostGuard.isExternalRefused(null, "beamio.app"))
    }

    /** refuseExternal logs one blocked line (host and first segment) and returns true only for a refused legacy https/http URL. */
    @Test
    fun refuseExternalLogsOnlyHostAndFirstSegment() {
        logs.clear()
        assertTrue(LegacyBeamioHostGuard.refuseExternal("https", "beamio.app", "/usdc-topup/SECRET"))
        assertFalse(LegacyBeamioHostGuard.refuseExternal("https", "basescan.org", "/tx/0x1"))
        assertEquals(listOf("blocked legacy host=beamio.app path=/usdc-topup"), logs)
    }

    /** P4: a legacy path mapped to the embedded bundle is not refused (the mapping is consulted first). */
    @Test
    fun mappedLocalLegacyPathIsNotCancelled() {
        logs.clear()
        assertFalse(LegacyBeamioHostGuard.cancelNavigation("beamio.app", "/app/index.html", mappedLocally = true))
        assertTrue(logs.isEmpty())
    }

    /** N6 ordering: the openURL bridge refuses before ACTION_VIEW; the intent branch refuses a legacy data or fallback host (static). */
    @Test
    fun externalLaunchSitesRefuseLegacyBeforeLaunching() {
        val main = java.io.File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        val bridge = main.substring(main.indexOf("private fun openExternalUrlFromBridge"), main.indexOf("private fun openExternalUrlFromBridge") + 1800)
        assertTrue(bridge.indexOf("refuseExternal(scheme, uri.host, uri.path)") in 0 until bridge.indexOf("startActivity(Intent(Intent.ACTION_VIEW, uri)"))
        val intentBranch = main.substring(main.indexOf("val fbHost = runCatching"), main.indexOf("val fbHost = runCatching") + 900)
        assertTrue(intentBranch.contains("refuseExternal(\"https\", dataUri?.host"))
        assertTrue(intentBranch.contains("refuseExternal(\"https\", fbHost"))
        val defaultBranch = main.substring(main.indexOf("if (com.beamio.app.net.LegacyBeamioHostGuard.refuseExternal(scheme, uri.host, uri.path)) return"), main.indexOf("if (com.beamio.app.net.LegacyBeamioHostGuard.refuseExternal(scheme, uri.host, uri.path)) return") + 300)
        assertTrue(defaultBranch.isNotEmpty())
    }

    // ---- r9 pure decisions (real runs, not text): N6 bridge, N8 intent data and fallback, P5/P6/P7 allowed ----

    /** N6 (openURL bridge): an https legacy URL is refused; N8: intent data or browser fallback that is legacy is refused. */
    @Test
    fun intentDecisionRefusesLegacyDataAndFallback() {
        assertTrue(LegacyBeamioHostGuard.isIntentRefused("https", "beamio.app", null))
        assertTrue(LegacyBeamioHostGuard.isIntentRefused("https", "www.beamio.app", null))
        assertTrue(LegacyBeamioHostGuard.isIntentRefused("https", "beamio.ca", "https://beamio.app/usdc-topup"))
        assertTrue(LegacyBeamioHostGuard.isIntentRefused("https", "basescan.org", "https://www.beamio.app/x"))
        assertTrue(LegacyBeamioHostGuard.isIntentRefused("https", "beamio.ca", "https://cashtrees.beamio.app/x"))
    }

    /** P5 third-party https, P6 market:// and Play, P7 beamio://: allowed (no refusal). */
    @Test
    fun intentDecisionAllowsThirdPartyPlayAndDeepLinks() {
        assertFalse(LegacyBeamioHostGuard.isIntentRefused("https", "basescan.org", null))
        assertFalse(LegacyBeamioHostGuard.isIntentRefused("https", "basescan.org", "https://basescan.org/tx/0x1"))
        assertFalse(LegacyBeamioHostGuard.isIntentRefused("market", "details", null))
        assertFalse(LegacyBeamioHostGuard.isIntentRefused("https", "play.google.com", "https://play.google.com/store/apps/details?id=x"))
        assertFalse(LegacyBeamioHostGuard.isIntentRefused("beamio", "open", null))
        assertFalse(LegacyBeamioHostGuard.isIntentRefused("https", "beamio.ca", "https://beamio.ca/app/"))
        assertFalse(LegacyBeamioHostGuard.isIntentRefused("https", "beamio.ca", "not a url :::"))
        assertFalse(LegacyBeamioHostGuard.isIntentRefused(null, null, null))
    }

    /** refuseIntent logs one blocked line for the refused part and returns true. */
    @Test
    fun refuseIntentLogsTheRefusedPartOnly() {
        logs.clear()
        assertTrue(LegacyBeamioHostGuard.refuseIntent("https", "beamio.ca", "/x", "https://beamio.app/usdc-topup/SECRET"))
        assertEquals(listOf("blocked legacy host=beamio.app path=/usdc-topup"), logs)
        assertFalse(LegacyBeamioHostGuard.refuseIntent("market", "details", null, null))
    }

    /** P4: a local beamio.app/app mapping is consulted before the legacy refusal in the main client (text check; mapping is Android-only). */
    @Test
    fun p4LocalMappingPrecedesTheLegacyRefusalTextCheck() {
        val main = java.io.File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        val block = main.indexOf("if (host.mapBeamioAppUrlToLocal(u) == null && com.beamio.app.net.LegacyBeamioHostGuard.isLegacyHost(u.host))")
        assertTrue(block > 0)
        assertTrue(main.indexOf("host.mapBeamioAppUrlToLocal(u)?.let { local ->", block) > block)
    }
}
