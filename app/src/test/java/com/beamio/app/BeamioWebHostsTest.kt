package com.beamio.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** PM R1626/R1637: the shell uses beamio.ca, exact host names only, strict TLS, no fallback. */
class BeamioWebHostsTest {
    @Test
    fun onlyTheExactNewHostsAreWebHosts() {
        for (h in listOf("beamio.ca", "www.beamio.ca", "BEAMIO.CA")) assertTrue(h, BeamioWebHosts.isWebHost(h))
        for (h in listOf(null, "", "pos.beamio.ca", "api.beamio.ca", "beamio.ca.evil.com", "evilbeamio.ca", "cashtrees.beamio.app")) {
            assertFalse("$h", BeamioWebHosts.isWebHost(h))
        }
        assertEquals("https://beamio.ca", BeamioWebHosts.CANONICAL_ORIGIN)
    }

    private fun mainCode(): List<String> =
        File("src/main/java/com/beamio/app").walkTopDown().filter { it.isFile && it.extension == "kt" && it.name != "BeamioWebHosts.kt" && it.name != "BeamioNfcSunBlock.kt" }
            .flatMap { f -> f.readLines().mapIndexed { i, l -> "${f.name}:${i + 1}: $l" } }
            .filterNot { it.substringAfter(": ").trimStart().let { s -> s.startsWith("*") || s.startsWith("//") || s.startsWith("/*") } }
            .toList()

    /** Source guard: no shell network URL on beamio.app, host checks go through BeamioWebHosts, no wildcard match. */
    @Test
    fun shellNetworkUrlsAreOnBeamioCaOnly() {
        val badUrl = mainCode().filter { it.contains("https://beamio.app/") || it.contains("https://www.beamio.app/") }
        assertTrue("shell URLs on the old domain: $badUrl", badUrl.isEmpty())
        val badCheck = mainCode().filter { Regex("""== "(www\.)?beamio\.(app|ca)"|!= "(www\.)?beamio\.(app|ca)"|endsWith\("\.beamio""").containsMatchIn(it) }
        assertTrue("host checks outside BeamioWebHosts or wildcard: $badCheck", badCheck.isEmpty())
        for (f in listOf("BeamioTelecomService.kt", "BeamioVoiceOfferIdentity.kt")) {
            val s = File("src/main/java/com/beamio/app/$f").readText()
            assertTrue("$f search-users on beamio.ca", s.contains("\${BeamioWebHosts.CANONICAL_ORIGIN}/api/search-users"))
        }
        assertTrue(File("src/main/java/com/beamio/app/embedded/EmbeddedPwaConstants.kt").readText().contains("REMOTE_FALLBACK_URL = \"https://beamio.ca/app/\""))
        for (f in listOf("src/ota/java/com/beamio/app/embedded/EmbeddedPwaOtaConstants.kt", "build.gradle.kts")) {
            val s = File(f).readText()
            assertTrue("$f uses beamio.ca", s.contains("https://beamio.ca/app/update.json"))
            assertFalse("$f has no beamio.app OTA URL", s.contains("https://beamio.app/app/update.json"))
        }
        assertTrue(File("src/main/res/values/strings.xml").readText().contains("https://beamio.ca&#34;"))
    }

    /** Local data does not depend on the website domain: the page origin stays the asset loader. */
    @Test
    fun pageOriginIsUnchanged() {
        assertEquals("https://appassets.androidplatform.net", com.beamio.app.embedded.EmbeddedPwaConstants.ASSET_LOADER_ORIGIN)
    }

    /** PM R2030: the store gate looks for the live update URL (beamio.ca), not only the old domain's. */
    @Test
    fun storeGateCoversTheLiveUpdateUrl() {
        val gate = File("../scripts/verify-android-store-no-ota.sh").readText()
        val strings = gate.substringAfter("STRINGS=(").substringBefore(")")
        assertTrue(strings.contains("\"beamio.ca/app/update.json\""))
        assertTrue(strings.contains("\"beamio.app/app/update.json\""))
    }

    /** PM R2030: no README or main-code link points at the old site as the live app address. */
    @Test
    fun readmeNamesTheLiveDomain() {
        val readme = File("../README.md").readText()
        assertFalse(readme.contains("https://beamio.app/app"))
        assertTrue(readme.contains("https://beamio.ca/app"))
    }

    /** PM R2040: the SDK's old-domain default apiBaseUrl is never used: the shell fills or moves it in a page init. */
    @Test
    fun chatApiBaseNeverFallsBackToTheOldDomain() {
        assertEquals("https://beamio.ca/api", BeamioWebHosts.chatApiBaseFor(null))
        assertEquals("https://beamio.ca/api", BeamioWebHosts.chatApiBaseFor(""))
        assertEquals("https://beamio.ca/api", BeamioWebHosts.chatApiBaseFor("  "))
        assertEquals("https://beamio.ca/api", BeamioWebHosts.chatApiBaseFor("https://beamio.app/api"))
        assertEquals("https://www.beamio.ca/api/v2", BeamioWebHosts.chatApiBaseFor("https://WWW.beamio.app/api/v2"))
        assertEquals("https://beamio.ca/api", BeamioWebHosts.chatApiBaseFor("http://beamio.app"))
        // the live value and anything else stay as given
        for (keep in listOf("https://beamio.ca/api", "https://www.beamio.ca/api", "https://pos.beamio.app/api", "https://api.example.test/x")) {
            assertEquals(keep, null, BeamioWebHosts.chatApiBaseFor(keep))
        }
        val main = mainCode().joinToString("\n")
        assertTrue(main.contains("BeamioWebHosts.chatApiBaseFor(if (body.has(\"apiBaseUrl\")) body.optString(\"apiBaseUrl\") else null)"))
        val h = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        assertTrue(h.indexOf("chatApiBaseFor(") < h.indexOf("BeamioConetChatModule.handleCommand(applicationContext, body, sdkDeliver(deliver))"))
    }

    /** PM R2120: the legacy chatModuleSignResponse never accepts a signing reply, even in a legacy QA probe. */
    @Test
    fun legacySignResponseIsAlwaysRefused() {
        val main = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        val legacy = main.substringAfter("@JavascriptInterface override fun chatModuleSignResponse(json: String) {").substringBefore("\n        }")
        assertTrue(legacy.contains("legacy chatModuleSignResponse refused"))
        assertFalse(legacy.contains("super.chatModuleSignResponse"))
        assertFalse(legacy.contains("fulfillSign"))
        // BeamioChat still delivers signing replies (main frame + appassets, decided in BeamioChatChannel)
        assertTrue(main.contains("onSignResponse = { json -> deliverChatSignResponse(json) }"))
        assertFalse(main.contains("onSignResponse = { json -> jsBridge.chatModuleSignResponse(json) }"))
        // README states that the QA lock blocks store packaging until a non-QA SDK and lock replace it.
        assertTrue(File("../README.md").readText().contains("chat_sdk_qa=false"))
    }
}
