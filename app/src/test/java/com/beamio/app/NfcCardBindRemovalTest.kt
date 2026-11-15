package com.beamio.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * GAP-17 (owner decision 2026-11-13): consumer binding or claiming of a physical NFC card is removed, with no
 * replacement. Source checks on MainActivity (the bridge and the NFC code live there). Runtime checks are on the
 * emulator (see the receipt).
 */
class NfcCardBindRemovalTest {
    private val src = File("src/main/java/com/beamio/app/MainActivity.kt").readText()

    private fun body(name: String): String {
        val start = Regex("fun $name\\([^)]*\\)[^{]*\\{").find(src) ?: error("no fun $name")
        var depth = 0
        var i = src.indexOf('{', start.range.first)
        val from = i
        while (true) {
            when (src[i]) {
                '{' -> depth++
                '}' -> if (--depth == 0) return src.substring(from, i + 1)
            }
            i++
        }
    }

    @Test
    fun noCardReaderSessionOrTagReadIsLeft() {
        for (gone in listOf(
            "enableReaderMode", "disableReaderMode", "armNfcPhysicalCardRead", "onNfcTagForBind",
            "readNdefUriAndSun", "readConnectedNdef", "parseSunParamsFromNdefUrl", "SunParams",
            "nfcBindKeepAlive", "nfcBindSessionActive", "android.nfc.tech.Ndef", "disarmNfcReader",
        )) {
            assertFalse("still present: $gone", src.contains(gone))
        }
    }

    /**
     * The binding entries are deleted, not stubbed: old PWAs (0.52.930, 0.52.932) check
     * `typeof CashTreesAndroid.startPhysicalCardBind === 'function'` and, when it is missing, go to /myWallet without
     * opening the card sheet. A stub would make them enter the binding UI first and then show an error.
     */
    @Test
    fun bindingEntriesAreGone() {
        for (name in listOf("startPhysicalCardBind", "cancelPhysicalCardBind", "dispatchNfcJsonToWeb", "cashtreesnfc", "__cashTreesNfcBindResult")) {
            assertFalse("still present: $name", src.contains(name))
        }
    }

    @Test
    fun nfcStatusStaysAndOnlyReadsTheAdapterState() {
        assertTrue(Regex("@JavascriptInterface\\s+fun getNfcStatus\\(\\)").containsMatchIn(src))
        val b = body("queryNfcStatus")
        assertTrue(b.contains("hasNfcPermission()") && b.contains("isEnabled"))
        assertFalse(b.contains("Wallet") || b.contains("enableReaderMode") || b.contains("PhysicalCard"))
    }

    @Test
    fun nfcTagIntentsAreConsumedWithoutABindPath() {
        val b = body("onNewIntent")
        assertTrue(b.contains("ACTION_NDEF_DISCOVERED"))
        assertFalse(b.contains("Tag::class.java") || b.contains("EXTRA_TAG"))
    }

    /** Positive regression: the other shell entries are untouched (names from the 168 bridge list). */
    @Test
    fun otherBridgeEntriesRemain() {
        val expected = listOf(
            "getNfcStatus", "scanQr", "openURL", "openInAppBrowser", "saveFile", "prepareSystemCall",
            "cancelPreparedSystemCall", "startSystemCall", "reportIncomingSystemCall", "endSystemCall",
            "requestCameraCapture", "queryInstalledApps", "listInstalledWalletApps", "publishAppState",
            "clearOfflineChatAlerts", "notifyBackgroundChat", "bindPushIdentity",
            "setNativeVoiceRelayNodes", "setNativeSiNodeRoster", "postPgpCiphertext", "chatModuleCommand",
            "chatModuleSignResponse", "applyEmbeddedPwaUpdate",
        )
        val entries = Regex("@JavascriptInterface\\s+(?:open |override )?fun (\\w+)\\(").findAll(src).map { it.groupValues[1] }.toSet()
        for (e in expected) assertTrue("missing $e", e in entries)
        assertFalse("startPhysicalCardBind" in entries || "cancelPhysicalCardBind" in entries)
        // PM R679 / R680 (2026-11-14): removed entries
        assertFalse("setNativeChatPgpSecrets" in entries || "requestPendingSystemCallAction" in entries)
        assertFalse("scanRecoveryQr" in entries) // PM R820
    }

    /** Positive regression: merchant card / coupon deep links are not part of GAP-17 and stay as they were. */
    @Test
    fun merchantAndCouponDeepLinksStay() {
        val dl = File("src/main/java/com/beamio/app/BeamioDeepLink.kt").readText()
        assertTrue(dl.contains("fun carriesMerchantOrCouponPayload(") && dl.contains("beamiocard") && dl.contains("couponId"))
        assertTrue(src.contains("captureBeamioDeepLink("))
    }
}
