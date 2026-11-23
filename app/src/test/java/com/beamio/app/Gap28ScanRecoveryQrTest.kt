package com.beamio.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * GAP-28 (interim, spec r3m 25.31.1): scanRecoveryQr no longer opens the recovery scanner and no recovery code reaches
 * the WebView; the bridge answers not_supported. Source check on MainActivity.
 */
class Gap28ScanRecoveryQrTest {
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

    /** (spec r3fr §25.52DR.4): the entry is removed from the shell; BeamioShell answers unknown_command. */
    @Test
    fun scanRecoveryQrIsRemoved() {
        assertFalse(Regex("fun scanRecoveryQr\\(").containsMatchIn(src))
        assertFalse("scanRecoveryQr" in BeamioShellChannel.ACTIONS)
        val d = BeamioShellChannel.decide("{\"action\":\"scanRecoveryQr\",\"reqId\":1}", "https://appassets.androidplatform.net", true)
        assertTrue((d as BeamioShellChannel.Decision.Answer).ack.getString("error") == "unknown_command")
    }

    /** Positive regression: the general QR scanner (scanQr) still opens the scanner. */
    @Test
    fun scanQrStillOpensTheScanner() {
        val b = body("scanQr")
        assertTrue(b.contains("launchGeneralQrScanner") && b.contains("FILTER_ANY"))
    }

    /** No code path launches the scanner with the recovery filter any more. */
    @Test
    fun nothingLaunchesTheRecoveryFilter() {
        assertFalse(Regex("filter\\s*=\\s*GeneralQRScannerActivity\\.FILTER_RECOVERY").containsMatchIn(src))
    }
}
