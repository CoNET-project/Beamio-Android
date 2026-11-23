package com.beamio.app

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Routing order (items 1, 2): a passcode command takes the page-sync route before the GATED check in both entry points, and the
 * page-sync path sets trustedOrigin only from the shell's verdict (same as pwaWalletSync, errata E1).
 */
class PasscodeRoutingOrderTest {
    private val main = File("src/main/java/com/beamio/app/MainActivity.kt").readText()

    @Test fun chatModuleCommandRoutesPageSyncFirst() {
        val body = main.substringAfter("open fun chatModuleCommand(json: String) {").substringBefore("// Origin first")
        assertTrue(body.indexOf("PageSyncRoute.normalize(json)") >= 0)
    }

    @Test fun handleChatCommandRoutesPageSyncBeforeGatedCommands() {
        val body = main.substringAfter("private fun handleChatCommand(json: String, channel: WalletCredentialGate.Channel, deliver: (JSONObject) -> Unit) {")
            .substringBefore("private fun handlePageSyncCommand")
        val pageSync = body.indexOf("PageSyncRoute.normalize(json)")
        val gated = body.indexOf("WalletCredentialGate.GATED_COMMANDS")
        assertTrue(pageSync in 0 until gated)
    }

    @Test fun pageSyncPathSetsTrustedOriginOnlyFromVerdict() {
        val body = main.substringAfter("private fun handlePageSyncCommand(").substringBefore("private fun handleWalletCredential")
        assertTrue(body.contains("body.remove(\"trustedOrigin\")"))
        assertTrue(body.indexOf("body.put(\"trustedOrigin\", true)") > body.indexOf("PageSyncRoute.refusalBeforeSdk"))
    }
}
