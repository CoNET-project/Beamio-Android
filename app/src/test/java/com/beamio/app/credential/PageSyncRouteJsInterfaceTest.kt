package com.beamio.app.credential

import com.beamio.app.ChatOriginGate
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Narrowing of the JavascriptInterface channel (CashTreesAndroid.chatModuleCommand, reachable from every frame):
 * page-sync and passcode commands are refused there before the SDK; the window channel (BeamioShellRecord) keeps its
 * origin and main-frame checks and stays usable for the same commands.
 */
class PageSyncRouteJsInterfaceTest {
    private val pageSyncAndPasscode = listOf(
        "pwaWalletSync", "nativeMnemonicPreread", "pwaEmptySignal",
        "passcodeProvision", "passcodeUnlock", "passcodeChange", "passcodeDisable", "nativeRepairProvide", "passcodeStatus",
    )

    private fun body(type: String): String = JSONObject().put("type", type).put("reqId", 9).toString()

    @Test fun pageSyncAndPasscodeCommandsAreRefusedOnTheJsInterfaceFromAnyFrame() {
        for (type in pageSyncAndPasscode) {
            val refusal = PageSyncRoute.refusalOnJsInterface(body(type))
            assertNotEquals("$type must be refused on chatModuleCommand", null, refusal)
            assertEquals("untrusted_source", refusal!!.optString("error"))
            assertEquals(9, refusal.optInt("reqId"))
            assertEquals(false, refusal.optBoolean("ok"))
        }
    }

    @Test fun nestedPageSyncCommandIsAlsoRefusedOnTheJsInterface() {
        val nested = JSONObject().put("command", JSONObject().put("type", "nativeMnemonicPreread").put("reqId", 3)).toString()
        assertNotEquals(null, PageSyncRoute.refusalOnJsInterface(nested))
    }

    @Test fun ordinaryChatCommandsAreNotAffectedOnTheJsInterface() {
        assertNull(PageSyncRoute.refusalOnJsInterface(body("hello")))
        assertNull(PageSyncRoute.refusalOnJsInterface(body("sendMessage")))
        assertNull(PageSyncRoute.refusalOnJsInterface("not json"))
    }

    @Test fun childFrameOnTheWindowChannelIsNotTrusted() {
        val verdict = ShellCredentialTrust.verdict(
            WalletCredentialGate.Channel.WEB_MESSAGE, isMainFrame = false, sourceOrigin = ChatOriginGate.TRUSTED,
            requireCapability = false, passcode = false,
        )
        assertNotEquals(WalletCredentialGate.Verdict.TRUSTED, verdict)
    }

    @Test fun wrongOriginOnTheWindowChannelIsNotTrusted() {
        val verdict = ShellCredentialTrust.verdict(
            WalletCredentialGate.Channel.WEB_MESSAGE, isMainFrame = true, sourceOrigin = "https://evil.example",
            requireCapability = false, passcode = false,
        )
        assertNotEquals(WalletCredentialGate.Verdict.TRUSTED, verdict)
    }

    @Test fun mainFrameTrustedOriginOnTheWindowChannelPassesTheFrameAndOriginChecks() {
        // On the JVM there is no embedded bundle, so the verdict stops at BUNDLE_NOT_VERIFIED. What matters here is that the
        // main frame and the trusted origin are not refused at the channel or frame step (those would be CHANNEL_REFUSED / FRAME_REFUSED).
        val verdict = ShellCredentialTrust.verdict(
            WalletCredentialGate.Channel.WEB_MESSAGE, isMainFrame = true, sourceOrigin = ChatOriginGate.TRUSTED,
            requireCapability = false, passcode = false,
        )
        assertEquals(WalletCredentialGate.Verdict.BUNDLE_NOT_VERIFIED, verdict)
    }

    @Test fun windowChannelRouteStillRecognisesThePageSyncCommands() {
        // The route itself is unchanged: the window channel still reaches the trust gate for these commands.
        for (type in listOf("pwaWalletSync", "nativeMnemonicPreread", "passcodeStatus")) {
            assertNotEquals(null, PageSyncRoute.normalize(body(type)))
        }
    }
}
