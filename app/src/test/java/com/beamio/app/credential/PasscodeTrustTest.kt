package com.beamio.app.credential

import com.beamio.app.ChatOriginGate
import org.junit.Assert.assertEquals
import org.junit.Test

/** Protocol v1 §一第 4-5 条: passcode capability is wallet.passcode.v1 from the SDK; events drop on remote pages. */
class PasscodeTrustTest {
    private val hash = "a".repeat(64)

    private fun inputs(sdk: Set<String>, manifest: Set<String> = emptySet(), origin: String? = ChatOriginGate.TRUSTED, verified: String? = hash) =
        WalletCredentialGate.TrustInputs(
            manifestCapabilities = manifest,
            manifestZipSha256 = hash,
            buildZipSha256 = hash,
            sdkCapabilities = sdk,
            verifiedActiveZipSha256 = verified,
            channel = WalletCredentialGate.Channel.WEB_MESSAGE,
            isMainFrame = true,
            sourceOrigin = origin,
        )

    @Test fun passcodeNeedsSdkPasscodeCapability() {
        assertEquals(WalletCredentialGate.Verdict.SDK_NOT_DECLARED,
            WalletCredentialGate.evaluate(inputs(sdk = setOf("wallet.credential.v1")), passcode = true))
    }

    @Test fun passcodeTrustedWithSdkCapabilityAndVerifiedBundle() {
        assertEquals(WalletCredentialGate.Verdict.TRUSTED,
            WalletCredentialGate.evaluate(inputs(sdk = setOf(WalletCredentialGate.PASSCODE_CAPABILITY)), passcode = true))
    }

    @Test fun manifestBitsAreNotUsedForPasscode() {
        assertEquals(WalletCredentialGate.Verdict.TRUSTED,
            WalletCredentialGate.evaluate(inputs(sdk = setOf(WalletCredentialGate.PASSCODE_CAPABILITY), manifest = emptySet()), passcode = true))
    }

    @Test fun passcodeStillRefusesWrongOrigin() {
        assertEquals(WalletCredentialGate.Verdict.ORIGIN_REFUSED,
            WalletCredentialGate.evaluate(inputs(sdk = setOf(WalletCredentialGate.PASSCODE_CAPABILITY), origin = "https://example.com"), passcode = true))
    }

    @Test fun passcodeWithoutVerifiedBundleIsRefused() {
        assertEquals(WalletCredentialGate.Verdict.BUNDLE_NOT_VERIFIED,
            WalletCredentialGate.evaluate(inputs(sdk = setOf(WalletCredentialGate.PASSCODE_CAPABILITY), verified = null), passcode = true))
    }

    @Test fun remotePageNavigationDropsProxy() {
        val exit = TrustedEventExit<String>()
        exit.onTrusted("main")
        exit.onMainFrameNavigation(trustedPage = false)
        assertEquals("no_event_target", exit.deliver("{}") { _, _ -> })
    }

    @Test fun trustedPageNavigationKeepsProxy() {
        val exit = TrustedEventExit<String>()
        exit.onTrusted("main")
        exit.onMainFrameNavigation(trustedPage = true)
        assertEquals(true, exit.hasTarget())
    }
}
