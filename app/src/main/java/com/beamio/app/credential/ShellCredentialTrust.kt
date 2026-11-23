package com.beamio.app.credential

import com.beamio.app.BuildConfig
import com.beamio.app.embedded.EmbeddedPwaBundleStore
import network.conet.chat.BeamioConetChatProtocol

/**
 * Runtime inputs of [WalletCredentialGate.evaluate] (spec r3np §25.52Y.38 item 2; r3nq §25.52Y.41 item 2):
 *  (a) capability bits: BuildConfig.PWA_CAPABILITIES, written by build.gradle.kts only from the manifest the PWA version gate
 *      checked against the embedded zip (never the page's hello, never a shell constant);
 *  (b)(c)(g) bundle: active/ must hold exactly the bundled zip whose every byte hashed to pwa-embed.lock at this process's
 *      bootstrap ([EmbeddedPwaBundleStore.currentVerifiedActiveZipSha256]);
 *  (d) channel, frame and origin: from the caller (only the WebMessage listener passes WEB_MESSAGE);
 *  (e) native declaration: the running Chat SDK's own capability list.
 */
object ShellCredentialTrust {
    private val manifestCapabilities: Set<String> = WalletCredentialGate.parseCapabilities(BuildConfig.PWA_CAPABILITIES)

    private fun sdkCapabilities(): Set<String> =
        runCatching { BeamioConetChatProtocol.CAPABILITIES.toSet() }.getOrDefault(emptySet())

    fun inputs(channel: WalletCredentialGate.Channel, isMainFrame: Boolean, sourceOrigin: String?): WalletCredentialGate.TrustInputs =
        WalletCredentialGate.TrustInputs(
            manifestCapabilities = manifestCapabilities,
            manifestZipSha256 = BuildConfig.PWA_CAPABILITIES_ZIP_SHA256,
            buildZipSha256 = BuildConfig.PWA_ZIP_SHA256,
            sdkCapabilities = sdkCapabilities(),
            // Only computed when the cheaper conditions hold; hashing active/ is the expensive step.
            verifiedActiveZipSha256 = null,
            channel = channel,
            isMainFrame = isMainFrame,
            sourceOrigin = sourceOrigin,
        )

    /** Evaluate in order; the bundle is hashed only when every earlier condition holds. Call off the main thread. */
    fun verdict(
        channel: WalletCredentialGate.Channel,
        isMainFrame: Boolean,
        sourceOrigin: String?,
        requireCapability: Boolean = true,
        passcode: Boolean = false,
    ): WalletCredentialGate.Verdict {
        val base = inputs(channel, isMainFrame, sourceOrigin)
        val early = WalletCredentialGate.evaluate(base, requireCapability, passcode)
        if (early != WalletCredentialGate.Verdict.BUNDLE_NOT_VERIFIED) return early
        return WalletCredentialGate.evaluate(base.copy(verifiedActiveZipSha256 = EmbeddedPwaBundleStore.currentVerifiedActiveZipSha256()), requireCapability, passcode)
    }
}
