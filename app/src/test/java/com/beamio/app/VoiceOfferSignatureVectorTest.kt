package com.beamio.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * Callee signature recovery on the PWA-generated voice_call_offer_v1 vector
 * (VECTOR-voice-call-offer-v1-pwa-2026-11-20.json, sha256 5abe826f…). Covers the
 * signature step only (recovery and R/from comparison), not the decrypt path.
 */
class VoiceOfferSignatureVectorTest {
    private val signText = "CoNET voice_call_offer_v3\ncallId:vt-call-0001\nsessionId:vt-session-0001\nto:0x000000000000000000000000000000000000dead\ncreatedAt:1795217195851\nexpiresAt:1795218095851\ntimestamp:1795217195851\ncodec:audio/pcm;rate=16000\ncallerPgp:VEVTVC1GSVhUVVJFLVBHUC1BUk1PUi1OT1QtQS1SRUFMLUtFWQ==\ncallerRoute:VEVTVC1GSVhUVVJFLVJPVVRFLU5PVC1BLVJFQUwtS0VZ"
    private val signature = "0xf814f04f44d3342c013041364877442c7f0de864e092ca16c72dd30a4531422328b05dc310274b8e05c23e247c3437d912db10eb2af05a11c1b2899375a51d8c1c"
    private val signer = "0x660fc041ffe39750ef53149debb5cf2df32c5b0f"
    private val from = "0x660fC041FFE39750eF53149debB5cF2dF32C5B0f"

    @Test fun positiveRecoversSignerAndFromMatches() {
        val r = BeamioNativeEthSigner.recoverAddress(signText, signature)?.lowercase()
        assertEquals(signer, r)
        assertEquals(signer, from.lowercase())
    }

    @Test fun oneByteChangedCallIdDoesNotRecoverSigner() {
        val changed = signText.replace("callId:vt-call-0001", "callId:vt-call-0002")
        val r = BeamioNativeEthSigner.recoverAddress(changed, signature)?.lowercase()
        assertNotEquals(signer, r)
        assertEquals("0xac0d24ee362a6a85ba96fb7b32f8d00cead94274", r)
    }

    @Test fun fromNotSignerIsRejectedByComparison() {
        // The claimed from is replaced; the signature still recovers the signer.
        val r = BeamioNativeEthSigner.recoverAddress(signText, signature)?.lowercase()
        val claimedFrom = "0x1111111111111111111111111111111111111111"
        assertEquals(signer, r)
        assertNotEquals(r, claimedFrom.lowercase())
    }

    @Test fun malformedSignatureIsNull() {
        assertEquals(null, BeamioNativeEthSigner.recoverAddress(signText, "0x1234"))
    }
}
