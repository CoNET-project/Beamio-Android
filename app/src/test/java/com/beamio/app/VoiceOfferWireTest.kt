package com.beamio.app

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Wire checks on the PWA rev2 voice_call_offer_v1 vector (signal fields and signText) and a
 * synthetic envelope. PGP decrypt of the armored offer is NOT covered here (device-only).
 */
class VoiceOfferWireTest {
    private val signText = "CoNET voice_call_offer_v3\ncallId:vt-call-0001\nsessionId:vt-session-0001\nto:0x000000000000000000000000000000000000dead\ncreatedAt:1795217195851\nexpiresAt:1795218095851\ntimestamp:1795217195851\ncodec:audio/pcm;rate=16000\ncallerPgp:VEVTVC1GSVhUVVJFLVBHUC1BUk1PUi1OT1QtQS1SRUFMLUtFWQ==\ncallerRoute:VEVTVC1GSVhUVVJFLVJPVVRFLU5PVC1BLVJFQUwtS0VZ"
    private val signer = "0x660fc041ffe39750ef53149debb5cf2df32c5b0f"

    private fun signal(): JSONObject = JSONObject()
        .put("type", "voice_call_offer_v1")
        .put("proto", 3)
        .put("callId", "vt-call-0001")
        .put("sessionId", "vt-session-0001")
        .put("to", "0x000000000000000000000000000000000000dEaD")
        .put("createdAt", "1795217195851")
        .put("expiresAt", "1795218095851")
        .put("timestamp", "1795217195851")
        .put("codec", "audio/pcm;rate=16000")
        .put("callerPgp", "VEVTVC1GSVhUVVJFLVBHUC1BUk1PUi1OT1QtQS1SRUFMLUtFWQ==")
        .put("callerRoute", "VEVTVC1GSVhUVVJFLVJPVVRFLU5PVC1BLVJFQUwtS0VZ")
        .put("from", "0x660fC041FFE39750eF53149debB5cF2dF32C5B0f")
        .put("callerSignature", "0xf814f04f44d3342c013041364877442c7f0de864e092ca16c72dd30a4531422328b05dc310274b8e05c23e247c3437d912db10eb2af05a11c1b2899375a51d8c1c")

    @Test fun canonicalTextMatchesPwaSignText() {
        assertEquals(signText, VoiceOfferWire.canonicalText(signal()))
    }

    @Test fun innerSignerIsFromOnPositive() {
        assertEquals(signer, VoiceOfferWire.innerSigner(signal())?.lowercase())
    }

    @Test fun changedCallIdDoesNotRecoverFrom() {
        val s = signal().put("callId", "vt-call-0002")
        assertNotEquals(signer, VoiceOfferWire.innerSigner(s)?.lowercase())
    }

    @Test fun claimedFromReplacedStillRecoversSignerNotClaim() {
        val s = signal().put("from", "0x1111111111111111111111111111111111111111")
        val r = VoiceOfferWire.innerSigner(s)?.lowercase()
        assertEquals(signer, r)
        assertNotEquals("0x1111111111111111111111111111111111111111", r)
    }

    @Test fun base64DecodeRoundTrip() {
        val raw = "hello voice offer"
        val enc = java.util.Base64.getEncoder().encodeToString(raw.toByteArray(Charsets.UTF_8))
        assertEquals(raw, String(VoiceOfferWire.base64Decode(enc)!!, Charsets.UTF_8))
        assertNull(VoiceOfferWire.base64Decode("not*base64"))
    }

    @Test fun envelopeSignedByKeyRecoversItsAddress() {
        // Throwaway synthetic key for this test only (not an account, not registered).
        val key = "0x" + "11".repeat(32)
        val text = signal().toString()
        val sig = BeamioNativeEthSigner.signEip191(key, text)!!
        val envelope = JSONObject()
            .put("timestamp", 1795217195851L)
            .put("text", text)
            .put("from", BeamioNativeEthSigner.address(key)!!)
            .put("signMessage", sig)
        val wire = java.util.Base64.getEncoder().encodeToString(envelope.toString().toByteArray(Charsets.UTF_8))
        val parsed = VoiceOfferWire.parseEnvelope(wire)!!
        assertEquals(parsed.from.lowercase(), VoiceOfferWire.envelopeSigner(parsed)?.lowercase())
    }

    @Test fun malformedEnvelopeIsNull() {
        assertNull(VoiceOfferWire.parseEnvelope("bm90IGpzb24="))
    }

    @Test fun verifiedFieldsOnPositive() {
        val v = VoiceOfferWire.verifiedFields(signal())
        assertEquals(signer, v?.from)
        assertEquals(signer, v?.recoveredR)
        assertEquals("vt-call-0001", v?.callId)
        assertEquals("vt-session-0001", v?.sessionId)
        assertEquals(3, v?.proto)
    }

    @Test fun verifiedFieldsRefusedOnChangedCallId() {
        assertEquals(null, VoiceOfferWire.verifiedFields(signal().put("callId", "vt-call-0002")))
    }

    @Test fun verifiedFieldsRefusedWhenFromReplaced() {
        assertEquals(null, VoiceOfferWire.verifiedFields(signal().put("from", "0x1111111111111111111111111111111111111111")))
    }

    @Test fun verifiedFieldsRefusedForOtherType() {
        assertEquals(null, VoiceOfferWire.verifiedFields(signal().put("type", "voice_offer")))
    }

    @Test fun outerEnvelopeOkForSignerAndMatchingFrom() {
        val key = "0x" + "22".repeat(32) // throwaway synthetic key for this test only
        val addr = BeamioNativeEthSigner.address(key)!!.lowercase()
        val text = "envelope text sample"
        val sig = BeamioNativeEthSigner.signEip191(key, text)!!
        assertTrue(VoiceOfferWire.outerEnvelopeOk(text, sig, addr, addr))
        assertFalse(VoiceOfferWire.outerEnvelopeOk(text, sig, "0x1111111111111111111111111111111111111111", addr))
        assertFalse(VoiceOfferWire.outerEnvelopeOk(text, sig, addr, "0x1111111111111111111111111111111111111111"))
        assertFalse(VoiceOfferWire.outerEnvelopeOk("other text", sig, addr, addr))
        assertFalse(VoiceOfferWire.outerEnvelopeOk("", sig, addr, addr))
        assertFalse(VoiceOfferWire.outerEnvelopeOk(text, "0x1234", addr, addr))
    }
}
