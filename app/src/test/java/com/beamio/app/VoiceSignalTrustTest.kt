package com.beamio.app

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class VoiceSignalTrustTest {
    private val key = "0x" + "33".repeat(32) // throwaway synthetic key for this test only
    private val addr = BeamioNativeEthSigner.address(key)!!.lowercase()

    private fun inner(from: String?): String {
        val o = JSONObject().put("type", "voice_call_accept_v1").put("proto", 3)
            .put("callId", "call-offer-0002").put("sessionId", "sess-0002")
        if (from != null) o.put("from", from)
        return o.toString()
    }

    private fun line(text: String, from: String, signer: String = key, payloadFromIn: String? = null): String {
        val sig = BeamioNativeEthSigner.signEip191(signer, text)!!
        val env = JSONObject().put("timestamp", 1L).put("text", text).put("from", from).put("signMessage", sig)
        return java.util.Base64.getEncoder().encodeToString(env.toString().toByteArray(Charsets.UTF_8))
    }

    @Test fun verifiedEnvelopeDrivesTheInnerSignal() {
        val t = inner(addr)
        val got = VoiceSignalTrust.verifiedInner(line(t, addr), addr)
        assertEquals("voice_call_accept_v1", got?.getString("type"))
    }

    @Test fun bareSignalIsDropped() {
        assertNull(VoiceSignalTrust.verifiedInner(inner(addr), addr))
    }

    @Test fun missingInnerFromIsDropped() {
        assertNull(VoiceSignalTrust.verifiedInner(line(inner(null), addr), addr))
    }

    @Test fun signerNotEnvelopeFromIsDropped() {
        val other = "0x" + "44".repeat(32)
        assertNull(VoiceSignalTrust.verifiedInner(line(inner(addr), addr, signer = other), addr))
    }

    @Test fun payloadSenderMismatchIsDropped() {
        assertNull(VoiceSignalTrust.verifiedInner(line(inner(addr), addr), "0x1111111111111111111111111111111111111111"))
    }

    @Test fun innerFromMismatchIsDropped() {
        assertNull(VoiceSignalTrust.verifiedInner(line(inner("0x2222222222222222222222222222222222222222"), addr), addr))
    }
}
