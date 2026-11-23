package com.beamio.app

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Structure and signature rules of offer v4 (v108 §108.4–108.7). Own vectors; PWA interop vectors come separately. */
class VoiceOfferV4Test {
    private val key1 = "0x" + "0".repeat(63) + "1"
    private val caller = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf" // key 1
    private val callee = "0x1111111111111111111111111111111111111111"
    private val callId = "call-0001-abcdef"
    private val sessionId = "0123456789abcdef0123456789abcdef"
    private val created = 1_000_000L
    private val expires = 1_060_000L
    private val now = 1_010_000L
    private val recover: (String, String) -> String? = { t, s -> BeamioNativeEthSigner.recoverAddress(t, s) }
    private val noArmor: (String) -> String? = { null }

    private fun channel(role: String): JSONObject {
        val temp = "0x" + (if (role == "cv") "a" else "b").repeat(40)
        val auth = JSONObject().put("from", caller).put("validUntil", expires - 1_000L)
        val text = VoicePgpAuth.canonical(callId, sessionId, role, temp, "", caller, expires - 1_000L)
        auth.put("sig", BeamioNativeEthSigner.signEip191(key1, text)!!)
        return JSONObject()
            .put("sid", "sid-$role-0001")
            .put("key", "AAAA")
            .put("wk", "BBBB")
            .put("temp", temp)
            .put("tempPgpFpr", "")
            .put("auth", auth)
    }

    private fun offer(): JSONObject {
        val cv = channel("cv")
        val cV = channel("cV")
        val digest = VoiceOfferV4.chansDigest(listOf("cv" to cv, "cV" to cV))
        val text = VoiceOfferV4.canonicalOffer(callId, sessionId, caller, callee, created, expires, "audio/pcm;rate=16000", digest)
        return JSONObject()
            .put("type", "voice_call_offer_v1").put("proto", 4)
            .put("callId", callId).put("sessionId", sessionId)
            .put("from", caller).put("to", callee)
            .put("codec", "audio/pcm;rate=16000")
            .put("createdAt", created).put("expiresAt", expires).put("timestamp", created)
            .put("cv", cv).put("cV", cV)
            .put("sig", BeamioNativeEthSigner.signEip191(key1, text)!!)
    }

    private fun verify(o: JSONObject, nowMs: Long = now) = VoiceOfferV4.verify(o, callee, nowMs, recover, noArmor)

    @Test fun validOfferPasses() {
        assertNull(verify(offer()))
    }

    @Test fun wrongProtoOrTypeRefused() {
        assertEquals("shape", verify(offer().put("proto", 3)))
        assertEquals("shape", verify(offer().put("type", "voice_call_offer_v3")))
    }

    @Test fun unknownTopLevelKeyRefused() {
        assertEquals("unknown_key", verify(offer().put("callerTag", "@x")))
    }

    @Test fun notForLocalAccountRefused() {
        assertEquals("not_for_local", VoiceOfferV4.verify(offer(), "0x2222222222222222222222222222222222222222", now, recover, noArmor))
    }

    @Test fun expiredRefused() {
        assertEquals("expired", verify(offer(), expires))
    }

    @Test fun timestampMustEqualCreatedAt() {
        assertEquals("timestamp", verify(offer().put("timestamp", created + 1)))
    }

    @Test fun tamperedChannelBreaksDigestAndSignature() {
        val o = offer()
        o.getJSONObject("cv").put("sid", "sid-tampered-0002")
        assertEquals("sig_signer", verify(o))
    }

    @Test fun signerMustBeFrom() {
        // from is changed to the callee: the signature no longer recovers to from.
        val o = offer().put("from", callee)
        assertEquals("sig_signer", verify(o))
    }

    @Test fun channelUnknownKeyRefused() {
        val o = offer()
        o.getJSONObject("cV").put("extra", 1)
        assertEquals("channel_unknown_key", verify(o))
    }

    @Test fun callIdFormatRefused() {
        assertEquals("call_id", verify(offer().put("callId", "short")))
        assertEquals("call_id", verify(offer().put("callId", "x".repeat(129))))
        assertEquals("call_id", verify(offer().put("callId", "call 0001 abc")))
        assertEquals("call_id", verify(offer().put("callId", "call/0001/abc")))
        assertEquals("call_id", verify(offer().put("callId", "")))
    }

    @Test fun callIdEightAndLongest128Accepted() {
        // Format-only: the signature is over the old callId, so re-signing is needed for a full pass;
        // here only the format branch is checked (the result must not be call_id).
        assertTrue(verify(offer().put("callId", "abcdefgh")) != "call_id")
        assertTrue(verify(offer().put("callId", "a".repeat(128))) != "call_id")
    }

    @Test fun sessionIdFormatRefused() {
        assertEquals("session_id", verify(offer().put("sessionId", "")))
        assertEquals("session_id", verify(offer().put("sessionId", "sess-0001-abcdef")))
        assertEquals("session_id", verify(offer().put("sessionId", "A".repeat(32))))
        assertEquals("session_id", verify(offer().put("sessionId", "a".repeat(31))))
        assertEquals("session_id", verify(offer().put("sessionId", "a".repeat(33))))
        assertEquals("session_id", verify(offer().put("sessionId", "a".repeat(31) + "G")))
    }

    @Test fun sessionIdThirtyTwoLowerHexAccepted() {
        assertTrue(verify(offer().put("sessionId", "0123456789abcdef0123456789abcdef")) != "session_id")
    }

    @Test fun codecMustBeTheV4Value() {
        assertEquals("codec", verify(offer().put("codec", "audio/opus")))
        assertEquals("codec", verify(offer().put("codec", "")))
    }

    @Test fun chansDigestIsDeterministicAndOrderSensitive() {
        val a = channel("cv"); val b = channel("cV")
        assertEquals(VoiceOfferV4.chansDigest(listOf("cv" to a, "cV" to b)), VoiceOfferV4.chansDigest(listOf("cv" to a, "cV" to b)))
        assertTrue(VoiceOfferV4.chansDigest(listOf("cv" to a, "cV" to b)) != VoiceOfferV4.chansDigest(listOf("cV" to b, "cv" to a)))
    }

    @Test fun canonicalOfferTextIsExact() {
        val t = VoiceOfferV4.canonicalOffer("call-0001-abcdef", "sess-0001-abcdef", "0xAA", "0xBB", 5L, 9L, "c", "d")
        assertEquals("CoNET voice_call_offer_v4\ncallId:call-0001-abcdef\nsessionId:sess-0001-abcdef\nfrom:0xaa\nto:0xbb\ncreatedAt:5\nexpiresAt:9\ntimestamp:5\ncodec:c\nchansDigest:d", t)
    }

    /** Re-signs an offer after a field change, so a full-pass case can use a different callId/sessionId. */
    private fun resigned(callId: String, sessionId: String): JSONObject {
        val o = offer().put("callId", callId).put("sessionId", sessionId)
        // Channels carry no callId/sessionId in their own canonical except through VoicePgpAuth; re-sign those too.
        for (role in listOf("cv", "cV")) {
            val c = o.getJSONObject(role)
            val temp = c.getString("temp")
            val text = VoicePgpAuth.canonical(callId, sessionId, role, temp, "", caller, expires - 1_000L)
            c.getJSONObject("auth").put("sig", BeamioNativeEthSigner.signEip191(key1, text)!!)
        }
        val digest = VoiceOfferV4.chansDigest(listOf("cv" to o.getJSONObject("cv"), "cV" to o.getJSONObject("cV")))
        val text = VoiceOfferV4.canonicalOffer(callId, sessionId, caller, callee, created, expires, "audio/pcm;rate=16000", digest)
        return o.put("sig", BeamioNativeEthSigner.signEip191(key1, text)!!)
    }

    @Test fun fullPassWithAnotherCallIdAndSessionIdResigned() {
        assertNull(verify(resigned("call-0002-zzzzzz", "fedcba9876543210fedcba9876543210")))
    }

    @Test fun fullPassRejectsWhenSessionIdChangedWithoutResign() {
        // Changing sessionId without re-signing breaks the signature: the offer is refused.
        assertTrue(verify(offer().put("sessionId", "fedcba9876543210fedcba9876543210")) != null)
    }
}
