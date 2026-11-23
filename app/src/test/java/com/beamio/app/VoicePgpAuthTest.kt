package com.beamio.app

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VoicePgpAuthTest {
    private val key1 = "0x" + "0".repeat(63) + "1"
    private val addr1 = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    private val callId = "call-0001-abcdef"
    private val sessionId = "sess-0001-abcdef"
    private val channel = "cv"
    private val temp = "0x" + "a".repeat(40)
    private val fpr = "b".repeat(40)
    private val armor = "-----BEGIN PGP PUBLIC KEY BLOCK-----x"
    private val validUntil = 2_000_000L
    private val expires = 3_000_000L
    private val now = 1_000_000L

    private fun signedAuth(validUntilMs: Long = validUntil, fprForSig: String = fpr): JSONObject {
        val text = VoicePgpAuth.canonical(callId, sessionId, channel, temp, fprForSig, addr1, validUntilMs)
        val sig = BeamioNativeEthSigner.signEip191(key1, text)!!
        return JSONObject().put("from", addr1).put("validUntil", validUntilMs).put("sig", sig)
    }

    private fun verify(auth: JSONObject, top: String = fpr, armorFp: String? = fpr, nowMs: Long = now, exp: Long = expires): Boolean =
        VoicePgpAuth.verify(callId, sessionId, channel, temp, top, armor, auth, exp, nowMs,
            armorFingerprint = { armorFp }, recover = { t, s -> BeamioNativeEthSigner.recoverAddress(t, s) })

    @Test fun canonicalTextIsExact() {
        val t = VoicePgpAuth.canonical(callId, sessionId, channel, "0xABC", "B".repeat(40), "0xDEF", 42L)
        assertEquals(
            "CoNET voice_pgp_auth_v1\ncallId:call-0001-abcdef\nsessionId:sess-0001-abcdef\nchannel:cv\ntemp:0xabc\ntempPgpFpr:" +
                "b".repeat(40) + "\nfrom:0xdef\nvalidUntil:42", t)
    }

    @Test fun validSignatureVerifies() {
        assertTrue(verify(signedAuth()))
    }

    @Test fun extraAuthFieldRefused() {
        val auth = signedAuth().put("tempPgpFpr", fpr)
        assertFalse(verify(auth))
    }

    @Test fun fprMustBeLowerHex40() {
        assertTrue(VoicePgpAuth.fprFormatOk(fpr))
        assertTrue(VoicePgpAuth.fprFormatOk(""))
        assertFalse(VoicePgpAuth.fprFormatOk(fpr.uppercase()))
        assertFalse(VoicePgpAuth.fprFormatOk("b".repeat(39)))
        assertFalse(VoicePgpAuth.fprFormatOk("0x" + "b".repeat(40)))
    }

    @Test fun armorFingerprintMustMatchTopLevel() {
        assertFalse(verify(signedAuth(), armorFp = "c".repeat(40)))
        assertFalse(verify(signedAuth(), armorFp = null))
    }

    @Test fun tamperedFprFailsSignature() {
        // Signed over a different fingerprint than the top-level one: the rebuilt canonical no longer matches.
        assertFalse(verify(signedAuth(fprForSig = "c".repeat(40))))
    }

    @Test fun validUntilWindow() {
        assertFalse(verify(signedAuth(), nowMs = validUntil + 1))
        assertFalse(verify(signedAuth(validUntilMs = expires + 1), exp = expires))
    }

    @Test fun noArmorRequiresEmptyTopFpr() {
        assertTrue(VoicePgpAuth.fprFormatOk(""))
        assertNotNull(VoicePgpAuth.canonical(callId, sessionId, channel, temp, "", addr1, validUntil))
    }
}
