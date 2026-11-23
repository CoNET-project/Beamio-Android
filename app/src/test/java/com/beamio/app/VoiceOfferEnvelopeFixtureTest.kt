package com.beamio.app

import org.json.JSONObject
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * PWA envelope fixture (VECTOR-voice-offer-envelope-v2, one-time test only, not in git, not on a device).
 * The fixture path comes from VOICE_ENVELOPE_FIXTURE; without it the test is skipped. Only the outer
 * envelope check is exercised here (EIP-191 over the UTF-8 text), not PGP decrypt.
 */
class VoiceOfferEnvelopeFixtureTest {
    private fun fixture(): JSONObject? {
        val path = System.getenv("VOICE_ENVELOPE_FIXTURE") ?: return null
        val f = File(path)
        if (!f.isFile) return null
        return JSONObject(f.readText(Charsets.UTF_8))
    }

    @Test fun outerEnvelopeAcceptsPwaPositive() {
        val d = fixture()
        assumeTrue("fixture not provided", d != null)
        d!!
        val text = d.getString("envelopeText")
        val inner = JSONObject(text).getString("from")
        assertTrue(VoiceOfferWire.outerEnvelopeOk(text, d.getString("signMessage"), d.getString("envelopeFrom"), inner))
    }

    @Test fun outerEnvelopeRefusesChangedText() {
        val d = fixture()
        assumeTrue("fixture not provided", d != null)
        d!!
        val text = d.getString("envelopeText") + " "
        val inner = JSONObject(d.getString("envelopeText")).getString("from")
        assertFalse(VoiceOfferWire.outerEnvelopeOk(text, d.getString("signMessage"), d.getString("envelopeFrom"), inner))
    }

    @Test fun outerEnvelopeRefusesOtherFrom() {
        val d = fixture()
        assumeTrue("fixture not provided", d != null)
        d!!
        val text = d.getString("envelopeText")
        assertFalse(VoiceOfferWire.outerEnvelopeOk(text, d.getString("signMessage"), "0x1111111111111111111111111111111111111111", "0x1111111111111111111111111111111111111111"))
    }

    @Test fun outerEnvelopeRefusesInnerFromMismatch() {
        val d = fixture()
        assumeTrue("fixture not provided", d != null)
        d!!
        val text = d.getString("envelopeText")
        assertFalse(VoiceOfferWire.outerEnvelopeOk(text, d.getString("signMessage"), d.getString("envelopeFrom"), "0x1111111111111111111111111111111111111111"))
    }
}
