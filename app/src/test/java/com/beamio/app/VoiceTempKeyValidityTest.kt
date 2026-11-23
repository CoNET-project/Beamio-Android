package com.beamio.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Temp-key validity (0 < d < n) and the pre-send signer self-check.
 * Key 1 has the well-known address 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf.
 */
class VoiceTempKeyValidityTest {
    private val n = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
    private val key1 = "0x" + "0".repeat(63) + "1"
    private val addr1 = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"

    @Test fun zeroScalarRefused() {
        assertNull(BeamioNativeEthSigner.address("0x" + "0".repeat(64)))
    }

    @Test fun scalarOutOfRangeRefused() {
        assertNull(BeamioNativeEthSigner.address("0x" + n))
        assertNull(BeamioNativeEthSigner.address("0x" + "f".repeat(64)))
    }

    @Test fun lastValidScalarAccepted() {
        val nMinus1 = "0x" + "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140"
        assertNotNull(BeamioNativeEthSigner.address(nMinus1))
    }

    @Test fun keyOneHasKnownAddress() {
        assertEquals(addr1, BeamioNativeEthSigner.address(key1)?.lowercase())
    }

    @Test fun selfCheckAcceptsSignerAndRefusesOthers() {
        val msg = "CoNET voice_call_offer_v3 self-check"
        val sig = BeamioNativeEthSigner.signEip191(key1, msg)
        assertNotNull(sig)
        assertTrue(BeamioNativeEthSigner.signedBy(msg, sig!!, addr1))
        assertTrue(BeamioNativeEthSigner.signedBy(msg, sig, addr1.uppercase().replaceFirst("0X", "0x")))
        assertFalse(BeamioNativeEthSigner.signedBy(msg, sig, "0x1111111111111111111111111111111111111111"))
        assertFalse(BeamioNativeEthSigner.signedBy(msg + "!", sig, addr1))
        assertFalse(BeamioNativeEthSigner.signedBy(msg, sig, ""))
    }
}
