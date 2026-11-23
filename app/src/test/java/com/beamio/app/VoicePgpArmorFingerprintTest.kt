package com.beamio.app

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Negative cases only. A positive vector (armor → expected v4 fingerprint) must come from the
 * SDK/PWA sample (chat interface spec §128 method); it is not invented here.
 */
class VoicePgpArmorFingerprintTest {
    @Test fun notAnArmorIsNull() {
        assertNull(VoicePgpArmorFingerprint.of("not a key"))
    }

    @Test fun wrongBlockTypeIsNull() {
        assertNull(VoicePgpArmorFingerprint.of("-----BEGIN PGP MESSAGE-----\nAAAA\n-----END PGP MESSAGE-----"))
    }

    @Test fun garbagePublicBlockIsNull() {
        assertNull(VoicePgpArmorFingerprint.of("-----BEGIN PGP PUBLIC KEY BLOCK-----\ngarbage\n-----END PGP PUBLIC KEY BLOCK-----"))
    }

    /**
     * Positive case from the PWA's one-time test vector (PWA rev1, curve25519, public key only).
     * Runs only when VOICE_ARMOR_FP_FIXTURE points to that file; the vector is not stored in the repo.
     */
    @Test fun positiveVectorMatchesPwaFingerprint() {
        val path = System.getenv("VOICE_ARMOR_FP_FIXTURE")
        assumeTrue("fixture not provided", !path.isNullOrBlank())
        val json = JSONObject(File(path!!).readText(Charsets.UTF_8))
        val armor = json.getString("tempPgpArmor")
        val expected = json.getString("tempPgpFpr")
        assertEquals(40, expected.length)
        assertEquals(expected, expected.lowercase())
        assertEquals(expected, VoicePgpArmorFingerprint.of(armor))
    }
}
