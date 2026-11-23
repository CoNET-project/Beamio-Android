package com.beamio.app

import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import java.io.ByteArrayInputStream

/**
 * OpenPGP v4 fingerprint of the primary public key in an ASCII armor (RFC 4880 §12.2:
 * SHA-1(0x99 ‖ 2-byte length ‖ key packet body)). Lower-case 40-hex; null when the armor is
 * unreadable or the primary key is not a v4 key. Sub-keys are never used.
 */
object VoicePgpArmorFingerprint {
    fun of(armor: String): String? = runCatching {
        if (!armor.contains("BEGIN PGP PUBLIC KEY")) return null
        val input = ArmoredInputStream(ByteArrayInputStream(armor.toByteArray(Charsets.UTF_8)))
        val ring = PGPPublicKeyRing(input, BcKeyFingerprintCalculator())
        val primary: PGPPublicKey = ring.publicKey
        if (primary.version != 4) return null
        primary.fingerprint.joinToString("") { "%02x".format(it) }
    }.getOrNull()
}
