package com.beamio.app.legacy

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Encryption for the native page record (an encrypted copy is allowed). File layout: "BSR1" | 12-byte IV | AES-GCM
 * ciphertext with 128-bit tag; AAD binds the format. [Keystore] is used on devices; tests inject [Software].
 */
interface RecordCipher {
    fun seal(plain: ByteArray): ByteArray
    fun open(sealed: ByteArray): ByteArray

    abstract class Gcm : RecordCipher {
        protected abstract fun key(): SecretKey
        private val rnd = SecureRandom()

        override fun seal(plain: ByteArray): ByteArray {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, key())
            c.updateAAD(AAD)
            val iv = c.iv
            require(iv.size == 12)
            val ct = c.doFinal(plain)
            return MAGIC + iv + ct
        }

        override fun open(sealed: ByteArray): ByteArray {
            if (sealed.size < 4 + 12 + 16 || !sealed.copyOfRange(0, 4).contentEquals(MAGIC)) throw java.io.IOException("record_unreadable")
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, sealed, 4, 12))
            c.updateAAD(AAD)
            return try { c.doFinal(sealed, 16, sealed.size - 16) } catch (e: Exception) { throw java.io.IOException("record_unreadable") }
        }

        @Suppress("unused") private fun unused() = rnd
    }

    /**
     * Android Keystore AES-256-GCM, non-exportable, randomized IVs, usable only while the device is unlocked
     * (setUnlockedDeviceRequired, API 28+; ≈ iOS Complete), StrongBox when present. The key never leaves the device
     * and the file lives in noBackupFilesDir (≈ ThisDeviceOnly).
     */
    class Keystore(private val alias: String = "beamio.shellrecord.v1") : Gcm() {
        override fun key(): SecretKey {
            val ks = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            (ks.getKey(alias, null) as? SecretKey)?.let { return it }
            fun spec(strongBox: Boolean): android.security.keystore.KeyGenParameterSpec {
                val b = android.security.keystore.KeyGenParameterSpec.Builder(
                    alias, android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or android.security.keystore.KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setRandomizedEncryptionRequired(true)
                if (android.os.Build.VERSION.SDK_INT >= 28) {
                    b.setUnlockedDeviceRequired(true)
                    if (strongBox) b.setIsStrongBoxBacked(true)
                }
                return b.build()
            }
            val gen = javax.crypto.KeyGenerator.getInstance(android.security.keystore.KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            return try {
                gen.init(spec(strongBox = true)); gen.generateKey()
            } catch (e: Exception) {
                gen.init(spec(strongBox = false)); gen.generateKey()
            }
        }
    }

    /** Test-only software key. */
    class Software(private val k: SecretKey = javax.crypto.KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()) : Gcm() {
        override fun key() = k
    }

    companion object {
        val MAGIC = byteArrayOf('B'.code.toByte(), 'S'.code.toByte(), 'R'.code.toByte(), '1'.code.toByte())
        val AAD = "beamio.shellrecord.v1".toByteArray()
    }
}
