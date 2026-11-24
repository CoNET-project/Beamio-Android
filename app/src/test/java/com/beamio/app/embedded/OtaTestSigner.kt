package com.beamio.app.embedded

import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.util.encoders.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Test-only signer for manifest v2. Keys are generated in memory per test run and never written to disk.
 */
internal object OtaTestSigner {
    private fun newPair(): AsymmetricCipherKeyPair =
        Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair()

    private val trusted = newPair()
    val untrusted = newPair()
    val untrustedPublicBase64: String get() = Base64.toBase64String((untrusted.public as Ed25519PublicKeyParameters).encoded)

    val publicBase64: String = Base64.toBase64String((trusted.public as Ed25519PublicKeyParameters).encoded)
    val keys: List<OtaPublicKey> get() = EmbeddedPwaOtaKeys.table(publicBase64)
    val keyId: String get() = keys.single().keyId

    fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    /** beamio-tree-v1 of a zip, computed with the shell's own content digest after unpacking. */
    fun contentDigestOfZip(zip: ByteArray): String {
        val dir = Files.createTempDirectory("ota-cd").toFile()
        try {
            EmbeddedPwaZip.unzip(ByteArrayInputStream(zip), dir)
            return EmbeddedPwaBundleStore(Files.createTempDirectory("ota-cd-root").toFile(), { ByteArrayInputStream(zip) }, object : ActivatedAssetHashStore {
                override fun get(): String? = null
                override fun set(value: String) {}
            }).contentDigest(dir)
        } finally {
            dir.deleteRecursively()
        }
    }

    fun payload(
        zip: ByteArray,
        ver: String,
        filename: String = "SilentPassUI-$ver.zip",
        contentDigest: String = contentDigestOfZip(zip),
        minAndroid: Long = 0,
        v: Int = 2,
        contentAlg: String = "beamio-tree-v1",
        sha256: String = sha256(zip),
        size: Long = zip.size.toLong(),
    ): ByteArray = (
        // canonical field order and form (spec v2 §2), same as EmbeddedPwaOtaVerifier.canonicalPayload
        "{\"type\":\"beamio-pwa-ota\",\"v\":$v,\"ver\":\"$ver\",\"filename\":\"$filename\",\"sha256\":\"$sha256\"," +
            "\"size\":$size,\"contentAlg\":\"$contentAlg\",\"contentDigest\":\"$contentDigest\"," +
            "\"minShell\":{\"ios\":0,\"android\":$minAndroid},\"issuedAt\":1795000000}"
        ).toByteArray(Charsets.UTF_8)

    fun sign(payload: ByteArray, pair: AsymmetricCipherKeyPair = trusted, domain: String = "beamio-pwa-ota/v2\n"): JSONObject {
        val message = domain.toByteArray(Charsets.UTF_8) + payload
        val sig = Ed25519Signer().run {
            init(true, pair.private as Ed25519PrivateKeyParameters)
            update(message, 0, message.size)
            generateSignature()
        }
        val kid = EmbeddedPwaOtaVerifier.keyIdOf((pair.public as Ed25519PublicKeyParameters).encoded)
        return JSONObject().put("payload", Base64.toBase64String(payload))
            .put("signatures", JSONArray().put(JSONObject().put("keyId", kid).put("sig", Base64.toBase64String(sig))))
    }

    fun updateJson(payload: ByteArray, signed: JSONObject?, ver: String, filename: String = "SilentPassUI-$ver.zip"): String {
        val doc = JSONObject().put("ver", ver).put("filename", filename)
        if (signed != null) doc.put("signed", signed)
        return doc.toString()
    }

    /** A correctly signed update.json for [zip] at [ver]. */
    fun signedUpdateJson(zip: ByteArray, ver: String, minAndroid: Long = 0): String {
        val p = payload(zip, ver, minAndroid = minAndroid)
        return updateJson(p, sign(p), ver)
    }

    /**
     * Canonical ZIP (spec v2 §5): entries in order, local headers contiguous from 0, no data descriptors, no comments,
     * names written as given (validity is the reader's job). [level] 0 still deflates (method 8); [stored] uses method 0.
     */
    fun canonicalZip(entries: List<Pair<String, ByteArray>>, level: Int = 6, stored: Boolean = false,
                     declaredSize: Map<String, Long> = emptyMap()): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val central = java.io.ByteArrayOutputStream()
        fun le16(o: java.io.OutputStream, v: Int) { o.write(v and 0xff); o.write((v ushr 8) and 0xff) }
        fun le32(o: java.io.OutputStream, v: Long) { le16(o, (v and 0xffff).toInt()); le16(o, ((v ushr 16) and 0xffff).toInt()) }
        for ((name, data) in entries) {
            val crc = java.util.zip.CRC32().apply { update(data) }.value
            val body = if (stored) data else {
                val d = java.util.zip.Deflater(level, true)
                d.setInput(data); d.finish()
                val bo = java.io.ByteArrayOutputStream(); val buf = ByteArray(8192)
                while (!d.finished()) { val n = d.deflate(buf); bo.write(buf, 0, n) }
                d.end(); bo.toByteArray()
            }
            val nb = name.toByteArray(Charsets.UTF_8)
            val method = if (stored) 0 else 8
            val off = out.size().toLong()
            val usize = declaredSize[name] ?: data.size.toLong()
            le32(out, 0x04034b50); le16(out, 20); le16(out, 0); le16(out, method); le16(out, 0); le16(out, 0x21)
            le32(out, crc); le32(out, body.size.toLong()); le32(out, usize); le16(out, nb.size); le16(out, 0)
            out.write(nb); out.write(body)
            le32(central, 0x02014b50); le16(central, 0x0314); le16(central, 20); le16(central, 0); le16(central, method)
            le16(central, 0); le16(central, 0x21); le32(central, crc); le32(central, body.size.toLong()); le32(central, usize)
            le16(central, nb.size); le16(central, 0); le16(central, 0); le16(central, 0); le16(central, 0)
            le32(central, 0x81a4L shl 16); le32(central, off); central.write(nb)
        }
        val cdOff = out.size().toLong()
        val cd = central.toByteArray()
        out.write(cd)
        le32(out, 0x06054b50); le16(out, 0); le16(out, 0); le16(out, entries.size); le16(out, entries.size)
        le32(out, cd.size.toLong()); le32(out, cdOff); le16(out, 0)
        return out.toByteArray()
    }

    /** Rewrites any zip (e.g. from ZipOutputStream, which writes data descriptors) in canonical form; directories dropped. */
    fun canonicalize(zip: ByteArray, level: Int = 6): ByteArray {
        val entries = ArrayList<Pair<String, ByteArray>>()
        java.util.zip.ZipInputStream(ByteArrayInputStream(zip)).use { zin ->
            var e = zin.nextEntry
            while (e != null) {
                if (!e.isDirectory) entries.add(e.name to zin.readBytes())
                e = zin.nextEntry
            }
        }
        return canonicalZip(entries, level)
    }

    /** Verifies a correctly signed manifest for [zipFile] against the store's reference version and stages it. */
    fun stage(store: EmbeddedPwaBundleStore, zipFile: File, ver: String) {
        zipFile.writeBytes(canonicalize(zipFile.readBytes()))
        val check = store.otaVerifier.verifyManifest(signedUpdateJson(zipFile.readBytes(), ver), store.selectedVerifiedVersion())
        store.installDownloadToStaging(check, zipFile)
    }
}
