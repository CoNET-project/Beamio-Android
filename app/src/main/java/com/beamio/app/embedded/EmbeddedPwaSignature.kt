package com.beamio.app.embedded

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.util.encoders.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

/**
 * Signed PWA OTA manifest, version 2.
 *
 * update.json = {"ver","filename","signed":{"payload":<base64>,"signatures":[{"keyId","sig"}]}}
 * Signed message = "beamio-pwa-ota/v2\n" + payload bytes (Ed25519). The payload is parsed from the verified raw bytes:
 * {"type":"beamio-pwa-ota","v":2,"ver","filename","sha256","size","contentAlg":"beamio-tree-v1","contentDigest",
 *  "minShell":{"ios","android"},"issuedAt"}
 *
 * A top-level `zip_sha256` is transport integrity only and is ignored: trust comes only from a signature by a key in the
 * compile-time table. This file has no network code; the store build never calls it.
 */
data class OtaPublicKey(val keyId: String, val publicKeyBase64: String)

/**
 * Compile-time public keys trusted to sign the OTA manifest. Several may be listed so a key can be rotated.
 * The production table is empty until production keys exist: an empty table means no OTA (nothing verifies).
 * A QA build (compile-time QA flag, debug certificate, local manifest URL) may add one test key; formal builds cannot.
 */
object EmbeddedPwaOtaKeys {
    val PRODUCTION: List<OtaPublicKey> = listOf(
        // Production public keys are added here only after they are generated offline and approved.
    )

    /** Keys used by this build: production plus the QA test key compiled in by a QA build (empty in formal builds). */
    fun table(qaPublicKeyBase64: String?): List<OtaPublicKey> {
        val qa = qaPublicKeyBase64?.takeIf { it.isNotBlank() }?.let { b64 ->
            EmbeddedPwaOtaVerifier.decodeBase64(b64)?.takeIf { it.size == 32 }?.let { raw ->
                OtaPublicKey(EmbeddedPwaOtaVerifier.keyIdOf(raw), b64)
            }
        }
        return PRODUCTION + listOfNotNull(qa)
    }

    /** First 16 hex of SHA-256 over the sorted "keyId:publicKey" lines of [keys] (records bind to it). */
    fun tableId(keys: List<OtaPublicKey>): String {
        val md = MessageDigest.getInstance("SHA-256")
        keys.map { "${it.keyId}:${it.publicKeyBase64}\n" }.sorted().forEach { md.update(it.toByteArray(Charsets.UTF_8)) }
        return md.digest().joinToString("") { "%02x".format(it) }.substring(0, 16)
    }
}

/** Phase is fixed at compile time: only bundles with an OK verdict are ever staged or promoted. */
object EmbeddedPwaOtaPolicy {
    const val ENFORCE: Boolean = true
}

enum class OtaVerdict(val code: String, val status: String) {
    OK("ok", "verified-staged"),
    MISSING_SIGNATURE("missing_signature", "rejected-signature"),
    MALFORMED("malformed", "rejected-signature"),
    UNTRUSTED_KEY("untrusted_key", "rejected-signature"),
    BAD_SIGNATURE("bad_signature", "rejected-signature"),
    REVOKED("revoked", "rejected-signature"),
    MISMATCH("mismatch", "rejected-signature"),
    DOWNGRADE("downgrade", "not-applicable"),
    SHELL_TOO_OLD("shell_too_old", "not-applicable"),
    SIZE_MISMATCH("size_mismatch", "rejected-integrity"),
    HASH_MISMATCH("hash_mismatch", "rejected-integrity"),
    CONTENT_MISMATCH("content_mismatch", "rejected-integrity"),
    NONCANONICAL_ZIP("noncanonical_zip", "rejected-integrity"),
    /**
     * Release-only pre-download limit (payload.size > [EmbeddedPwaOtaVerifier.MAX_ZIP_BYTES]); not a spec v2.0 verdict,
     * to be named in v2.1. Nothing is downloaded.
     */
    ZIP_TOO_LARGE("zip_too_large", "rejected-integrity"),
}

data class OtaManifest(
    val ver: String,
    val filename: String,
    val sha256: String,
    val size: Long,
    val contentDigest: String,
    val minShellIos: Long,
    val minShellAndroid: Long,
    val issuedAt: Long,
    val keyId: String,
    /** SHA-256 of the verified payload bytes (revocation list key). */
    val payloadSha256: String,
)

data class OtaManifestCheck(
    val verdict: OtaVerdict,
    val manifest: OtaManifest? = null,
    /** The `signed` object to store as `ota-signed/<contentDigest>.json` (payload and signatures copied verbatim). */
    val signedObject: JSONObject? = null,
)

class EmbeddedPwaOtaVerifier(
    trustedKeys: List<OtaPublicKey>,
    private val shellVersionCode: Long,
    private val revokedPayloads: Set<String> = REVOKED_PAYLOADS,
    /** minShell field this shell checks; "ios" only in the cross-platform vector tests. */
    private val platform: String = "android",
) {
    private val trusted: Map<String, ByteArray> = trustedKeys.mapNotNull { key ->
        val raw = decodeBase64(key.publicKeyBase64) ?: return@mapNotNull null
        if (raw.size != 32) return@mapNotNull null
        keyIdOf(raw) to raw
    }.toMap()

    val hasKeys: Boolean get() = trusted.isNotEmpty()

    /**
     * Checks done before downloading: signature, fields, minimum shell, and "strictly newer than [referenceVer]" (the
     * version of the currently selected verified bundle, or the embedded constant; never an unverified active version).
     */
    fun verifyManifest(updateJson: String, referenceVer: String?): OtaManifestCheck {
        val doc = try {
            JSONObject(updateJson)
        } catch (_: Exception) {
            return OtaManifestCheck(OtaVerdict.MALFORMED)
        }
        if (!doc.has("signed") || doc.isNull("signed")) return OtaManifestCheck(OtaVerdict.MISSING_SIGNATURE)
        val signed = doc.opt("signed") as? JSONObject ?: return OtaManifestCheck(OtaVerdict.MALFORMED)
        val (verdict, manifest) = verifySigned(signed)
        if (verdict != OtaVerdict.OK || manifest == null) return OtaManifestCheck(verdict, manifest)
        // Spec v2 §6 steps 7–9.
        if (doc.opt("ver") != manifest.ver || doc.opt("filename") != manifest.filename) {
            return OtaManifestCheck(OtaVerdict.MISMATCH, manifest)
        }
        val ref = PwaVersion.parse(referenceVer)
        val offered = checkNotNull(PwaVersion.parse(manifest.ver))
        if (ref == null || offered <= ref) return OtaManifestCheck(OtaVerdict.DOWNGRADE, manifest)
        val minShell = if (platform == "ios") manifest.minShellIos else manifest.minShellAndroid
        if (shellVersionCode < minShell) return OtaManifestCheck(OtaVerdict.SHELL_TOO_OLD, manifest)
        val stored = JSONObject()
            .put("payload", signed.getString("payload"))
            .put("signatures", signed.getJSONArray("signatures"))
            .put("updateVer", manifest.ver)
            .put("updateFilename", manifest.filename)
        return OtaManifestCheck(OtaVerdict.OK, manifest, stored)
    }

    /** Release-only limit checked before any download: a payload larger than [MAX_ZIP_BYTES] is never fetched. */
    fun checkDownloadSize(manifest: OtaManifest): OtaVerdict =
        if (manifest.size > MAX_ZIP_BYTES) OtaVerdict.ZIP_TOO_LARGE else OtaVerdict.OK

    /**
     * Signature and payload checks of a `signed` object (also used for a stored object), spec v2 §6 steps 1–6:
     * structure (malformed), missing signature, untrusted key, bad signature, payload v2 with canonical bytes
     * (malformed), revoked.
     */
    fun verifySigned(signed: JSONObject): Pair<OtaVerdict, OtaManifest?> {
        val signatures = signed.opt("signatures") as? JSONArray ?: return OtaVerdict.MALFORMED to null
        if (signatures.length() == 0) return OtaVerdict.MISSING_SIGNATURE to null
        if (signatures.length() > MAX_SIGNATURES) return OtaVerdict.MALFORMED to null
        val payload = decodeBase64(signed.opt("payload") as? String)
        if (payload == null || payload.size > MAX_PAYLOAD_BYTES) return OtaVerdict.MALFORMED to null
        // Every item must be well formed before any signature is checked (a keyId is exactly 16 lowercase hex).
        val items = ArrayList<Pair<String, String>>(signatures.length())
        for (i in 0 until signatures.length()) {
            val entry = signatures.opt(i) as? JSONObject ?: return OtaVerdict.MALFORMED to null
            val id = entry.opt("keyId") as? String ?: return OtaVerdict.MALFORMED to null
            val sig = entry.opt("sig") as? String ?: return OtaVerdict.MALFORMED to null
            if (!KEY_ID.matches(id)) return OtaVerdict.MALFORMED to null
            items.add(id to sig)
        }
        val message = SIGN_DOMAIN.toByteArray(Charsets.UTF_8) + payload
        var keyId: String? = null
        var sawTrusted = false
        for ((id, sigText) in items) {
            val raw = trusted[id] ?: continue
            sawTrusted = true
            val sig = decodeBase64(sigText)
            if (sig == null || sig.size != 64) continue
            if (ed25519Verify(raw, message, sig)) {
                keyId = id
                break
            }
        }
        if (keyId == null) return (if (sawTrusted) OtaVerdict.BAD_SIGNATURE else OtaVerdict.UNTRUSTED_KEY) to null
        val payloadSha = hex(MessageDigest.getInstance("SHA-256").digest(payload))
        val manifest = parsePayload(payload, keyId, payloadSha) ?: return OtaVerdict.MALFORMED to null
        if (payloadSha in revokedPayloads) return OtaVerdict.REVOKED to manifest
        return OtaVerdict.OK to manifest
    }

    /**
     * Bridge trust for an OTA active: the stored signed object must verify with a compile-time key, its payload must be
     * v2 with [activeDigest] (computed in full by this process) and [activeVer], and the shell must meet minShell.
     * Returns the verified manifest, or null (fail closed).
     */
    fun verifyStoredIdentity(storedBytes: ByteArray, activeDigest: String, activeVer: String?): OtaManifest? {
        if (storedBytes.size > MAX_STORED_BYTES) return null
        val obj = try {
            JSONObject(String(storedBytes, Charsets.UTF_8))
        } catch (_: Exception) {
            return null
        }
        val (verdict, manifest) = verifySigned(obj)
        if (verdict != OtaVerdict.OK || manifest == null) return null
        if (manifest.contentDigest != activeDigest) return null
        if (activeVer == null || manifest.ver != activeVer || PwaVersion.parse(activeVer) == null) return null
        val minShell = if (platform == "ios") manifest.minShellIos else manifest.minShellAndroid
        if (shellVersionCode < minShell) return null
        return manifest
    }

    /** Checks done on the downloaded zip, before it is unpacked: size and SHA-256 from the signed payload. */
    fun verifyBundle(manifest: OtaManifest, zip: File): OtaVerdict {
        if (zip.length() != manifest.size) return OtaVerdict.SIZE_MISMATCH
        val digest = MessageDigest.getInstance("SHA-256")
        zip.inputStream().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buffer)
                if (n < 0) break
                digest.update(buffer, 0, n)
            }
        }
        return if (hex(digest.digest()) == manifest.sha256) OtaVerdict.OK else OtaVerdict.HASH_MISMATCH
    }

    /**
     * Strict v2 payload of the verified bytes, or null. After the field checks the parsed fields are serialized again in
     * the fixed order (spec v2 §2); the result must equal [payload] byte for byte, so duplicate keys, `2.0`, `1e2`,
     * whitespace, `\u` escapes or reordering are all malformed whatever the JSON parser makes of them.
     */
    private fun parsePayload(payload: ByteArray, keyId: String, payloadSha: String): OtaManifest? {
        val p = try {
            JSONObject(String(payload, Charsets.UTF_8))
        } catch (_: Exception) {
            return null
        }
        if (p.length() != PAYLOAD_KEYS) return null
        if (p.opt("type") != PAYLOAD_TYPE || strictLong(p, "v") != PAYLOAD_VERSION) return null
        if (p.opt("contentAlg") != CONTENT_ALG) return null
        val ver = (p.opt("ver") as? String)?.takeIf { SEMVER.matches(it) && PwaVersion.parse(it) != null } ?: return null
        val filename = (p.opt("filename") as? String)?.takeIf { FILENAME.matches(it) } ?: return null
        val sha256 = (p.opt("sha256") as? String)?.takeIf { SHA256_HEX.matches(it) } ?: return null
        val size = strictLong(p, "size")?.takeIf { it in 1..MAX_SAFE_INTEGER } ?: return null
        val contentDigest = (p.opt("contentDigest") as? String)?.takeIf { SHA256_HEX.matches(it) } ?: return null
        val issuedAt = strictLong(p, "issuedAt")?.takeIf { it in 0..MAX_SAFE_INTEGER } ?: return null
        val minShell = p.opt("minShell") as? JSONObject ?: return null
        if (minShell.length() != 2) return null
        val minIos = strictLong(minShell, "ios")?.takeIf { it in 0..MAX_SAFE_INTEGER } ?: return null
        val minAndroid = strictLong(minShell, "android")?.takeIf { it in 0..MAX_SAFE_INTEGER } ?: return null
        val canonical = canonicalPayload(ver, filename, sha256, size, contentDigest, minIos, minAndroid, issuedAt)
        if (!canonical.contentEquals(payload)) return null
        return OtaManifest(ver, filename, sha256, size, contentDigest, minIos, minAndroid, issuedAt, keyId, payloadSha)
    }

    companion object {
        const val PAYLOAD_TYPE = "beamio-pwa-ota"
        const val PAYLOAD_VERSION = 2L
        const val SIGN_DOMAIN = "beamio-pwa-ota/v2\n"
        const val CONTENT_ALG = "beamio-tree-v1"
        /** SHA-256 of revoked payloads (compile time; empty by default). */
        val REVOKED_PAYLOADS: Set<String> = emptySet()
        /** Release-only download limit (bytes); the frozen 0.53.48 ZIP is about 11 MB. */
        const val MAX_ZIP_BYTES: Long = 128L * 1024 * 1024
        private const val MAX_SAFE_INTEGER = 9007199254740991L
        private const val PAYLOAD_KEYS = 10
        private val KEY_ID = Regex("""^[0-9a-f]{16}$""")
        private val SEMVER = Regex("""^(0|[1-9]\d{0,8})(\.(0|[1-9]\d{0,8})){2}$""")
        private const val MAX_PAYLOAD_BYTES = 4096
        private const val MAX_STORED_BYTES = 8192
        private const val MAX_SIGNATURES = 8
        private val FILENAME = Regex("""^[A-Za-z0-9._-]{1,128}\.zip$""")
        private val SHA256_HEX = Regex("""^[0-9a-f]{64}$""")
        private val BASE64 = Regex("""^[A-Za-z0-9+/]+={0,2}$""")

        /**
         * The one canonical payload serialization (spec v2 §2): fixed order, no whitespace. All string fields are
         * already restricted to characters JSON writes without escaping, so they are written as they are.
         */
        internal fun canonicalPayload(
            ver: String, filename: String, sha256: String, size: Long, contentDigest: String,
            minIos: Long, minAndroid: Long, issuedAt: Long,
        ): ByteArray = (
            "{\"type\":\"$PAYLOAD_TYPE\",\"v\":$PAYLOAD_VERSION,\"ver\":\"$ver\",\"filename\":\"$filename\"," +
                "\"sha256\":\"$sha256\",\"size\":$size,\"contentAlg\":\"$CONTENT_ALG\",\"contentDigest\":\"$contentDigest\"," +
                "\"minShell\":{\"ios\":$minIos,\"android\":$minAndroid},\"issuedAt\":$issuedAt}"
            ).toByteArray(Charsets.UTF_8)

        fun keyIdOf(rawPublicKey: ByteArray): String =
            hex(MessageDigest.getInstance("SHA-256").digest(rawPublicKey)).substring(0, 16)

        /** Strict standard base64 (padded); null when malformed. */
        fun decodeBase64(text: String?): ByteArray? {
            if (text.isNullOrEmpty() || text.length % 4 != 0 || !BASE64.matches(text)) return null
            return try {
                Base64.decode(text)
            } catch (_: Exception) {
                null
            }
        }

        private fun ed25519Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean =
            try {
                Ed25519Signer().run {
                    init(false, Ed25519PublicKeyParameters(publicKey, 0))
                    update(message, 0, message.size)
                    verifySignature(signature)
                }
            } catch (_: Exception) {
                false
            }

        /** Integer JSON numbers only (no strings, no fractions). */
        private fun strictLong(obj: JSONObject, key: String): Long? =
            when (val v = obj.opt(key)) {
                is Int -> v.toLong()
                is Long -> v
                else -> null
            }

        internal fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
    }
}
