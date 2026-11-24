package com.beamio.app.embedded

import org.json.JSONObject
import java.io.File
import java.math.BigInteger

/**
 * Table-driven run of the frozen manifest v2 golden vectors (OTA-MANIFEST-V2-VECTORS/vectors.json, spec v2.0 revision 1)
 * through the shell's own verifier and download check. Shared by the JVM unit test and the instrumented test (API 24–32,
 * BouncyCastle Ed25519 and the platform org.json). The vectors are TEST ONLY and are never copied into the repository:
 * [vectorsDir] holds vectors.json and zips/, [goldenZip] the frozen 0.53.48 ZIP.
 */
internal class OtaVectorRunner(private val vectorsDir: File, private val goldenZip: File, private val workDir: File) {

    data class Outcome(val name: String, val expected: String, val actual: String) {
        val ok: Boolean get() = expected == actual
        override fun toString(): String = "$name expected=$expected actual=$actual ${if (ok) "OK" else "FAIL"}"
    }

    val doc: JSONObject = JSONObject(File(vectorsDir, "vectors.json").readText())

    private val trustedKeys: List<OtaPublicKey> = doc.getJSONArray("trustedKeys").let { a ->
        (0 until a.length()).map { a.getJSONObject(it).let { k -> OtaPublicKey(k.getString("keyId"), k.getString("publicKey")) } }
    }

    private fun zipFor(name: String): File =
        if (name.startsWith("golden:")) goldenZip else File(vectorsDir, name)

    private fun verifier(ctx: JSONObject): EmbeddedPwaOtaVerifier {
        val revoked = ctx.getJSONArray("revokedPayloads").let { a -> (0 until a.length()).map { a.getString(it) }.toSet() }
        return EmbeddedPwaOtaVerifier(trustedKeys, ctx.getLong("shellBuild"), revoked, ctx.getString("platform"))
    }

    /** Runs every case; each outcome compares "manifestVerdict/bundleVerdict" with the expectation. */
    fun runAll(): List<Outcome> {
        val cases = doc.getJSONArray("cases")
        return (0 until cases.length()).map { i -> runCase(cases.getJSONObject(i)) }
    }

    private fun runCase(c: JSONObject): Outcome {
        val name = c.getString("name")
        val ctx = c.getJSONObject("context")
        val expect = c.getJSONObject("expect")
        val expManifest = expect.getString("manifestVerdict")
        val expBundle = if (expect.isNull("bundleVerdict")) null else expect.getString("bundleVerdict")
        val v = verifier(ctx)
        val ref = if (ctx.isNull("referenceVersion")) null else ctx.getString("referenceVersion")
        val check = v.verifyManifest(c.getString("updateJson"), ref)
        var actualBundle: String? = null
        if (expBundle != null && check.verdict == OtaVerdict.OK && check.manifest != null && !c.isNull("zip")) {
            val zip = zipFor(c.getString("zip"))
            val partial = File(workDir, "partial-$name")
            actualBundle = EmbeddedPwaBundleStore.unpackVerifiedDownload(v, check.manifest!!, zip, partial).code
            partial.deleteRecursively()
        }
        return Outcome(name, "$expManifest/${expBundle ?: "-"}", "${check.verdict.code}/${actualBundle ?: "-"}")
    }

    /**
     * Extra case: the golden manifest with S replaced by S + L (a non-canonical scalar with the same
     * value mod L) must be bad_signature. Returns the verdict code.
     */
    fun nonCanonicalS(): String {
        val golden = (0 until doc.getJSONArray("cases").length()).map { doc.getJSONArray("cases").getJSONObject(it) }
            .first { it.getString("name") == "golden-ok-android" }
        val outer = JSONObject(golden.getString("updateJson"))
        val sigObj = outer.getJSONObject("signed").getJSONArray("signatures").getJSONObject(0)
        val sig = EmbeddedPwaOtaVerifier.decodeBase64(sigObj.getString("sig"))!!
        val s = BigInteger(1, sig.copyOfRange(32, 64).reversedArray())
        val l = BigInteger.ONE.shiftLeft(252).add(BigInteger("27742317777372353535851937790883648493"))
        val sl = s.add(l).toByteArray().reversedArray().copyOf(32) // little-endian, still fits 256 bits
        val forged = sig.copyOfRange(0, 32) + sl
        sigObj.put("sig", org.bouncycastle.util.encoders.Base64.toBase64String(forged))
        return verifier(golden.getJSONObject("context")).verifyManifest(outer.toString(), golden.getJSONObject("context").getString("referenceVersion")).verdict.code
    }

    /** beamio-tree-v1 of the golden ZIP through the shell's canonical reader (must equal golden.contentDigest). */
    fun goldenContentDigest(): String {
        val dest = File(workDir, "golden-digest")
        try {
            return EmbeddedPwaCanonicalZip.extract(goldenZip, EmbeddedPwaCanonicalZip.validate(goldenZip), dest).contentDigest
        } finally {
            dest.deleteRecursively()
        }
    }
}

internal object OtaTestShared {
    fun sha256(bytes: ByteArray): String = EmbeddedPwaOtaVerifier.hex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes))
}
