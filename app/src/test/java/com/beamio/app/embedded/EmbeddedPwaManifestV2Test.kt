package com.beamio.app.embedded

import com.beamio.app.BuildConfig
import com.beamio.app.ChatOriginGate
import com.beamio.app.credential.WalletCredentialGate
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.attribute.FileTime
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Manifest v2 (spec v2.0 revision 1, vectors 747abad2…): golden vectors (45), non-canonical S, canonical payload
 * bytes, ZIP structure from the central directory, letter case, declared-length cut-off, MAX_ZIP_BYTES, re-verify before
 * promotion, decision table golden hash, concurrency cases and capability commands under an OTA active.
 */
class EmbeddedPwaManifestV2Test {
    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var root: File
    private val hashStore = object : ActivatedAssetHashStore {
        var value: String? = null
        override fun get(): String? = value
        override fun set(value: String) { this.value = value }
    }
    private val jvmStatter = FileStatter { f ->
        try {
            val a = Files.readAttributes(f.toPath(), "unix:size,lastModifiedTime,ctime,ino,mode", LinkOption.NOFOLLOW_LINKS)
            val mode = (a["mode"] as Int)
            FileStat((a["size"] as Long), (a["lastModifiedTime"] as FileTime).to(TimeUnit.NANOSECONDS),
                (a["ctime"] as FileTime).to(TimeUnit.NANOSECONDS), (a["ino"] as Long),
                (mode and 0xF000) == 0xA000, (mode and 0xF000) == 0x8000, (mode and 0xF000) == 0x4000)
        } catch (_: Exception) {
            null
        }
    }

    @Before
    fun setUp() {
        root = tmp.newFolder("silentpass_pwa")
    }

    private class Pkg(val zip: ByteArray, val sha: String, val content: String, val ver: String)

    private fun pkg(ver: String, extra: String = ""): Pkg {
        val zip = zipOf(ver, extra)
        return Pkg(zip, OtaTestSigner.sha256(zip), OtaTestSigner.contentDigestOfZip(zip), ver)
    }

    private fun store(p: Pkg, keys: List<OtaPublicKey> = OtaTestSigner.keys, opener: (() -> java.io.InputStream)? = null) =
        EmbeddedPwaBundleStore(
            rootDir = root, openBundledZip = opener ?: { ByteArrayInputStream(p.zip) }, activatedAssetHash = hashStore,
            remotePwaUpdate = true, expectedZipSha256 = p.sha, expectedContentSha256 = p.content, embeddedZipVer = p.ver,
            shellBuild = 191, statter = jvmStatter, installId = "fit:1000", otaKeys = keys,
        )

    private fun record() = ColdStartRecordFile(root).read()
    private fun stagedZip(ver: String, extra: String = "ota$ver") = tmp.newFile("ota-$ver-${System.nanoTime()}.zip").apply { writeBytes(zipOf(ver, extra)) }

    private fun zipOf(version: String, extra: String = ""): ByteArray {
        val files = mutableListOf(
            "index.html" to """<!doctype html><html><head><script defer="defer" src="/static/js/main.js"></script></head><body><div id="root"></div></body></html>""".toByteArray(),
            "update.json" to """{"ver":"$version","filename":"SilentPassUI-$version.zip"}""".toByteArray(),
            "static/js/main.js" to "// fixture".toByteArray(),
        )
        if (extra.isNotEmpty()) files.add("static/extra-$extra.txt" to extra.toByteArray())
        return OtaTestSigner.canonicalZip(files)
    }

    // ---- golden vectors (shared runner; TEST ONLY files outside the repository) ----

    private fun vectorRunner(): OtaVectorRunner {
        val dir = System.getProperty("beamio.otaVectorsDir")
        val golden = System.getProperty("beamio.otaGoldenZip")
        assumeTrue("set -PotaVectorsDir and -PotaGoldenZip to run the manifest v2 vectors", dir != null && golden != null)
        return OtaVectorRunner(File(dir!!), File(golden!!), tmp.newFolder("vectors-work"))
    }

    @Test
    fun goldenVectorsAll45() {
        val r = vectorRunner()
        val sha = OtaTestSigner.sha256(File(System.getProperty("beamio.otaVectorsDir"), "vectors.json").readBytes())
        assertEquals("vectors.json must be the frozen revision 1", "747abad22e97da707d45684ec6078fc0abab354405dc7cf228b6d8a4538b8031", sha)
        val outcomes = r.runAll()
        outcomes.forEach { println("vector $it") }
        assertEquals(45, outcomes.size)
        val failed = outcomes.filter { !it.ok }
        assertTrue("failed vectors: $failed", failed.isEmpty())
        println("vectors.json sha256=$sha cases=${outcomes.size} passed=${outcomes.count { it.ok }}")
    }

    @Test
    fun nonCanonicalSIsBadSignature() {
        assertEquals("bad_signature", vectorRunner().nonCanonicalS())
    }

    @Test
    fun goldenContentDigestEqualsBuildConstantFullLength() {
        val r = vectorRunner()
        val expected = r.doc.getJSONObject("golden").getString("contentDigest")
        assertEquals("13080eef9cec6068692696a8bd70ff10d19c1cfd9aa815f7c421f24748604974", expected)
        assertEquals(expected, r.goldenContentDigest())
        assertEquals(expected, BuildConfig.PWA_CONTENT_SHA256)
        // the embedded (installed) path computes the same full value from the unpacked directory
        val dir = tmp.newFolder("golden-unpacked")
        EmbeddedPwaZip.unzip(File(System.getProperty("beamio.otaGoldenZip")).inputStream(), dir)
        assertEquals(expected, store(pkg("0.53.48")).contentDigest(dir))
    }

    // ---- canonical payload bytes (independent of the vectors) ----

    @Test
    fun payloadMustBeByteForByteCanonical() {
        val z = zipOf("0.53.49")
        val good = OtaTestSigner.payload(z, "0.53.49")
        val v = EmbeddedPwaOtaVerifier(OtaTestSigner.keys, 191)
        fun verdictOf(p: ByteArray) = v.verifyManifest(OtaTestSigner.updateJson(p, OtaTestSigner.sign(p), "0.53.49"), "0.53.48").verdict
        assertEquals(OtaVerdict.OK, verdictOf(good))
        val text = String(good)
        val variants = listOf(
            text.replace("\"v\":2,", "\"v\":2,\"v\":2,"),
            text.replace("\"v\":2", "\"v\":2.0"),
            text.replace("\"size\":${z.size}", "\"size\":${z.size}e0"),
            text.replace("\"v\":2,", "\"v\": 2,"),
            text.replace("beamio-pwa-ota\"", "beamio-pwa-ot\\u0061\""),
            text.replace("{\"type\":\"beamio-pwa-ota\",\"v\":2,", "{\"v\":2,\"type\":\"beamio-pwa-ota\","),
        )
        variants.forEach { assertEquals(it, OtaVerdict.MALFORMED, verdictOf(it.toByteArray())) }
    }

    @Test
    fun revokedPayloadIsRevokedAndKeyIdMustBeHex() {
        val z = zipOf("0.53.49")
        val p = OtaTestSigner.payload(z, "0.53.49")
        val revoked = EmbeddedPwaOtaVerifier(OtaTestSigner.keys, 191, setOf(OtaTestSigner.sha256(p)))
        assertEquals(OtaVerdict.REVOKED, revoked.verifyManifest(OtaTestSigner.updateJson(p, OtaTestSigner.sign(p), "0.53.49"), "0.53.48").verdict)
        val signed = OtaTestSigner.sign(p)
        signed.getJSONArray("signatures").getJSONObject(0).put("keyId", "test-" + OtaTestSigner.keyId)
        assertEquals(OtaVerdict.MALFORMED, EmbeddedPwaOtaVerifier(OtaTestSigner.keys, 191).verifyManifest(OtaTestSigner.updateJson(p, signed, "0.53.49"), "0.53.48").verdict)
    }

    // ---- canonical ZIP read from the central directory ----

    @Test
    fun zipStructureIsCheckedFromTheCentralDirectory() {
        fun ok(b: ByteArray) = EmbeddedPwaCanonicalZip.validate(tmp.newFile().apply { writeBytes(b) })
        fun bad(b: ByteArray) = assertThrows(EmbeddedPwaCanonicalZip.NonCanonical::class.java) { ok(b) }
        val base = listOf("index.html" to "<html>".toByteArray(), "update.json" to "{\"ver\":\"0.53.49\"}".toByteArray())
        assertEquals(2, ok(OtaTestSigner.canonicalZip(base)).entries.size)
        assertEquals(2, ok(OtaTestSigner.canonicalZip(base, stored = true)).entries.size)
        // ZipOutputStream writes data descriptors (flag bit 3): not canonical
        val zos = ByteArrayOutputStream().also { o -> ZipOutputStream(o).use { z -> base.forEach { (n, b) -> z.putNextEntry(ZipEntry(n)); z.write(b); z.closeEntry() } } }.toByteArray()
        bad(zos)
        bad(OtaTestSigner.canonicalZip(base + ("static/A.js" to "a".toByteArray()) + ("static/a.js" to "b".toByteArray()))) // letter case only
        assertEquals("directory entry", bad(OtaTestSigner.canonicalZip(base + ("static/" to ByteArray(0)))).message)
        // the end record states a comment length that is not there: refused by the comment rule itself
        val lyingComment = OtaTestSigner.canonicalZip(base).also { it[it.size - 2] = 1 }
        assertEquals("archive comment present", bad(lyingComment).message)
        bad(OtaTestSigner.canonicalZip(base + (".source.json" to "{}".toByteArray())))
        bad(OtaTestSigner.canonicalZip(base + ("x/".repeat(130) + "a" to "a".toByteArray()))) // name > 255 bytes
        bad(OtaTestSigner.canonicalZip(base) + byteArrayOf(0)) // byte after the end record
        val withComment = OtaTestSigner.canonicalZip(base).let { b -> b.copyOf(b.size + 1).also { it[b.size - 2] = 1 } }
        bad(withComment) // archive comment
        bad(OtaTestSigner.canonicalZip(listOf("index.html" to "<html>".toByteArray()))) // no update.json
    }

    @Test
    fun entryIsCutOffAtItsDeclaredLength() {
        val big = ByteArray(100_000) { 'a'.code.toByte() }
        val zip = OtaTestSigner.canonicalZip(
            listOf("index.html" to "<html>".toByteArray(), "update.json" to "{\"ver\":\"0.53.49\"}".toByteArray(), "static/big.txt" to big),
            declaredSize = mapOf("static/big.txt" to 10L),
        )
        val f = tmp.newFile().apply { writeBytes(zip) }
        val layout = EmbeddedPwaCanonicalZip.validate(f) // headers agree: the lie is only visible while inflating
        val dest = File(tmp.root, "cut")
        val e = assertThrows(EmbeddedPwaCanonicalZip.NonCanonical::class.java) { EmbeddedPwaCanonicalZip.extract(f, layout, dest) }
        assertEquals("entry longer than declared", e.message)
        assertTrue("never more than the declared length on disk", File(dest, "static/big.txt").length() <= 10)
    }

    @Test
    fun updateJsonOverOneMibIsRefusedBeforeBuffering() {
        val pad = " ".repeat(EmbeddedPwaCanonicalZip.MAX_UPDATE_JSON_BYTES.toInt())
        fun zipWith(updateJson: String) = tmp.newFile().apply {
            writeBytes(OtaTestSigner.canonicalZip(listOf("index.html" to "<html>".toByteArray(), "update.json" to updateJson.toByteArray())))
        }
        val big = zipWith("{\"ver\":\"0.53.49\"}$pad")
        val e = assertThrows(EmbeddedPwaCanonicalZip.NonCanonical::class.java) {
            EmbeddedPwaCanonicalZip.extract(big, EmbeddedPwaCanonicalZip.validate(big), File(tmp.root, "big"))
        }
        assertEquals("update.json too large", e.message)
        assertFalse("refused before anything of update.json is written", File(tmp.root, "big/update.json").exists())
        // exactly at the limit is accepted
        val body = "{\"ver\":\"0.53.49\"}"
        val atLimit = zipWith(body + " ".repeat(EmbeddedPwaCanonicalZip.MAX_UPDATE_JSON_BYTES.toInt() - body.length))
        assertEquals("0.53.49", EmbeddedPwaCanonicalZip.extract(atLimit, EmbeddedPwaCanonicalZip.validate(atLimit), File(tmp.root, "ok")).updateVer)
    }

    @Test
    fun declaredTotalOverLimitIsRefusedBeforeInflating() {
        val zip = OtaTestSigner.canonicalZip(
            listOf("index.html" to "<html>".toByteArray(), "update.json" to "{}".toByteArray(), "static/a.bin" to ByteArray(1)),
            declaredSize = mapOf("static/a.bin" to EmbeddedPwaCanonicalZip.MAX_UNCOMPRESSED),
        )
        val e = assertThrows(EmbeddedPwaCanonicalZip.NonCanonical::class.java) { EmbeddedPwaCanonicalZip.validate(tmp.newFile().apply { writeBytes(zip) }) }
        assertEquals("uncompressed size too large", e.message)
    }

    @Test
    fun zipLargerThanMaxZipBytesIsNeverDownloaded() {
        val m = OtaManifest("0.53.49", "SilentPassUI-0.53.49.zip", "0".repeat(64), EmbeddedPwaOtaVerifier.MAX_ZIP_BYTES + 1,
            "0".repeat(64), 0, 0, 0, OtaTestSigner.keyId, "0".repeat(64))
        val v = EmbeddedPwaOtaVerifier(OtaTestSigner.keys, 191)
        assertEquals(OtaVerdict.ZIP_TOO_LARGE, v.checkDownloadSize(m))
        assertEquals("rejected-integrity", OtaVerdict.ZIP_TOO_LARGE.status)
        assertEquals(OtaVerdict.OK, v.checkDownloadSize(m.copy(size = EmbeddedPwaOtaVerifier.MAX_ZIP_BYTES)))
        assertEquals(128L * 1024 * 1024, EmbeddedPwaOtaVerifier.MAX_ZIP_BYTES)
    }

    // ---- before promotion, staging is verified again and its full digest recomputed ----

    @Test
    fun replacedStagingDoesNotPassWithTheOldSignedObject() {
        val p = pkg("0.53.48")
        store(p).bootstrapIfNeeded()
        val s = store(p)
        OtaTestSigner.stage(s, stagedZip("0.53.49"), "0.53.49")
        assertTrue(File(root, "staging/index.html").exists())
        // same version, other bytes (the signed object for the original content stays in ota-signed/)
        File(root, "staging/static/js/main.js").writeText("// replaced after staging")
        val c = store(p)
        c.bootstrapIfNeeded()
        assertEquals("0.53.48", c.activeVersion())
        assertFalse(File(root, "staging").exists())
        assertEquals("kept-identical", record()?.decision)
        // explicit apply path: a wholly replaced staging directory is refused as well
        OtaTestSigner.stage(c, stagedZip("0.53.49", "second"), "0.53.49")
        File(root, "staging").deleteRecursively()
        EmbeddedPwaZip.unzip(ByteArrayInputStream(zipOf("0.53.49", "other")), File(root, "staging"))
        assertEquals("staged_not_verified", assertThrows(IllegalStateException::class.java) { c.promoteStagingToActive() }.message)
        assertEquals("0.53.48", c.activeVersion())
    }

    // ---- any change to the decision table must change RULE_VERSION ----

    @Test
    fun decisionTableGoldenHashIsBoundToRuleVersion() {
        val vers = listOf(null, "0.53.47", "0.53.48", "0.53.49").map { PwaVersion.parse(it) }
        val sb = StringBuilder()
        for (local in LocalClass.values()) for (lv in vers) for (hasActive in listOf(false, true)) for (eOk in listOf(false, true))
            for (ev in vers) for (sOk in listOf(false, true)) for (sv in vers) {
                val r = selectCandidate(local, lv, hasActive, eOk, ev, sOk, sv)
                sb.append("$local|$lv|$hasActive|$eOk|$ev|$sOk|$sv -> ${r.pick}|${r.decision}|${r.embeddedOutcome}|${r.compares}\n")
            }
        val hash = OtaTestSigner.sha256(sb.toString().toByteArray())
        val golden = mapOf(2 to DECISION_TABLE_GOLDEN_V2)
        assertEquals(
            "decision table changed: raise ColdStartRecord.RULE_VERSION and add its golden hash here (got $hash)",
            golden[ColdStartRecord.RULE_VERSION], hash,
        )
    }

    // ---- concurrency cases C1a–C5 ----

    @Test
    fun c1aColdStartDuringDownloadKeepsOwnPartialAndRecordsUnconfirmed() {
        val p = pkg("0.53.48")
        val s = store(p)
        s.bootstrapIfNeeded()
        val own = File(root, "${EmbeddedPwaBundleStore.PARTIAL_PREFIX}${s.instanceId}").apply { mkdirs() }
        val foreign = File(root, "${EmbeddedPwaBundleStore.PARTIAL_PREFIX}0000other").apply { mkdirs() }
        assertTrue(s.instanceId.matches(Regex("^[0-9a-f]{32}$")))
        ColdStartRecordFile(root).invalidate()
        s.bootstrapIfNeeded() // retry in the same process while a download is unpacking
        assertTrue(own.exists())
        assertFalse(foreign.exists())
        assertEquals("unconfirmed", record()?.network)
        own.deleteRecursively()
        OtaTestSigner.stage(s, stagedZip("0.53.49"), "0.53.49") // the commit afterwards still works
        assertTrue(File(root, "staging/index.html").exists())
    }

    @Test
    fun c1bKilledBetweenSignedObjectAndRename() {
        val p = pkg("0.53.48")
        store(p).bootstrapIfNeeded()
        val s = store(p)
        OtaTestSigner.stage(s, stagedZip("0.53.49"), "0.53.49")
        val signed = File(root, EmbeddedPwaBundleStore.SIGNED_DIR).listFiles()!!.single()
        // killed after writing ota-signed but before the rename: no staging, orphan signed object
        File(root, "staging").deleteRecursively()
        val a = store(p)
        a.bootstrapIfNeeded()
        assertEquals("0.53.48", a.activeVersion())
        assertTrue(signed.exists()) // harmless; never trusted without a matching bundle
        assertNull(a.pendingUpdateVersion())
        // staging without a valid signed object is not S+: deleted by the full pass, never promoted
        EmbeddedPwaZip.unzip(ByteArrayInputStream(zipOf("0.53.50", "unsigned")), File(root, "staging"))
        val b = store(p)
        b.bootstrapIfNeeded()
        assertEquals("staging-present", b.lastReason)
        assertFalse(File(root, "staging").exists())
        assertEquals("0.53.48", b.activeVersion())
    }

    @Test
    fun c1cCommitRereadsTheReference() {
        val p = pkg("0.53.48")
        val s = store(p)
        s.bootstrapIfNeeded()
        val z = stagedZip("0.53.49")
        z.writeBytes(OtaTestSigner.canonicalize(z.readBytes()))
        val check = s.otaVerifier.verifyManifest(OtaTestSigner.signedUpdateJson(z.readBytes(), "0.53.49"), "0.53.48")
        assertEquals(OtaVerdict.OK, check.verdict)
        // meanwhile another path promoted a signed 0.53.50
        OtaTestSigner.stage(s, stagedZip("0.53.50"), "0.53.50")
        s.promoteStagingToActive()
        assertEquals(OtaVerdict.DOWNGRADE, assertThrows(EmbeddedPwaBundleStore.OtaRejected::class.java) { s.installDownloadToStaging(check, z) }.verdict)
    }

    @Test
    fun c2ColdStartPromotionDeletesRecordFirstAndTrustsByOtaIdentity() {
        val p = pkg("0.53.48")
        store(p).bootstrapIfNeeded()
        val z = stagedZip("0.53.49")
        OtaTestSigner.stage(store(p), z, "0.53.49")
        val c = store(p)
        c.bootstrapIfNeeded()
        assertEquals("0.53.49", c.activeVersion())
        assertEquals("promoted-ota", record()?.decision)
        assertEquals(OtaTestSigner.sha256(z.readBytes()), c.verifiedActiveZipSha256())
        // undeletable record: the change is refused
        val p2 = pkg("0.53.48")
        val t = store(p2)
        OtaTestSigner.stage(t, stagedZip("0.53.50"), "0.53.50")
        root.setWritable(false)
        try {
            assertThrows(IllegalStateException::class.java) { t.promoteStagingToActive() }
            assertEquals("0.53.49", t.activeVersion())
        } finally {
            root.setWritable(true)
        }
    }

    @Test
    fun c3aNewerEmbeddedOverOlderStaged() {
        // L = V-ota: the newer embedded is installed; the older S+ is no longer higher and is deleted
        val p = pkg("0.53.48")
        store(p).bootstrapIfNeeded()
        OtaTestSigner.stage(store(p), stagedZip("0.53.49"), "0.53.49")
        store(p).promoteStagingToActive()
        OtaTestSigner.stage(store(p), stagedZip("0.53.50"), "0.53.50")
        val n = pkg("0.53.51")
        val s = store(n)
        s.bootstrapIfNeeded()
        assertEquals("0.53.51", s.activeVersion())
        assertEquals("installed-newer", record()?.decision)
        assertFalse(File(root, "staging").exists())
        assertEquals(n.sha, s.verifiedActiveZipSha256())
        // L = U (previous shell's embedded bundle, not verifiable by this shell): candidates {E, S+} -> E
        root.deleteRecursively(); root.mkdirs()
        store(p).bootstrapIfNeeded()
        OtaTestSigner.stage(store(p), stagedZip("0.53.49"), "0.53.49")
        val u = store(pkg("0.53.50"))
        u.bootstrapIfNeeded()
        assertEquals("0.53.50", u.activeVersion())
        assertEquals("repaired-unverifiable", record()?.decision)
        assertFalse(File(root, "staging").exists())
    }

    @Test
    fun c3bNewerEmbeddedThenNewerStagedIsPromoted() {
        // L = V-ota: E (newer than L) installed, then S+ (newer than E) promoted
        val p = pkg("0.53.48")
        store(p).bootstrapIfNeeded()
        OtaTestSigner.stage(store(p), stagedZip("0.53.49"), "0.53.49")
        store(p).promoteStagingToActive()
        val z = stagedZip("0.53.52")
        OtaTestSigner.stage(store(p), z, "0.53.52")
        val s = store(pkg("0.53.51"))
        s.bootstrapIfNeeded()
        assertEquals("0.53.52", s.activeVersion())
        assertEquals("promoted-ota", record()?.decision)
        assertEquals(OtaTestSigner.sha256(z.readBytes()), s.verifiedActiveZipSha256())
        // L = U: S+ is chosen among the verified candidates and E is not unpacked
        root.deleteRecursively(); root.mkdirs()
        store(p).bootstrapIfNeeded()
        val z2 = stagedZip("0.53.51")
        OtaTestSigner.stage(store(p), z2, "0.53.51")
        val u = store(pkg("0.53.50"))
        u.bootstrapIfNeeded()
        assertEquals("0.53.51", u.activeVersion())
        assertEquals("selected-ota-over-embedded", record()?.decision)
        assertEquals(0, u.counters.unpack)
        assertEquals(OtaTestSigner.sha256(z2.readBytes()), u.verifiedActiveZipSha256())
    }

    @Test
    fun c3cRotatedKeyMakesOldOtaUnverifiable() {
        val p = pkg("0.53.48")
        store(p).bootstrapIfNeeded()
        OtaTestSigner.stage(store(p), stagedZip("0.53.49"), "0.53.49")
        store(p).promoteStagingToActive()
        OtaTestSigner.stage(store(p), stagedZip("0.53.50"), "0.53.50")
        val rotated = EmbeddedPwaOtaKeys.table(OtaTestSigner.untrustedPublicBase64)
        val s = store(pkg("0.53.48", "newshell"), keys = rotated)
        s.bootstrapIfNeeded()
        assertEquals("0.53.48", s.activeVersion())
        assertEquals("repaired-unverifiable", record()?.decision)
        assertFalse(File(root, "staging").exists())
    }

    @Test
    fun c4OlderEmbeddedIgnoredThenNewerStagedPromoted() {
        val p = pkg("0.53.47")
        store(p).bootstrapIfNeeded()
        OtaTestSigner.stage(store(p), stagedZip("0.53.49"), "0.53.49")
        store(p).promoteStagingToActive()
        OtaTestSigner.stage(store(p), stagedZip("0.53.50"), "0.53.50")
        ColdStartRecordFile(root).invalidate()
        val s = store(pkg("0.53.47", "rebuilt")) // new shell, embedded still older than the OTA active
        s.bootstrapIfNeeded()
        assertEquals("0.53.50", s.activeVersion())
        assertEquals("promoted-ota", record()?.decision)
        assertEquals("older-ignored", record()?.embeddedOutcome)
    }

    @Test
    fun c5BridgeCheckDuringColdStartWaitsAndNeverTrustsStale() {
        repeat(10) { round ->
            root.deleteRecursively(); root.mkdirs()
            val p = pkg("0.53.48")
            val s = store(p)
            val start = CountDownLatch(1)
            var seen: String? = "unset"
            val t = Thread { start.await(); seen = s.verifiedActiveZipSha256() }
            t.start()
            start.countDown()
            s.bootstrapIfNeeded()
            t.join(10_000)
            assertTrue("round $round: bridge saw $seen", seen == null || seen == p.sha)
            assertEquals(p.sha, s.verifiedActiveZipSha256())
        }
    }

    // ---- capability commands stay BUNDLE_NOT_VERIFIED under an OTA active (current behaviour, fixed here) ----

    @Test
    fun f13CapabilityCommandsUnderOtaActiveAreBundleNotVerified() {
        val p = pkg("0.53.48")
        store(p).bootstrapIfNeeded()
        val z = stagedZip("0.53.49")
        OtaTestSigner.stage(store(p), z, "0.53.49")
        val s = store(p)
        s.promoteStagingToActive()
        val otaSha = s.verifiedActiveZipSha256()
        assertNotNull(otaSha)
        assertEquals(OtaTestSigner.sha256(z.readBytes()), otaSha)
        val build = BuildConfig.PWA_ZIP_SHA256
        val inputs = WalletCredentialGate.TrustInputs(
            setOf(WalletCredentialGate.CAPABILITY), build, build, setOf(WalletCredentialGate.CAPABILITY), otaSha,
            WalletCredentialGate.Channel.WEB_MESSAGE, true, ChatOriginGate.TRUSTED,
        )
        assertEquals(WalletCredentialGate.Verdict.BUNDLE_NOT_VERIFIED, WalletCredentialGate.evaluate(inputs))
        assertEquals(WalletCredentialGate.Verdict.TRUSTED, WalletCredentialGate.evaluate(inputs, requireCapability = false))
        assertEquals(WalletCredentialGate.Verdict.TRUSTED, WalletCredentialGate.evaluate(inputs.copy(verifiedActiveZipSha256 = build)))
    }

    // ---- the formal key table never carries a test key ----

    @Test
    fun productionKeyTableHasNoTestKey() {
        val forbidden = setOf("250cf19731885996", "633f7e7faa3978cd", "6a43691314e4d10a", OtaTestSigner.keyId)
        assertTrue(EmbeddedPwaOtaKeys.PRODUCTION.none { it.keyId in forbidden })
        assertTrue(EmbeddedPwaOtaKeys.PRODUCTION.isEmpty()) // 191 ships with an empty table (no OTA)
    }

    private companion object {
        /** sha256 of the enumerated selectCandidate table for RULE_VERSION 2 (computed 2026-11-24 from b65f1103 rules). */
        const val DECISION_TABLE_GOLDEN_V2 = "b171c154c48335b334aefbabe2b6e225ae9b2a72da0467533b9197cf71211626"
    }
}
