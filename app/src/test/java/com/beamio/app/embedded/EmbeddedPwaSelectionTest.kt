package com.beamio.app.embedded

import com.beamio.app.BuildConfig
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
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
import java.util.concurrent.TimeUnit
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Selection rules for unverifiable local bundles, "compared but not enabled" records, install identity, signed staging
 * and bridge trust for signed downloads.
 */
class EmbeddedPwaSelectionTest {
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

    private fun store(p: Pkg, release: Boolean = true, build: Long = 191, install: String? = "fit:1000",
                      keys: List<OtaPublicKey> = OtaTestSigner.keys, opener: (() -> java.io.InputStream)? = null) =
        EmbeddedPwaBundleStore(
            rootDir = root, openBundledZip = opener ?: { ByteArrayInputStream(p.zip) }, activatedAssetHash = hashStore,
            remotePwaUpdate = release, expectedZipSha256 = p.sha, expectedContentSha256 = p.content, embeddedZipVer = p.ver,
            shellBuild = build, statter = jvmStatter, installId = install, otaKeys = keys,
        )

    private fun record() = ColdStartRecordFile(root).read()
    private fun recordFile() = File(root, ColdStartRecord.FILE_NAME)
    private fun counts(s: EmbeddedPwaBundleStore) = s.counters.snapshot().take(3) // zipRead, unpack, compare

    /** Brings active/ to a signed OTA bundle at [ver] (embedded [base] installed first, then staged + promoted). */
    private fun activateSigned(base: Pkg, ver: String): File {
        store(base).bootstrapIfNeeded()
        val s = store(base)
        val z = tmp.newFile("ota-$ver-${System.nanoTime()}.zip").apply { writeBytes(zipOf(ver, "ota$ver")) }
        OtaTestSigner.stage(s, z, ver)
        s.promoteStagingToActive()
        return z
    }

    // 1 selector table (pure function)
    @Test
    fun selectorTable() {
        val v = { s: String -> PwaVersion.parse(s) }
        // verified local
        assertEquals(Selection(Pick.LOCAL, "kept-identical", "identical", 0), selectCandidate(LocalClass.V_EMB, v("0.53.48"), true, true, v("0.53.48"), false, null))
        assertEquals(Selection(Pick.EMBEDDED, "installed-newer", "enabled", 1), selectCandidate(LocalClass.V_OTA, v("0.53.48"), true, true, v("0.53.49"), false, null))
        assertEquals(Selection(Pick.LOCAL, "embedded-same-ignored", "same-version-ignored", 1), selectCandidate(LocalClass.V_OTA, v("0.53.49"), true, true, v("0.53.49"), false, null))
        assertEquals(Selection(Pick.LOCAL, "embedded-older-ignored", "older-ignored", 1), selectCandidate(LocalClass.V_OTA, v("0.53.49"), true, true, v("0.53.47"), false, null))
        assertEquals(Selection(Pick.LOCAL, null, "not-selected", 0), selectCandidate(LocalClass.V_OTA, v("0.53.49"), true, false, v("0.53.47"), false, null))
        assertEquals(Selection(Pick.LOCAL, "embedded-ver-unknown", "ver-unknown", 0), selectCandidate(LocalClass.V_OTA, v("0.53.49"), true, true, null, false, null))
        // unverifiable local: only verified candidates, higher wins, tie -> embedded
        assertEquals(Selection(Pick.EMBEDDED, "installed-first", "enabled", 0), selectCandidate(LocalClass.U, null, false, true, v("0.53.48"), false, null))
        assertEquals(Selection(Pick.EMBEDDED, "repaired-unverifiable", "enabled", 0), selectCandidate(LocalClass.U, v("9.9.9"), true, true, v("0.53.48"), false, null))
        assertEquals(Selection(Pick.STAGED, "selected-ota-over-embedded", "not-selected", 1), selectCandidate(LocalClass.U, null, true, true, v("0.53.48"), true, v("0.53.49")))
        assertEquals(Selection(Pick.EMBEDDED, "repaired-unverifiable", "enabled", 1), selectCandidate(LocalClass.U, null, true, true, v("0.53.48"), true, v("0.53.48")))
        assertEquals(Selection(Pick.EMBEDDED, "installed-first", "enabled", 1), selectCandidate(LocalClass.U, null, false, true, v("0.53.48"), true, v("0.53.40")))
        assertEquals(Selection(Pick.STAGED, "selected-ota-over-embedded", "not-selected", 0), selectCandidate(LocalClass.U, null, true, false, null, true, v("0.53.40")))
        assertEquals(Selection(Pick.NONE, null, "not-selected", 0), selectCandidate(LocalClass.U, null, true, false, null, false, null))
    }

    // 2 first start with an older embedded package and a signed active: compared, not enabled, recorded; then 0/0/0
    @Test
    fun olderEmbeddedIsComparedRecordedAndNeverOpenedAgain() {
        activateSigned(pkg("0.53.47"), "0.53.49")
        val older = pkg("0.53.47") // same embedded as the base, active is the signed 0.53.49
        recordFile().delete()
        val first = store(older)
        first.bootstrapIfNeeded()
        assertEquals("full", first.lastPath)
        assertEquals(listOf(1, 0, 1), counts(first))
        assertEquals("embedded-older-ignored", record()?.decision)
        assertEquals("older-ignored", record()?.embeddedOutcome)
        assertEquals("0.53.49", first.activeVersion())
        val bytes = recordFile().readBytes()
        val second = store(older, opener = { throw AssertionError("APK ZIP opened on the second start") })
        second.bootstrapIfNeeded()
        assertEquals("fast", second.lastPath)
        assertEquals(listOf(0, 0, 0), counts(second))
        assertArrayEquals(bytes, recordFile().readBytes())
    }

    // 3 same version: different content -> same-version-ignored; same content (other zip bytes) -> kept-identical, no unpack
    @Test
    fun sameVersionIgnoredOrIdentical() {
        activateSigned(pkg("0.53.47"), "0.53.49")
        recordFile().delete()
        val sameVerOtherContent = pkg("0.53.49", extra = "embedded-variant")
        val s = store(sameVerOtherContent)
        s.bootstrapIfNeeded()
        assertEquals("embedded-same-ignored", record()?.decision)
        assertEquals(0, s.counters.unpack)
        assertEquals("0.53.49", s.activeVersion())

        root.deleteRecursively(); root.mkdirs()
        val a = pkg("0.53.48")
        store(a).bootstrapIfNeeded()
        // same files, different zip container bytes (other compression level): same content digest
        val repacked = repack(a.zip)
        val b = Pkg(repacked, OtaTestSigner.sha256(repacked), OtaTestSigner.contentDigestOfZip(repacked), "0.53.48")
        assertEquals(a.content, b.content)
        val t = store(b)
        t.bootstrapIfNeeded()
        assertEquals("zip-changed", t.lastReason)
        assertEquals("kept-identical", record()?.decision)
        assertEquals(0, t.counters.unpack)
    }

    // 4 reinstall resets the ZIP check record (install identity); unknown identity writes no record
    @Test
    fun reinstallResetsRecordAndUnknownInstallWritesNothing() {
        val p = pkg("0.53.48")
        store(p, install = "fit:1000").bootstrapIfNeeded()
        val s = store(p, install = "fit:2000")
        s.bootstrapIfNeeded()
        assertEquals("install-changed", s.lastReason)
        assertEquals("fit:2000", record()?.installId)
        recordFile().delete()
        val u = store(p, install = null)
        u.bootstrapIfNeeded()
        assertFalse(recordFile().exists())
        assertEquals("install-unknown", store(p, install = null).also { it.bootstrapIfNeeded() }.lastReason)
    }

    // 5 rule version change is a miss
    @Test
    fun ruleVersionChangeIsAMiss() {
        val p = pkg("0.53.48")
        store(p).bootstrapIfNeeded()
        val rec = checkNotNull(record())
        ColdStartRecordFile(root).write(rec.copy(ruleVersion = 1))
        val s = store(p)
        s.bootstrapIfNeeded()
        assertEquals("rule-changed", s.lastReason)
    }

    // 6 unverifiable local x embedded x signed staged: higher verified candidate, tie -> embedded
    @Test
    fun unverifiableLocalChoosesHigherVerifiedCandidate() {
        for ((stagedVer, expectVer) in listOf("0.53.50" to "0.53.50", "0.53.48" to "0.53.48", "0.53.40" to "0.53.48")) {
            root.deleteRecursively(); root.mkdirs()
            val p = pkg("0.53.48")
            val s0 = store(p)
            s0.bootstrapIfNeeded()
            // a signed staged bundle (written under a lower reference so any version can be staged for the test)
            val z = zipOf(stagedVer, "staged")
            val zf = tmp.newFile().apply { writeBytes(z) }
            val check = s0.otaVerifier.verifyManifest(OtaTestSigner.signedUpdateJson(z, stagedVer), "0.0.1")
            // make the local bundle unverifiable and the reference low enough
            File(root, "active/static/js/main.js").appendText("// not trusted")
            val low = Pkg(p.zip, p.sha, p.content, "0.0.1")
            store(low).installDownloadToStaging(check, zf)
            val s = store(p)
            s.bootstrapIfNeeded()
            assertEquals("staged=$stagedVer", expectVer, s.activeVersion())
            val expectDecision = if (expectVer == stagedVer && stagedVer != "0.53.48") "selected-ota-over-embedded" else "repaired-unverifiable"
            assertEquals(expectDecision, record()?.decision)
            assertFalse(File(root, "staging").exists())
        }
    }

    // 7 untrusted things never become candidates or trust: unsigned staging, forged sig field, legacy ota-verified record
    @Test
    fun unsignedStagingForgedFieldsAndLegacyRecordsAreNeverTrusted() {
        val p = pkg("0.53.48")
        store(p).bootstrapIfNeeded()
        val active = File(root, "active")
        val forged = tmp.newFolder("forged")
        EmbeddedPwaZip.unzip(ByteArrayInputStream(zipOf("0.53.60", "forged")), forged)
        File(forged, "update.json").writeText("""{"ver":"0.53.60","filename":"SilentPassUI-0.53.60.zip","sig":"ok"}""")
        forged.copyRecursively(File(root, "staging"))
        val digest = store(p).contentDigest(File(root, "staging"))
        File(root, EmbeddedPwaBundleStore.OTA_RECORD_DIR).mkdirs()
        File(root, "${EmbeddedPwaBundleStore.OTA_RECORD_DIR}/$digest.json").writeText("""{"zip_sha256":"${"a".repeat(64)}"}""")
        val s = store(p)
        s.bootstrapIfNeeded()
        assertEquals("0.53.48", s.activeVersion())
        assertFalse(File(root, "staging").exists())
        assertFalse(File(root, EmbeddedPwaBundleStore.OTA_RECORD_DIR).exists())
        // the forged bundle as active is unverifiable (repaired), never trusted
        active.deleteRecursively(); forged.copyRecursively(active)
        assertNull(store(p).verifiedActiveZipSha256())
    }

    // 8 network failure: status only, selection and counts unchanged, offline start uses the embedded package
    @Test
    fun networkFailureIsStatusOnly() {
        val p = pkg("0.53.48")
        val s0 = store(p)
        s0.writeOtaStatus("network-error", null, null)
        s0.bootstrapIfNeeded()
        assertEquals("network-error", record()?.network)
        assertEquals("installed-first", record()?.decision)
        assertEquals("0.53.48", s0.activeVersion())
        assertEquals("fast", store(p).also { it.bootstrapIfNeeded() }.lastPath)
    }

    // 9 bridge: signed identity trusted; tampered active, swapped signed file, removed key, minShell too high -> closed
    @Test
    fun signedIdentityTrustAndFailClosed() {
        val base = pkg("0.53.47")
        val otaZip = activateSigned(base, "0.53.49")
        val s = store(base)
        s.bootstrapIfNeeded()
        assertEquals(OtaTestSigner.sha256(otaZip.readBytes()), s.verifiedActiveZipSha256())
        // removed key (new shell with an empty table): unverifiable -> repaired with embedded
        val noKey = store(base, keys = emptyList())
        assertNull(noKey.verifiedActiveZipSha256())
        // swapped signed object (other content): closed
        val signedFile = File(root, "${EmbeddedPwaBundleStore.SIGNED_DIR}/${s.contentDigest(s.activeDir)}.json")
        val original = signedFile.readBytes()
        val other = zipOf("0.53.49", "other")
        val p = OtaTestSigner.payload(other, "0.53.49")
        signedFile.writeText(OtaTestSigner.sign(p).put("updateVer", "0.53.49").put("updateFilename", "SilentPassUI-0.53.49.zip").toString())
        assertNull(store(base).verifiedActiveZipSha256())
        signedFile.writeBytes(original)
        // minShell above this shell: closed
        val high = OtaTestSigner.payload(otaZip.readBytes(), "0.53.49", minAndroid = 999)
        signedFile.writeText(OtaTestSigner.sign(high).toString())
        assertNull(store(base, build = 191).verifiedActiveZipSha256())
        signedFile.writeBytes(original)
        // tampered active: closed
        File(root, "active/static/js/main.js").appendText("// tampered")
        assertNull(store(base).verifiedActiveZipSha256())
    }

    // 10 concurrency: foreign partial = residue; staging commit re-reads the reference; undeletable record refuses changes
    @Test
    fun concurrencyRules() {
        val p = pkg("0.53.48")
        store(p).bootstrapIfNeeded()
        File(root, "${EmbeddedPwaBundleStore.PARTIAL_PREFIX}other-process").mkdirs()
        val s = store(p)
        s.bootstrapIfNeeded()
        assertEquals("residue", s.lastReason)
        assertFalse(File(root, "${EmbeddedPwaBundleStore.PARTIAL_PREFIX}other-process").exists())
        // C1c: verified for 0.53.49, but the selected bundle became 0.53.49 meanwhile -> rejected at commit
        val z = zipOf("0.53.49", "c1c")
        val zf = tmp.newFile().apply { writeBytes(z) }
        val check = s.otaVerifier.verifyManifest(OtaTestSigner.signedUpdateJson(z, "0.53.49"), "0.53.48")
        assertEquals(OtaVerdict.OK, check.verdict)
        val moved = Pkg(p.zip, p.sha, p.content, "0.53.49") // reference is now 0.53.49 (embedded constant of a new shell)
        File(root, "active/static/js/main.js").appendText("// unverifiable so the constant is the reference")
        assertEquals(OtaVerdict.DOWNGRADE, assertThrows(EmbeddedPwaBundleStore.OtaRejected::class.java) { store(moved).installDownloadToStaging(check, zf) }.verdict)
        // undeletable record: promotion refused
        root.deleteRecursively(); root.mkdirs()
        store(p).bootstrapIfNeeded()
        val n = tmp.newFile().apply { writeBytes(zipOf("0.53.50", "n")) }
        val t = store(p)
        OtaTestSigner.stage(t, n, "0.53.50")
        root.setWritable(false)
        try {
            assertThrows(IllegalStateException::class.java) { t.promoteStagingToActive() }
            assertEquals("0.53.48", t.activeVersion())
        } finally {
            root.setWritable(true)
        }
    }

    // 11 the downloaded content digest must be the signed one, and the staged update.json is never rewritten
    @Test
    fun stagingKeepsTheSignedBytes() {
        val p = pkg("0.53.48")
        val s = store(p)
        s.bootstrapIfNeeded()
        val z = zipOf("0.53.49", "keep")
        val zf = tmp.newFile().apply { writeBytes(z) }
        OtaTestSigner.stage(s, zf, "0.53.49")
        assertEquals(OtaTestSigner.contentDigestOfZip(z), s.contentDigest(File(root, "staging")))
        val originalUpdate = JSONObject(String(zipEntry(z, "update.json")))
        assertEquals(originalUpdate.toString(), JSONObject(File(root, "staging/update.json").readText()).toString())
    }

    // 12 the embedded content digest is the same full value on iOS (BeamioPWABuild.json treeDigest of 0.53.48)
    @Test
    fun embeddedContentDigestEqualsIosTreeDigestFullLength() {
        assertEquals("c4805a90ae4bbec1ea5f6f3db5cf1674023819fe77fed165287fe54b094f2f19", BuildConfig.PWA_ZIP_SHA256)
        assertEquals("13080eef9cec6068692696a8bd70ff10d19c1cfd9aa815f7c421f24748604974", BuildConfig.PWA_CONTENT_SHA256)
    }

    // 13 store builds never touch OTA: signed objects and staging are ignored, record network is n/a
    @Test
    fun storeIgnoresOta() {
        val p = pkg("0.53.48")
        val s = store(p, release = false)
        s.bootstrapIfNeeded()
        assertEquals("n/a", record()?.network)
        assertThrows(IllegalStateException::class.java) { s.installDownloadToStaging(OtaManifestCheck(OtaVerdict.OK), tmp.newFile()) }
    }

    // canonical zip form (names; structure and limits are in EmbeddedPwaManifestV2Test)
    @Test
    fun canonicalZipRules() {
        fun z(vararg names: String): File = tmp.newFile().apply { writeBytes(OtaTestSigner.canonicalZip(names.map { it to "x".toByteArray() })) }
        fun canonical(f: File) = runCatching { EmbeddedPwaCanonicalZip.validate(f) }.isSuccess
        assertTrue(canonical(z("index.html", "update.json", "static/js/main.js")))
        assertFalse(canonical(z("index.html")))
        assertFalse(canonical(z("index.html", "update.json", "../x")))
        assertFalse(canonical(z("index.html", "update.json", "__MACOSX/a")))
        assertFalse(canonical(z("index.html", "update.json", "static/._a")))
        assertFalse(canonical(z("index.html", "update.json", ".loaded-sha256")))
        assertFalse(canonical(z("index.html", "update.json", "a b.js")))
        assertFalse(canonical(z("index.html", "update.json", "/abs")))
    }

    private fun zipOf(version: String, extra: String = ""): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            val files = linkedMapOf(
                "index.html" to """<!doctype html><html><head><script defer="defer" src="/static/js/main.js"></script></head><body><div id="root"></div></body></html>""",
                "update.json" to """{"ver":"$version","filename":"SilentPassUI-$version.zip"}""",
                "static/js/main.js" to "// fixture",
            )
            if (extra.isNotEmpty()) files["static/extra-$extra.txt"] = extra
            files.forEach { (name, body) -> zip.putNextEntry(ZipEntry(name)); zip.write(body.toByteArray()); zip.closeEntry() }
        }
        return OtaTestSigner.canonicalize(out.toByteArray())
    }

    private fun repack(zip: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { z ->
            z.setLevel(0)
            java.util.zip.ZipInputStream(ByteArrayInputStream(zip)).use { zin ->
                var e = zin.nextEntry
                while (e != null) {
                    val data = zin.readBytes()
                    z.putNextEntry(ZipEntry(e.name)); z.write(data); z.closeEntry()
                    e = zin.nextEntry
                }
            }
        }
        return OtaTestSigner.canonicalize(out.toByteArray(), 0)
    }

    private fun zipEntry(zip: ByteArray, name: String): ByteArray {
        java.util.zip.ZipInputStream(ByteArrayInputStream(zip)).use { zin ->
            var e = zin.nextEntry
            while (e != null) {
                if (e.name == name) return zin.readBytes()
                e = zin.nextEntry
            }
        }
        error("no $name")
    }
}
