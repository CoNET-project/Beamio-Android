package com.beamio.app.embedded

import com.beamio.app.BuildConfig
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
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
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * cold-start completion record, fast path and the reordered full pass.
 * Counters are per store instance: zipRead (APK ZIP opens), unpack, compare (version comparisons), digest (full content
 * digests). A "second cold start" is a new store instance on the same directory (= a new process).
 */
class EmbeddedPwaColdStartTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var root: File
    private val hashStore = object : ActivatedAssetHashStore {
        var value: String? = null
        override fun get(): String? = value
        override fun set(value: String) { this.value = value }
    }

    /** JVM lstat through the "unix" attribute view (macOS/Linux test hosts); production uses android.system.Os. */
    private val jvmStatter = FileStatter { f ->
        try {
            val a = Files.readAttributes(f.toPath(), "unix:size,lastModifiedTime,ctime,ino,mode", LinkOption.NOFOLLOW_LINKS)
            val mode = (a["mode"] as Int)
            FileStat(
                size = (a["size"] as Long),
                mtimeNs = (a["lastModifiedTime"] as FileTime).to(TimeUnit.NANOSECONDS),
                ctimeNs = (a["ctime"] as FileTime).to(TimeUnit.NANOSECONDS),
                inode = (a["ino"] as Long),
                isSymlink = (mode and 0xF000) == 0xA000,
                isRegular = (mode and 0xF000) == 0x8000,
                isDirectory = (mode and 0xF000) == 0x4000,
            )
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
        val dir = tmp.newFolder()
        EmbeddedPwaZip.unzip(ByteArrayInputStream(zip), dir)
        val content = EmbeddedPwaBundleStore(tmp.newFolder(), { ByteArrayInputStream(zip) }, hashStore).contentDigest(dir)
        return Pkg(zip, sha256(zip), content, ver)
    }

    private fun store(p: Pkg, release: Boolean, build: Long = 190, opener: (() -> java.io.InputStream)? = null, install: String? = "fit:1000") =
        EmbeddedPwaBundleStore(
            rootDir = root,
            openBundledZip = opener ?: { ByteArrayInputStream(p.zip) },
            activatedAssetHash = hashStore,
            remotePwaUpdate = release,
            expectedZipSha256 = p.sha,
            expectedContentSha256 = p.content,
            embeddedZipVer = p.ver,
            shellBuild = build,
            statter = jvmStatter,
            installId = install,
            otaKeys = OtaTestSigner.keys,
        )

    private fun recordFile() = File(root, ColdStartRecord.FILE_NAME)
    private fun counts(s: EmbeddedPwaBundleStore) = s.counters.snapshot().toList()

    // 1 fresh install → full (unpack 1, record); second cold start → fast with all counters 0, record bytes unchanged.
    @Test
    fun freshInstallThenSecondColdStartIsFastWithZeroCounters() {
        for (release in listOf(false, true)) {
            root.deleteRecursively(); root.mkdirs()
            val p = pkg("0.53.48")
            val first = store(p, release)
            first.bootstrapIfNeeded()
            assertEquals("full", first.lastPath)
            assertEquals("no-record", first.lastReason)
            assertEquals(1, first.counters.unpack)
            assertTrue(recordFile().isFile)
            val bytes = recordFile().readBytes()

            val second = store(p, release)
            second.bootstrapIfNeeded()
            assertEquals("release=$release", "fast", second.lastPath)
            assertEquals(listOf(0, 0, 0, 0), counts(second))
            assertArrayEquals(bytes, recordFile().readBytes())
            // Trust is still established only by a full digest of active/ (constants seed the expectation).
            assertEquals(p.sha, second.verifiedActiveZipSha256())
            assertEquals(1, second.counters.fullDigest)
        }
    }

    // 2 no record, identical active → full without unpacking, record rewritten; next start fast.
    @Test
    fun missingRecordWithIdenticalActiveIsAFullPassWithoutUnpack() {
        for (release in listOf(false, true)) {
            root.deleteRecursively(); root.mkdirs()
            val p = pkg("0.53.48")
            store(p, release).bootstrapIfNeeded()
            recordFile().delete()
            val s = store(p, release)
            s.bootstrapIfNeeded()
            assertEquals("full", s.lastPath)
            assertEquals(0, s.counters.unpack)
            assertEquals(1, s.counters.zipRead)
            assertTrue(recordFile().isFile)
            val next = store(p, release)
            next.bootstrapIfNeeded()
            assertEquals("fast", next.lastPath)
        }
    }

    // 3 embedded update (new ZIP, pin, content, build) → miss, install, record; then fast.
    @Test
    fun embeddedUpdateInstallsAndThenRunsFast() {
        for (release in listOf(false, true)) {
            root.deleteRecursively(); root.mkdirs()
            val old = pkg("0.53.47")
            store(old, release, build = 189).bootstrapIfNeeded()
            val new = pkg("0.53.48")
            val s = store(new, release, build = 190)
            s.bootstrapIfNeeded()
            assertEquals("zip-changed", s.lastReason)
            assertEquals("0.53.48", s.activeVersion())
            assertEquals(1, s.counters.unpack)
            val next = store(new, release, build = 190)
            next.bootstrapIfNeeded()
            assertEquals("fast", next.lastPath)
        }
    }

    // 4 same version, different bytes, same build (QA) → pin change → repaired.
    @Test
    fun sameVersionDifferentBytesSameBuildIsRepaired() {
        for (release in listOf(false, true)) {
            root.deleteRecursively(); root.mkdirs()
            val a = pkg("0.53.48", extra = "a")
            store(a, release).bootstrapIfNeeded()
            val b = pkg("0.53.48", extra = "b")
            val s = store(b, release)
            s.bootstrapIfNeeded()
            assertEquals("zip-changed", s.lastReason)
            assertEquals(b.content, s.contentDigest(s.activeDir))
            assertEquals(b.sha, s.verifiedActiveZipSha256())
        }
    }

    // 5 embedded older: store repairs; release keeps a verified OTA active (record present).
    @Test
    fun olderEmbeddedRepairsStoreButKeepsVerifiedOtaOnRelease() {
        val newer = pkg("0.53.48")
        store(newer, release = false).bootstrapIfNeeded()
        val older = pkg("0.53.40")
        val s = store(older, release = false)
        s.bootstrapIfNeeded()
        assertEquals("0.53.40", s.activeVersion())

        root.deleteRecursively(); root.mkdirs()
        val r = store(older, release = true)
        r.bootstrapIfNeeded()
        val otaZip = tmp.newFile("ota.zip").apply { writeBytes(zipOf("0.53.50", "ota")) }
        OtaTestSigner.stage(r, otaZip, "0.53.50")
        val afterOta = store(older, release = true)
        afterOta.bootstrapIfNeeded() // staging promoted after the comparison
        assertEquals("0.53.50", afterOta.activeVersion())
        // Order: embedded-vs-active needs no comparison (identical), then one staging comparison. Promoting staging
        // first would classify the result as OTA and add an embedded-vs-OTA comparison (compare=2, kept-verified-newer-ota).
        assertEquals(1, afterOta.counters.compare)
        assertEquals("promoted-ota", ColdStartRecordFile(root).read()?.decision)
        val again = store(older, release = true)
        again.bootstrapIfNeeded()
        assertEquals("fast", again.lastPath)
        assertEquals("0.53.50", again.activeVersion())
        assertEquals(sha256(otaZip.readBytes()), again.verifiedActiveZipSha256())
        recordFile().delete()
        val full = store(older, release = true)
        full.bootstrapIfNeeded()
        assertEquals("0.53.50", full.activeVersion()) // same-or-older embedded: verified OTA kept
        assertEquals(1, full.counters.compare)
        assertEquals("embedded-older-ignored", ColdStartRecordFile(root).read()?.decision)
    }

    // 6 fingerprint sensitivity: same-size rewrite with mtime restored, delete, add, replace all change it.
    @Test
    fun fingerprintChangesOnSameSizeRewriteWithRestoredMtimeAndOnDeleteAddReplace() {
        val p = pkg("0.53.48")
        store(p, release = false).bootstrapIfNeeded()
        val active = File(root, "active")
        val ex = setOf(EmbeddedPwaBundleStore.LOADED_SHA_MARKER, EmbeddedPwaBundleStore.LOADED_CONTENT_MARKER)
        val f0 = bundleFingerprint(active, jvmStatter, ex)
        assertNotNull(f0)
        val js = File(active, "static/js/main.js")
        val mtime = Files.getLastModifiedTime(js.toPath())
        Thread.sleep(20)
        js.writeText("// fixturX".take(js.length().toInt()).padEnd(js.length().toInt(), 'x'))
        Files.setLastModifiedTime(js.toPath(), mtime)
        val f1 = bundleFingerprint(active, jvmStatter, ex)
        assertNotEquals("ctime must change even with mtime restored", f0, f1)
        File(active, "new.txt").writeText("n")
        val f2 = bundleFingerprint(active, jvmStatter, ex)
        assertNotEquals(f1, f2)
        File(active, "new.txt").delete()
        assertNotEquals(f2, bundleFingerprint(active, jvmStatter, ex))
        // marker writes do not count
        val f3 = bundleFingerprint(active, jvmStatter, ex)
        File(active, EmbeddedPwaBundleStore.LOADED_SHA_MARKER).writeText("x")
        assertEquals(f3, bundleFingerprint(active, jvmStatter, ex))
        // and a changed active is a fast-path miss
        val s = store(p, release = false)
        s.bootstrapIfNeeded()
        assertEquals("fingerprint-changed", s.lastReason)
    }

    // 7 damaged record: truncated, unknown schema, tmp residue, empty field → full pass and rewrite.
    @Test
    fun damagedRecordsAreMissesAndAreRewritten() {
        val p = pkg("0.53.48")
        store(p, release = false).bootstrapIfNeeded()
        val good = recordFile().readText()
        val cases = listOf(
            good.substring(0, good.length / 2) to "parse-error",
            good.replace(ColdStartRecord.SCHEMA, "beamio.pwa.coldstart.v0") to "parse-error",
            good.replace("\"result\":\"complete\"", "\"result\":\"\"") to "parse-error",
        )
        for ((text, reason) in cases) {
            recordFile().writeText(text)
            val s = store(p, release = false)
            s.bootstrapIfNeeded()
            assertEquals(reason, s.lastReason)
            assertNotNull(ColdStartRecordFile(root).read())
        }
        File(root, ColdStartRecord.TMP_NAME).writeText("stale")
        val s = store(p, release = false)
        s.bootstrapIfNeeded()
        assertEquals("residue", s.lastReason)
        assertFalse(File(root, ColdStartRecord.TMP_NAME).exists())
        assertEquals("fast", store(p, release = false).also { it.bootstrapIfNeeded() }.lastPath)
    }

    // 8 delete-before-change: while active/ is being replaced, no record exists.
    @Test
    fun noRecordExistsWhileActiveIsReplaced() {
        val a = pkg("0.53.47")
        store(a, release = false).bootstrapIfNeeded()
        assertTrue(recordFile().isFile)
        val b = pkg("0.53.48")
        var recordSeenDuringReplace: Boolean? = null
        val s = object : EmbeddedPwaBundleStore(root, { ByteArrayInputStream(b.zip) }, hashStore, false, b.sha, b.content, b.ver, 190, jvmStatter, "fit:1000", OtaTestSigner.keys) {
            override fun onStoreReplaced(activeDir: File) { recordSeenDuringReplace = recordFile().exists() }
        }
        s.bootstrapIfNeeded()
        assertEquals(false, recordSeenDuringReplace)
        assertTrue(recordFile().isFile) // written after verification
        // interrupted mid-swap on release: active gone, backup complete → full pass recovers and rewrites
        root.deleteRecursively(); root.mkdirs()
        store(b, release = true).bootstrapIfNeeded()
        File(root, "active").renameTo(File(root, "backup"))
        val r = store(b, release = true)
        r.bootstrapIfNeeded()
        assertEquals("full", r.lastPath)
        assertEquals("0.53.48", r.activeVersion())
        assertNotNull(ColdStartRecordFile(root).read())
    }

    // 9 G5: active incomplete (missing script) with a complete backup is recovered before classification.
    @Test
    fun interruptedSwapRecoversCompleteBackup() {
        val p = pkg("0.53.48")
        store(p, release = true).bootstrapIfNeeded()
        val active = File(root, "active")
        active.copyRecursively(File(root, "backup"))
        File(active, "static/js/main.js").delete()
        val s = store(p, release = true)
        s.bootstrapIfNeeded()
        assertEquals("active-incomplete", s.lastReason)
        assertTrue(File(active, "static/js/main.js").isFile)
        assertEquals(0, s.counters.unpack) // the recovered backup is the embedded package: kept
    }

    // 10 release with staging present → full; a staged bundle not newer is deleted.
    @Test
    fun releaseStagingForcesFullPassAndStaleStagingIsDeleted() {
        val p = pkg("0.53.48")
        val s0 = store(p, release = true)
        s0.bootstrapIfNeeded()
        // A leftover staging without a valid signed object (e.g. an old hash-only download) is never a candidate.
        EmbeddedPwaZip.unzip(ByteArrayInputStream(zipOf("0.53.60", "stale")), File(root, "staging"))
        val s = store(p, release = true)
        s.bootstrapIfNeeded()
        assertEquals("staging-present", s.lastReason)
        assertFalse(File(root, "staging").exists())
        assertEquals(p.content, s.contentDigest(s.activeDir))
        assertEquals("fast", store(p, release = true).also { it.bootstrapIfNeeded() }.lastPath)
    }

    // 11 promote: not strictly newer → refused; promotion deletes the record first.
    @Test
    fun promoteRequiresStrictlyNewerAndDeletesTheRecord() {
        val p = pkg("0.53.48")
        val s = store(p, release = true)
        s.bootstrapIfNeeded()
        val same = tmp.newFile("same.zip").apply { writeBytes(zipOf("0.53.48", "same")) }
        val e = assertThrows(EmbeddedPwaBundleStore.OtaRejected::class.java) { OtaTestSigner.stage(s, same, "0.53.48") }
        assertEquals(OtaVerdict.DOWNGRADE, e.verdict) // same version is never staged
        assertTrue(recordFile().isFile)
        val newer = tmp.newFile("newer.zip").apply { writeBytes(zipOf("0.53.49", "n")) }
        OtaTestSigner.stage(s, newer, "0.53.49")
        s.promoteStagingToActive()
        assertFalse(recordFile().exists())
        assertEquals("0.53.49", s.activeVersion())
        val next = store(p, release = true)
        next.bootstrapIfNeeded()
        assertEquals("full", next.lastPath)
        assertEquals("0.53.49", next.activeVersion())
        assertEquals("fast", store(p, release = true).also { it.bootstrapIfNeeded() }.lastPath)
    }

    // 12 strict version parsing.
    @Test
    fun strictVersionParsing() {
        assertEquals(PwaVersion(0, 53, 48), PwaVersion.parse("0.53.48"))
        assertEquals(PwaVersion(999999999, 0, 1), PwaVersion.parse("999999999.0.1"))
        for (bad in listOf("0.53.48-rc", "v0.53.48", "0.53", "0.53.48.1", "01.2.3", "1.02.3", "1000000000.0.0", "", " 0.53.48", "0.53.48 ", "+1.2.3", "1..3")) {
            assertNull(bad, PwaVersion.parse(bad))
        }
        assertNull(PwaVersion.parse(null))
        assertTrue(EmbeddedPwaBundleStore.isSemverNewer("0.53.47", "0.53.48"))
        assertFalse(EmbeddedPwaBundleStore.isSemverNewer("0.53.48", "0.53.48"))
        assertFalse(EmbeddedPwaBundleStore.isSemverNewer("0.53.47", "0.53.48-rc"))
        assertFalse(EmbeddedPwaBundleStore.isSemverNewer("0.53.47-rc", "0.53.48"))
        assertEquals(OtaCheckDecision.SKIP_ACTIVE_UNKNOWN, decideOtaCheck("0.53.48x", "0.53.49"))
        assertEquals(OtaCheckDecision.NO_NEWER, decideOtaCheck("0.53.48", "0.53.49-rc"))
        assertEquals(OtaCheckDecision.STAGE, decideOtaCheck("0.53.48", "0.53.49"))
    }

    // 13 bridge independence: tampering after a fast start loses trust and deletes the record; a forged record grants nothing.
    @Test
    fun recordNeverGrantsTrust() {
        val p = pkg("0.53.48")
        store(p, release = false).bootstrapIfNeeded()
        val s = store(p, release = false)
        s.bootstrapIfNeeded()
        assertEquals("fast", s.lastPath)
        File(root, "active/static/js/main.js").writeText("// tampered after the fast start")
        assertNull(s.verifiedActiveZipSha256())
        assertFalse(recordFile().exists())

        // forged record that matches the tampered active's fingerprint and claims it is the embedded content
        root.deleteRecursively(); root.mkdirs()
        store(p, release = false).bootstrapIfNeeded()
        val rec = checkNotNull(ColdStartRecordFile(root).read())
        File(root, "active/static/js/main.js").writeText("// tampered")
        File(root, "active/update.json").writeText("""{"ver":"9.9.9","filename":"SilentPassUI-9.9.9.zip"}""") // "higher version"
        val fp = checkNotNull(bundleFingerprint(File(root, "active"), jvmStatter, setOf(EmbeddedPwaBundleStore.LOADED_SHA_MARKER, EmbeddedPwaBundleStore.LOADED_CONTENT_MARKER)))
        ColdStartRecordFile(root).write(rec.copy(activeFingerprint = fp))
        val forged = store(p, release = false)
        forged.bootstrapIfNeeded()
        assertEquals("fast", forged.lastPath) // page selection trusts the record...
        assertNull(forged.verifiedActiveZipSha256()) // ...the bridge does not
        assertFalse(recordFile().exists())
        val repaired = store(p, release = false)
        repaired.bootstrapIfNeeded()
        assertEquals(p.sha, repaired.verifiedActiveZipSha256())
    }

    // 14 scheme A: the build-time constant equals the runtime content digest of the real embedded ZIP.
    @Test
    fun buildTimeContentConstantMatchesRuntimeDigestOfTheEmbeddedZip() {
        val asset = File("src/main/assets/SilentPassUI.zip")
        assertTrue("run from the app module", asset.isFile)
        assertEquals(BuildConfig.PWA_ZIP_SHA256, sha256(asset.readBytes()))
        val dir = tmp.newFolder()
        EmbeddedPwaZip.unzip(asset.inputStream(), dir)
        val digest = EmbeddedPwaBundleStore(tmp.newFolder(), { asset.inputStream() }, hashStore).contentDigest(dir)
        assertEquals(BuildConfig.PWA_CONTENT_SHA256, digest)
        assertNotNull(PwaVersion.parse(BuildConfig.PWA_ZIP_VER))
    }

    // 15 release: OTA active without a verified record is repaired; with a record it is kept and trusted (see 5).
    @Test
    fun releaseOtaActiveWithoutRecordIsRepaired() {
        val p = pkg("0.53.48")
        store(p, release = true).bootstrapIfNeeded()
        val active = File(root, "active")
        active.deleteRecursively()
        EmbeddedPwaZip.unzip(ByteArrayInputStream(zipOf("0.53.60", "unrecorded")), active)
        val s = store(p, release = true)
        s.bootstrapIfNeeded()
        assertEquals("0.53.48", s.activeVersion())
        assertEquals("repaired-unverifiable", ColdStartRecordFile(root).read()?.decision)
        assertEquals(0, s.counters.compare) // unverifiable: repaired without a version comparison
    }

    // 16 store: pin mismatch fails closed even with an old record present; the record never makes it a hit.
    @Test
    fun storePinMismatchFailsClosedEvenWithRecord() {
        val p = pkg("0.53.48")
        store(p, release = false).bootstrapIfNeeded()
        val other = pkg("0.53.48", extra = "other")
        // APK ZIP bytes differ from the pin baked into this build.
        val s = EmbeddedPwaBundleStore(root, { ByteArrayInputStream(other.zip) }, hashStore, false, p.sha, p.content, p.ver, 190, jvmStatter, "fit:1000", OtaTestSigner.keys)
        // A fast hit never reads the ZIP, so force the full pass: change the active.
        File(root, "active/extra.txt").writeText("x")
        assertThrows(EmbeddedPwaBundleStore.BundleIntegrityException::class.java) { s.bootstrapIfNeeded() }
        assertFalse(File(root, "active").exists())
        assertFalse(recordFile().exists())
    }

    // 17 record location: only silentpass_pwa/coldstart-record.v1.json; a same-named file inside active/ is ignored.
    @Test
    fun recordLivesOnlyAtTheRoot() {
        val p = pkg("0.53.48")
        store(p, release = false).bootstrapIfNeeded()
        val good = recordFile().readText()
        recordFile().delete()
        File(root, "active/${ColdStartRecord.FILE_NAME}").writeText(good)
        val s = store(p, release = false)
        s.bootstrapIfNeeded()
        assertEquals("no-record", s.lastReason)
        assertTrue(recordFile().isFile)
    }

    // Record v2: a different shell build with the same ZIP reuses the record (fast); the fast path never opens the ZIP.
    @Test
    fun buildChangeWithSameZipReusesRecordAndFastPathNeverOpensTheZip() {
        val p = pkg("0.53.48")
        store(p, release = false, build = 189).bootstrapIfNeeded()
        val s = store(p, release = false, build = 190)
        s.bootstrapIfNeeded()
        assertEquals("fast", s.lastPath)
        val noZip = store(p, release = false, build = 190, opener = { throw AssertionError("fast path opened the APK ZIP") })
        noZip.bootstrapIfNeeded()
        assertEquals("fast", noZip.lastPath)
    }

    // a restore or device migration changes every inode/ctime: only a recomputation (full pass without
    // unpacking when the content is intact), never a refusal; afterwards fast again.
    @Test
    fun inodeChangeFromRestoreIsARecomputationNotARefusal() {
        for (release in listOf(false, true)) {
            root.deleteRecursively(); root.mkdirs()
            val p = pkg("0.53.48")
            store(p, release).bootstrapIfNeeded()
            val active = File(root, "active")
            val moved = File(root.parentFile, "restore-${'$'}release")
            active.copyRecursively(moved, overwrite = true) // new files = new inodes/ctimes, same bytes
            active.deleteRecursively()
            moved.copyRecursively(active)
            moved.deleteRecursively()
            val s = store(p, release)
            s.bootstrapIfNeeded()
            assertEquals("fingerprint-changed", s.lastReason)
            assertEquals(0, s.counters.unpack)
            assertEquals(p.sha, s.verifiedActiveZipSha256())
            assertEquals("fast", store(p, release).also { it.bootstrapIfNeeded() }.lastPath)
        }
    }

    // the embedded ZIP unpack refuses path traversal (zip slip) before writing outside bundled/.
    @Test
    fun unzipRefusesPathTraversal() {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { z ->
            z.putNextEntry(ZipEntry("../escape.txt")); z.write("x".toByteArray()); z.closeEntry()
        }
        val dest = File(root, "bundled")
        assertThrows(SecurityException::class.java) { EmbeddedPwaZip.unzip(ByteArrayInputStream(out.toByteArray()), dest) }
        assertFalse(File(root, "escape.txt").exists())
    }

    // a full digest added on the fast path must turn this red (bootstrap-only counters stay 0).
    @Test
    fun fastPathPerformsNoDigestEvenWhenCalledRepeatedly() {
        val p = pkg("0.53.48")
        store(p, release = true).bootstrapIfNeeded()
        val s = store(p, release = true)
        repeat(3) { s.bootstrapIfNeeded() }
        assertEquals("fast", s.lastPath)
        assertEquals(listOf(0, 0, 0, 0), counts(s))
    }

    // the trust cache key is the v2 fingerprint; a same-size rewrite with the mtime restored is never served
    // from the cache (ctime changes), so trust is recomputed and refused.
    @Test
    fun trustCacheMissesOnSameSizeRewriteWithRestoredMtime() {
        val p = pkg("0.53.48")
        val s = store(p, release = false)
        s.bootstrapIfNeeded()
        assertEquals(p.sha, s.verifiedActiveZipSha256())
        val before = s.counters.fullDigest
        assertEquals(p.sha, s.verifiedActiveZipSha256()) // cached: no new digest
        assertEquals(before, s.counters.fullDigest)
        val js = File(root, "active/static/js/main.js")
        val mtime = Files.getLastModifiedTime(js.toPath())
        Thread.sleep(20)
        js.writeText("X".repeat(js.length().toInt()))
        Files.setLastModifiedTime(js.toPath(), mtime)
        assertNull(s.verifiedActiveZipSha256())
        assertEquals(before + 1, s.counters.fullDigest)
    }

    // a trust mismatch on a bundle selected as verified notifies the shell (page down + Retry) exactly once,
    // deletes the record; Retry's bootstrap is a full pass that repairs active/ and restores trust.
    @Test
    fun trustMismatchNotifiesShellOnceAndRetryRepairs() {
        val p = pkg("0.53.48")
        store(p, release = false).bootstrapIfNeeded()
        var notified = 0
        EmbeddedPwaBundleStore.trustMismatchListener = { notified++ }
        try {
            val s = store(p, release = false)
            s.bootstrapIfNeeded()
            assertEquals("fast", s.lastPath)
            File(root, "active/static/js/main.js").writeText("// changed after start")
            assertNull(s.verifiedActiveZipSha256())
            assertNull(s.verifiedActiveZipSha256())
            assertEquals(1, notified)
            assertFalse(recordFile().exists())
            val retry = store(p, release = false) // MainActivity.retryEmbeddedBootstrap → bootstrapIfNeeded
            retry.bootstrapIfNeeded()
            assertEquals("full", retry.lastPath)
            assertEquals(1, retry.counters.unpack)
            assertEquals(p.sha, retry.verifiedActiveZipSha256())
            assertEquals(1, notified)
        } finally {
            EmbeddedPwaBundleStore.trustMismatchListener = null
        }
    }

    // an active kept without trust (e.g. APK ZIP unreadable) is not a mismatch: no page take-down loop.
    @Test
    fun untrustedKeptActiveDoesNotTriggerTakeDown() {
        val p = pkg("0.53.48")
        store(p, release = true).bootstrapIfNeeded()
        File(root, "active/static/extra.txt").writeText("not the embedded content")
        var notified = 0
        EmbeddedPwaBundleStore.trustMismatchListener = { notified++ }
        try {
            val s = store(p, release = true, opener = { throw java.io.IOException("unreadable") })
            s.bootstrapIfNeeded() // keeps the complete active, no record, no trust
            assertNull(s.verifiedActiveZipSha256())
            assertEquals(0, notified)
        } finally {
            EmbeddedPwaBundleStore.trustMismatchListener = null
        }
    }

    // process-wide full digests on a fast-path start: bootstrap 0, then exactly 1 for trust (the warm-up).
    @Test
    fun processWideDigestCountOnFastPathIsOne() {
        val p = pkg("0.53.48")
        store(p, release = true).bootstrapIfNeeded()
        val before = EmbeddedPwaBundleStore.processFullDigests
        val s = store(p, release = true)
        s.bootstrapIfNeeded()
        assertEquals(before, EmbeddedPwaBundleStore.processFullDigests)
        s.verifiedActiveZipSha256()
        s.verifiedActiveZipSha256()
        assertEquals(before + 1, EmbeddedPwaBundleStore.processFullDigests)
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
            files.forEach { (name, body) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(body.toByteArray())
                zip.closeEntry()
            }
        }
        return OtaTestSigner.canonicalize(out.toByteArray())
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
