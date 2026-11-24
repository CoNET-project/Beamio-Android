package com.beamio.app.embedded

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * The shell serves the PWA from the asset-loader root. A web build (homepage
 * `/app`) loads `/app/static/...` and shows only a broken icon, so the store
 * must never let such a bundle replace `active/`.
 */
class EmbeddedPwaBundleStoreTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var root: File
    private var bundledZip: ByteArray? = null
    private val hashStore = object : ActivatedAssetHashStore {
        var value: String? = null
        override fun get(): String? = value
        override fun set(value: String) {
            this.value = value
        }
    }

    @Before
    fun setUp() {
        root = tmp.newFolder("silentpass_pwa")
    }

    private fun newStore() = EmbeddedPwaBundleStore(
        rootDir = root,
        openBundledZip = { ByteArrayInputStream(checkNotNull(bundledZip) { "no bundled zip" }) },
        activatedAssetHash = hashStore,
    )

    /** Release store with the test signing key; [embeddedVer] is the reference when active/ is not verified. */
    private fun otaStore(embeddedVer: String = "0.52.927") = EmbeddedPwaBundleStore(
        rootDir = root,
        openBundledZip = { ByteArrayInputStream(checkNotNull(bundledZip) { "no bundled zip" }) },
        activatedAssetHash = hashStore,
        embeddedZipVer = embeddedVer,
        otaKeys = OtaTestSigner.keys,
    )

    // index.html check

    @Test
    fun rootPathIndexIsEmbeddedBuild() {
        assertTrue(EmbeddedPwaBundleStore.indexHtmlUsesEmbeddedAssetPaths(indexHtml("")))
    }

    @Test
    fun appPathIndexIsWebBuild() {
        assertFalse(EmbeddedPwaBundleStore.indexHtmlUsesEmbeddedAssetPaths(indexHtml("/app")))
    }

    @Test
    fun webBuildDetectedInAnyQuoting() {
        listOf(
            """<script src='/app/static/js/main.js'></script>""",
            """<script src=/app/static/js/main.js></script>""",
            """<SCRIPT SRC="/app/static/js/main.js"></SCRIPT>""",
            """<link href = "/app/static/css/main.css" rel="stylesheet">""",
        ).forEach { html ->
            assertFalse(html, EmbeddedPwaBundleStore.indexHtmlUsesEmbeddedAssetPaths(html))
        }
    }

    @Test
    fun appInsideOtherTextIsNotAWebBuild() {
        val html = """<meta content='{"url":"https://beamio.app/app/"}'/><a href="https://beamio.app/app/">x</a>""" +
            """<script src="/static/js/app/main.js"></script>"""
        assertTrue(EmbeddedPwaBundleStore.indexHtmlUsesEmbeddedAssetPaths(html))
    }

    // bundled zip (bootstrap)

    @Test
    fun bootstrapKeepsActiveWhenBundledZipIsWebBuild() {
        writeBundle(File(root, "active"), assetPrefix = "", version = "0.52.927")
        bundledZip = zipOf(assetPrefix = "/app", version = "9.9.9") // newer, but a web build
        val store = newStore()

        store.bootstrapIfNeeded()

        assertEquals("0.52.927", store.activeVersion())
        assertActiveIsEmbedded(store)
        assertFalse(File(root, "bundled").exists())
        assertNull(hashStore.value)
    }

    @Test
    fun bootstrapThrowsWhenOnlyCandidateIsWebBuild() {
        bundledZip = zipOf(assetPrefix = "/app", version = "9.9.9")
        val store = newStore()

        assertThrows(IllegalStateException::class.java) { store.bootstrapIfNeeded() }
        assertFalse(File(store.activeDir, "index.html").exists())
    }

    @Test
    fun bootstrapInstallsEmbeddedZipOnFreshInstall() {
        bundledZip = zipOf(assetPrefix = "", version = "9.9.9")
        val store = newStore()

        store.bootstrapIfNeeded()

        assertEquals("9.9.9", store.activeVersion())
        assertActiveIsEmbedded(store)
    }

    @Test
    fun bootstrapReplacesWebBuildActiveWithEmbeddedZip() {
        // Same semver and same zip hash as last time: only the path check triggers the repair.
        writeBundle(File(root, "active"), assetPrefix = "/app", version = "9.9.9")
        bundledZip = zipOf(assetPrefix = "", version = "9.9.9")
        hashStore.value = sha256(bundledZip!!)
        val store = newStore()

        store.bootstrapIfNeeded()

        assertActiveIsEmbedded(store)
    }

    @Test
    fun bootstrapDiscardsStagedWebBuild() {
        writeBundle(File(root, "active"), assetPrefix = "", version = "0.52.927")
        // Staging left on disk by an older shell that had no check.
        writeBundle(File(root, "staging"), assetPrefix = "/app", version = "9.9.9")
        bundledZip = zipOf(assetPrefix = "", version = "0.52.927")
        hashStore.value = sha256(bundledZip!!)
        val store = newStore()

        store.bootstrapIfNeeded()

        assertEquals("0.52.927", store.activeVersion())
        assertActiveIsEmbedded(store)
        assertFalse(store.stagingDir.exists())
    }

    // OTA download / staged update

    @Test
    fun otaDownloadOfWebBuildIsRejected() {
        writeBundle(File(root, "active"), assetPrefix = "", version = "0.52.927")
        val store = otaStore()
        val zip = tmp.newFile("web.zip").apply { writeBytes(zipOf(assetPrefix = "/app", version = "9.9.9")) }

        assertThrows(IllegalStateException::class.java) { OtaTestSigner.stage(store, zip, "9.9.9") }

        assertFalse(store.stagingDir.exists())
        assertNull(store.pendingUpdateVersion())
        assertEquals("0.52.927", store.activeVersion())
    }

    @Test
    fun otaDownloadOfEmbeddedBuildIsStagedAndPromoted() {
        writeBundle(File(root, "active"), assetPrefix = "", version = "0.52.927")
        val store = otaStore()
        val zip = tmp.newFile("ok.zip").apply { writeBytes(zipOf(assetPrefix = "", version = "9.9.9")) }

        OtaTestSigner.stage(store, zip, "9.9.9")
        assertEquals("9.9.9", store.pendingUpdateVersion())

        store.promoteStagingToActive()
        assertEquals("9.9.9", store.activeVersion())
        assertActiveIsEmbedded(store)
    }

    @Test
    fun stagedWebBuildIsNotPromoted() {
        writeBundle(File(root, "active"), assetPrefix = "", version = "0.52.927")
        val store = newStore()
        writeBundle(store.stagingDir, assetPrefix = "/app", version = "9.9.9")

        assertNull(store.pendingUpdateVersion())
        assertThrows(IllegalStateException::class.java) { store.promoteStagingToActive() }

        assertEquals("0.52.927", store.activeVersion())
        assertActiveIsEmbedded(store)
        assertFalse(store.stagingDir.exists())
    }

    // Store build (remotePwaUpdate = false): the bundled zip is the only source.
    // Cases follow the store-build OTA plan A (2026-11-12): P1, N1, N2, N3, N6
    // and same-sha-gate.md (S1, S3, S4, S8). Each case prints one evidence line with hashes.

    private val bundledVersion = "0.52.935"
    private val higherVersion = "0.52.999"

    /**: the corruption hook lives here, in the test source set only (not in the app's classes). */
    private class TestableBundleStore(
        rootDir: File, openBundledZip: () -> java.io.InputStream, activatedAssetHash: ActivatedAssetHashStore,
        remotePwaUpdate: Boolean, expectedZipSha256: String?,
    ) : EmbeddedPwaBundleStore(rootDir, openBundledZip, activatedAssetHash, remotePwaUpdate, expectedZipSha256) {
        @Volatile var afterStoreReplaceForTest: ((File) -> Unit)? = null
        override fun onStoreReplaced(activeDir: File) { afterStoreReplaceForTest?.invoke(activeDir) }
    }

    private fun storeStore(expected: String? = sha256(checkNotNull(bundledZip))) = TestableBundleStore(
        rootDir = root,
        openBundledZip = { ByteArrayInputStream(checkNotNull(bundledZip) { "no bundled zip" }) },
        activatedAssetHash = hashStore,
        remotePwaUpdate = false,
        expectedZipSha256 = expected,
    )

    /** Content digest of the bundled zip, computed independently (extract to a temp dir). */
    private fun bundledDigest(store: EmbeddedPwaBundleStore): String {
        val dir = tmp.newFolder()
        EmbeddedPwaZip.unzip(ByteArrayInputStream(checkNotNull(bundledZip)), dir)
        return store.contentDigest(dir)
    }

    private fun evidence(case: String, store: EmbeddedPwaBundleStore, extra: String = "") {
        val marker = File(store.activeDir, EmbeddedPwaBundleStore.LOADED_SHA_MARKER)
        println(
            "EVIDENCE $case zipSha256=${sha256(checkNotNull(bundledZip))} " +
                "activeVer=${store.activeVersion()} activeDigest=${if (store.activeDir.isDirectory) store.contentDigest(store.activeDir) else "none"} " +
                "marker=${if (marker.isFile) marker.readText() else "none"} staging=${store.stagingDir.exists()} " +
                "backup=${store.backupDir.exists()} $extra",
        )
    }

    private fun assertActiveIsBundled(store: EmbeddedPwaBundleStore) {
        assertEquals(bundledVersion, store.activeVersion())
        assertEquals(bundledDigest(store), store.contentDigest(store.activeDir))
        assertEquals(sha256(checkNotNull(bundledZip)), File(store.activeDir, EmbeddedPwaBundleStore.LOADED_SHA_MARKER).readText())
        assertActiveIsEmbedded(store)
    }

    @Test
    fun storeP1S1FreshInstallLoadsBundledZip() {
        bundledZip = zipOf(assetPrefix = "", version = bundledVersion)
        val store = storeStore()

        store.bootstrapIfNeeded()

        assertActiveIsBundled(store)
        assertEquals(sha256(bundledZip!!), hashStore.value)
        evidence("P1/S1", store)
    }

    @Test
    fun storeN2PreplacedHigherActiveIsReplacedEvenWithForgedMarker() {
        bundledZip = zipOf(assetPrefix = "", version = bundledVersion)
        val active = File(root, "active")
        writeBundle(active, assetPrefix = "", version = higherVersion)
        File(active, "static/js").mkdirs()
        File(active, "static/js/main.js").writeText("// remote code that must not run")
        // Forged marker claiming to be the bundled zip: must not be trusted.
        File(active, EmbeddedPwaBundleStore.LOADED_SHA_MARKER).writeText(sha256(bundledZip!!))
        val store = storeStore()

        store.bootstrapIfNeeded()

        assertActiveIsBundled(store)
        assertEquals("// fixture", File(store.activeDir, "static/js/main.js").readText())
        evidence("N2", store, "preplacedVer=$higherVersion forgedMarker=true")
    }

    @Test
    fun storeN3S4StagedBundleIsNeverPromotedOrLoaded() {
        bundledZip = zipOf(assetPrefix = "", version = bundledVersion)
        val store = storeStore()
        store.bootstrapIfNeeded()
        val before = store.contentDigest(store.activeDir)
        writeBundle(store.stagingDir, assetPrefix = "", version = higherVersion)

        assertNull(store.pendingUpdateVersion())
        assertThrows(IllegalStateException::class.java) { store.promoteStagingToActive() }
        val zip = tmp.newFile("remote.zip").apply { writeBytes(zipOf(assetPrefix = "", version = higherVersion)) }
        assertThrows(IllegalStateException::class.java) { store.installDownloadToStaging(OtaManifestCheck(OtaVerdict.OK), zip) }
        assertEquals(before, store.contentDigest(store.activeDir))

        store.bootstrapIfNeeded() // next cold start

        assertFalse(store.stagingDir.exists())
        assertActiveIsBundled(store)
        assertEquals(before, store.contentDigest(store.activeDir))
        evidence("N3/S4", store, "stagedVer=$higherVersion")
    }

    @Test
    fun storeN6WebBuildActiveIsReplaced() {
        bundledZip = zipOf(assetPrefix = "", version = bundledVersion)
        writeBundle(File(root, "active"), assetPrefix = "/app", version = bundledVersion)
        val store = storeStore()

        store.bootstrapIfNeeded()

        assertActiveIsBundled(store)
        evidence("N6", store, "preplaced=/app web build")
    }

    @Test
    fun storeS3SameVersionDifferentBytesIsReplaced() {
        bundledZip = zipOf(assetPrefix = "", version = bundledVersion)
        val active = File(root, "active")
        writeBundle(active, assetPrefix = "", version = bundledVersion)
        File(active, "static/js").mkdirs()
        File(active, "static/js/main.js").writeText("// same version number, different bytes")
        hashStore.value = sha256(bundledZip!!) // the old "last activated asset" check would have kept it
        val store = storeStore()

        store.bootstrapIfNeeded()

        assertActiveIsBundled(store)
        evidence("S3", store, "preplacedSameVer=$bundledVersion")
    }

    @Test
    fun storeS3UnchangedActiveIsKeptWithoutReplace() {
        bundledZip = zipOf(assetPrefix = "", version = bundledVersion)
        val store = storeStore()
        store.bootstrapIfNeeded()
        val marker = File(store.activeDir, "index.html").lastModified()

        store.bootstrapIfNeeded() // second cold start, nothing changed

        assertActiveIsBundled(store)
        assertEquals(marker, File(store.activeDir, "index.html").lastModified())
        evidence("S3-kept", store)
    }

    @Test
    fun storeS8BundledZipNotMatchingBuildShaLoadsNothing() {
        bundledZip = zipOf(assetPrefix = "", version = bundledVersion)
        writeBundle(File(root, "active"), assetPrefix = "", version = "0.52.930") // an old valid active
        val store = storeStore(expected = "0".repeat(64))

        assertThrows(EmbeddedPwaBundleStore.BundleIntegrityException::class.java) { store.bootstrapIfNeeded() }

        assertFalse(store.activeDir.exists()) // no fallback to the old active/
        println("EVIDENCE S8-zip zipSha256=${sha256(bundledZip!!)} expected=${"0".repeat(64)} activeExists=${store.activeDir.exists()}")
    }

    /**: no full 64-hex digest in shell logs or log-bound messages (T-131 LS-G1); first 8 digits only. */
    @Test
    fun noFullLengthDigestInBootstrapMessages() {
        bundledZip = zipOf(assetPrefix = "", version = bundledVersion)
        val store = storeStore(expected = "0".repeat(64))
        val e = assertThrows(EmbeddedPwaBundleStore.BundleIntegrityException::class.java) { store.bootstrapIfNeeded() }
        val hex64 = Regex("[0-9a-fA-F]{64}")
        assertFalse("message: ${e.message}", hex64.containsMatchIn(e.message ?: ""))
        assertTrue(e.message!!.contains(sha256(bundledZip!!).take(8) + "…"))
        assertEquals("abcdef01…", shortDigest("abcdef01" + "2".repeat(56)))
        assertEquals("null", shortDigest(null))
        // Source: every log or exception string in the bundle store passes digests through shortDigest/shortEntry.
        val src = File("src/main/java/com/beamio/app/embedded/EmbeddedPwaBundleStore.kt").readText()
        for (v in listOf("zipSha", "expectedZipSha256", "bundledDigest", "loadedDigest", "activeDigest")) {
            assertFalse("raw \$$v in a string", Regex("\"[^\"\\n]*\\$$v\\b").containsMatchIn(src))
            assertFalse("raw \${$v} in a string", Regex("\"[^\"\\n]*\\$\\{$v[ }]").containsMatchIn(src))
        }
    }

    /** The replacement-mismatch message (store bootstrap, second exception) at runtime. */
    @Test
    fun replacementMismatchMessageHasNoFullDigest() {
        bundledZip = zipOf(assetPrefix = "", version = bundledVersion)
        val store = storeStore()
        store.afterStoreReplaceForTest = { active -> File(active, "index.html").appendText("<!-- changed after replace -->") }
        val e = assertThrows(EmbeddedPwaBundleStore.BundleIntegrityException::class.java) { store.bootstrapIfNeeded() }
        val msg = e.message ?: ""
        assertTrue(msg, msg.contains("after replacement"))
        assertFalse("message: $msg", Regex("[0-9a-fA-F]{64}").containsMatchIn(msg))
        // Both content digests and the differing entries ("index.html sha8…") are cut to 8 hex digits.
        assertTrue(msg, Regex("content [0-9a-f]{8}… != bundled [0-9a-f]{8}…").containsMatchIn(msg))
        assertTrue(msg, Regex("index\\.html [0-9a-f]{8}…").containsMatchIn(msg))
        assertFalse(store.activeDir.exists())
    }

    @Test
    fun storeS8LargeZipShaCoversWholeFile() {
        // Found on the emulator: a real 17 MB zip has a central directory far past the unzip read-ahead,
        // so hashing only what unzip reads gave a prefix SHA and the store build loaded nothing.
        // This zip's central directory alone is larger than the 8 KB buffer; the stream also returns
        // short reads like AssetInputStream.
        bundledZip = zipOf(assetPrefix = "", version = bundledVersion, padding = 400)
        val full = checkNotNull(bundledZip)
        val store = EmbeddedPwaBundleStore(
            rootDir = root,
            openBundledZip = {
                object : java.io.FilterInputStream(ByteArrayInputStream(full)) {
                    override fun read(b: ByteArray, off: Int, len: Int) = super.read(b, off, minOf(len, 1000))
                }
            },
            activatedAssetHash = hashStore,
            remotePwaUpdate = false,
            expectedZipSha256 = sha256(full),
        )

        store.bootstrapIfNeeded()

        assertActiveIsBundled(store)
        evidence("S8-large", store, "zipBytes=${full.size}")
    }

    @Test
    fun storeTwoInstancesNeverBootstrapAtTheSameTime() {
        // Found on the emulator: a config change relaunched MainActivity during startup, the second
        // onCreate made a new host and store, and the two bootstraps ran together on the same
        // silentpass_pwa/ directory (deleting and unzipping each other's files). The store build then
        // loaded nothing. Two stores on one directory must take turns.
        bundledZip = zipOf(assetPrefix = "", version = bundledVersion)
        val first = storeStore()
        val second = storeStore()
        var secondWaited = false
        var secondError: Throwable? = null
        first.afterStoreReplaceForTest = {
            val t = Thread { try { second.bootstrapIfNeeded() } catch (e: Throwable) { secondError = e } }
            t.start()
            t.join(500)
            secondWaited = t.isAlive // still blocked while the first bootstrap holds the directory
            first.afterStoreReplaceForTest = null
            second.afterStoreReplaceForTest = null
            secondThread = t
        }

        first.bootstrapIfNeeded()
        secondThread?.join(5000)

        assertTrue("second bootstrap ran inside the first one's critical section", secondWaited)
        assertNull(secondError)
        assertActiveIsBundled(second)
        evidence("S9-two-instances", second, "secondWaited=$secondWaited")
    }

    private var secondThread: Thread? = null

    @Test
    fun storeS8NoExpectedShaLoadsNothing() {
        // Lock missing at build time -> BuildConfig.PWA_ZIP_SHA256 blank -> fail closed, no fallback.
        bundledZip = zipOf(assetPrefix = "", version = bundledVersion)
        writeBundle(File(root, "active"), assetPrefix = "", version = "0.52.930")
        val store = storeStore(expected = null)

        assertThrows(EmbeddedPwaBundleStore.BundleIntegrityException::class.java) { store.bootstrapIfNeeded() }

        assertFalse(store.activeDir.exists())
        println("EVIDENCE S8-noexpected zipSha256=${sha256(bundledZip!!)} expected=null activeExists=${store.activeDir.exists()}")
    }

    @Test
    fun storeS8ActiveStillDifferentAfterReplacementLoadsNothing() {
        bundledZip = zipOf(assetPrefix = "", version = bundledVersion)
        writeBundle(File(root, "active"), assetPrefix = "", version = higherVersion)
        val store = storeStore()
        store.afterStoreReplaceForTest = { dir -> File(dir, "static/js/main.js").writeText("// corrupted on disk") }

        assertThrows(EmbeddedPwaBundleStore.BundleIntegrityException::class.java) { store.bootstrapIfNeeded() }

        assertFalse(store.activeDir.exists())
        println("EVIDENCE S8-replace zipSha256=${sha256(bundledZip!!)} activeExists=${store.activeDir.exists()}")
    }

    @Test
    fun stagedNotNewerThanActiveIsDiscardedAndActiveIsUnchanged() {
        for (stagedVer in listOf("0.52.932", "0.52.931")) {
            root.deleteRecursively()
            root.mkdirs()
            writeBundle(File(root, "active"), assetPrefix = "", version = "0.52.932")
            val store = newStore()
            writeBundle(store.stagingDir, assetPrefix = "", version = stagedVer)

            assertThrows(IllegalStateException::class.java) { store.promoteStagingToActive() }

            assertEquals("0.52.932", store.activeVersion())
            assertFalse(stagedVer, store.stagingDir.exists())
            assertNull(store.pendingUpdateVersion())
        }
    }

    @Test
    fun stagedStrictlyNewerThanActiveIsPromoted() {
        // only a staged bundle with a verified-download record (installDownloadToStaging) is promoted.
        writeBundle(File(root, "active"), assetPrefix = "", version = "0.52.932")
        val store = otaStore(embeddedVer = "0.52.932")
        val zip = tmp.newFile("ota-933.zip").apply { writeBytes(zipOf(assetPrefix = "", version = "0.52.933")) }
        OtaTestSigner.stage(store, zip, "0.52.933")

        store.promoteStagingToActive()

        assertEquals("0.52.933", store.activeVersion())
        assertActiveIsEmbedded(store)
    }

    @Test
    fun stagedStrictlyNewerWithoutVerifiedRecordIsRefusedAndDiscarded() {
        // a staging written outside installDownloadToStaging (no ota-verified record) is never promoted.
        writeBundle(File(root, "active"), assetPrefix = "", version = "0.52.932")
        val store = newStore()
        writeBundle(store.stagingDir, assetPrefix = "", version = "0.52.933")

        val error = assertThrows(IllegalStateException::class.java) { store.promoteStagingToActive() }

        assertEquals("staged_not_verified", error.message)
        assertEquals("0.52.932", store.activeVersion())
        assertFalse(store.stagingDir.exists())
    }

    // helpers

    // ----------: consumer black screen (embedded ZIP read failure with a valid active, missing JS) ----------

    private val failingZip: () -> java.io.InputStream = { throw java.io.IOException("injected: asset read failed") }

    private fun remoteStore(open: () -> java.io.InputStream) = EmbeddedPwaBundleStore(root, open, hashStore, remotePwaUpdate = true)

    private fun storeStoreWith(open: () -> java.io.InputStream, expected: String?) =
        TestableBundleStore(root, open, hashStore, remotePwaUpdate = false, expectedZipSha256 = expected)

    private fun snapshot(dir: File) = dir.walkTopDown().filter { it.isFile }.associate { it.relativeTo(dir).path to it.readBytes().contentHashCode() }

    @Test
    fun remoteZipUnreadableKeepsACompleteActiveAndDeletesNothing() {
        writeBundle(File(root, "active"), "", "0.53.0")
        val before = snapshot(File(root, "active"))
        remoteStore(failingZip).bootstrapIfNeeded() // no throw: the local UI is loadable
        assertEquals(before, snapshot(File(root, "active")))
        assertFalse(File(root, "bundled").exists())
        println("EVIDENCE remote zip unreadable + complete active -> kept, files=${before.size}")
    }

    @Test
    fun remoteZipUnreadableWithoutActiveOrWithIncompleteActiveFails() {
        assertThrows(IllegalStateException::class.java) { remoteStore(failingZip).bootstrapIfNeeded() }
        val active = File(root, "active").apply { mkdirs() }
        File(active, "index.html").writeText(indexHtml("")) // names /static/js/main.js, which is missing
        assertThrows(IllegalStateException::class.java) { remoteStore(failingZip).bootstrapIfNeeded() }
        assertTrue("incomplete active is not deleted", File(active, "index.html").isFile)
    }

    @Test
    fun remoteActiveMissingJsIsReplacedByTheReadableBundledZip() {
        val active = File(root, "active").apply { mkdirs() }
        File(active, "index.html").writeText(indexHtml(""))
        File(active, "update.json").writeText(updateJson("0.53.0"))
        hashStore.value = null
        bundledZip = zipOf("", "0.53.0")
        newStore().bootstrapIfNeeded()
        assertTrue("main.js restored", File(root, "active/static/js/main.js").isFile)
    }

    /**
     * The black-screen case of the old rule: the APK zip is unchanged since the last activation (same SHA), so the old code kept
     * any active/ that had index.html, even one whose JS is missing. It must be replaced by the bundled zip.
     */
    @Test
    fun remoteActiveMissingJsIsReplacedEvenWhenTheZipIsUnchanged() {
        bundledZip = zipOf("", "0.53.0")
        hashStore.value = sha256(checkNotNull(bundledZip)) // nothing changed since the last activation
        val active = File(root, "active").apply { mkdirs() }
        File(active, "index.html").writeText(indexHtml(""))
        File(active, "update.json").writeText(updateJson("0.53.0"))
        newStore().bootstrapIfNeeded()
        assertTrue("main.js restored (old rule kept the blank active)", File(root, "active/static/js/main.js").isFile)
    }

    @Test
    fun storeZipUnreadableLoadsActiveOnlyWhenVerifiedAsThisApksContent() {
        bundledZip = zipOf("", "0.53.0")
        val sha = sha256(checkNotNull(bundledZip))
        storeStore(sha).bootstrapIfNeeded() // normal start writes both markers
        val active = File(root, "active")
        assertTrue(File(active, EmbeddedPwaBundleStore.LOADED_CONTENT_MARKER).isFile)
        val before = snapshot(active)
        storeStoreWith(failingZip, sha).bootstrapIfNeeded() // verified: loads, nothing deleted
        assertEquals(before, snapshot(active))
        println("EVIDENCE store zip unreadable + verified active -> loaded, files=${before.size}")
    }

    @Test
    fun storeZipUnreadableRefusesAnUnverifiedActiveButDeletesNothing() {
        bundledZip = zipOf("", "0.53.0")
        val sha = sha256(checkNotNull(bundledZip))
        storeStore(sha).bootstrapIfNeeded()
        val active = File(root, "active")
        // a) a script removed
        File(active, "static/js/main.js").delete()
        assertThrows(EmbeddedPwaBundleStore.BundleIntegrityException::class.java) { storeStoreWith(failingZip, sha).bootstrapIfNeeded() }
        assertTrue("active kept on disk", File(active, "index.html").isFile)
        // b) content changed, scripts present
        File(active, "static/js/main.js").writeText("// fixture")
        File(active, "update.json").writeText(updateJson("9.9.9"))
        assertThrows(EmbeddedPwaBundleStore.BundleIntegrityException::class.java) { storeStoreWith(failingZip, sha).bootstrapIfNeeded() }
        // c) restored content, but a different expected zip (a new APK whose zip cannot be read)
        File(active, "update.json").writeText(updateJson("0.53.0"))
        storeStoreWith(failingZip, sha).bootstrapIfNeeded() // same APK: verified again
        assertThrows(EmbeddedPwaBundleStore.BundleIntegrityException::class.java) { storeStoreWith(failingZip, "0".repeat(64)).bootstrapIfNeeded() }
        assertTrue(File(active, "index.html").isFile)
    }

    @Test
    fun storeZipUnreadableWithNoActiveFails() {
        assertThrows(EmbeddedPwaBundleStore.BundleIntegrityException::class.java) { storeStoreWith(failingZip, "0".repeat(64)).bootstrapIfNeeded() }
    }

    @Test
    fun missingScriptsIgnoresAbsoluteUrlsAndQueries() {
        val d = tmp.newFolder()
        File(d, "index.html").writeText(
            """<script src="https://cdn.example/x.js"></script><script src="//cdn/y.js"></script>""" +
                """<script defer src="/static/js/a.js?v=1"></script><script src='static/js/b.js#h'></script>""",
        )
        val store = newStore()
        assertEquals(listOf("static/js/a.js", "static/js/b.js"), store.missingScripts(d))
        File(d, "static/js").mkdirs(); File(d, "static/js/a.js").writeText("a"); File(d, "static/js/b.js").writeText("b")
        assertTrue(store.missingScripts(d).isEmpty())
        assertTrue(store.hasCompleteBundle(d))
    }

    /** Source guards: the unavailable page offers Retry, Retry reruns the local bootstrap only, and nothing goes to the remote site. */
    @Test
    fun unavailablePageHasRetryAndNoRemoteFallback() {
        val main = File("src/main/java/com/beamio/app/MainActivity.kt").readText()
        assertTrue(main.contains("EMBEDDED_RETRY_URL"))
        assertTrue(main.contains("Retry / 重试"))
        assertTrue(main.contains("Your wallet and data were not deleted."))
        val retry = main.substring(main.indexOf("private fun retryEmbeddedBootstrap"), main.indexOf("private fun retryEmbeddedBootstrap") + 1500)
        assertTrue(retry.contains("bootstrapExecutor.execute"))
        assertTrue(retry.contains("embeddedPwaHost.bootstrapIfNeeded()"))
        assertTrue(retry.contains("mountEmbeddedWebView(jsBridge)"))
        assertFalse(retry.contains("deleteRecursively") || retry.contains("loadUrl(\"https://beamio.app"))
        assertTrue(main.contains("remote fallback disabled"))
        val store = File("src/main/java/com/beamio/app/embedded/EmbeddedPwaBundleStore.kt").readText()
        assertFalse("bootstrap does no network", store.contains("HttpURLConnection") || store.contains("URL("))
    }

    /**: the bootstrap fault hook exists only in the debug source set; release and store compile a pass-through. */
    @Test
    fun faultHookIsDebugOnly() {
        val debug = File("src/debug/java/com/beamio/app/qa/QaBootstrapFaults.kt").readText()
        val stub = File("src/qaGuardStub/java/com/beamio/app/qa/QaBootstrapFaults.kt").readText()
        assertTrue(debug.contains("beamio-qa-fault-bundled-zip") && debug.contains("throw IOException"))
        assertFalse("stub has no flag and never throws", stub.contains("beamio-qa-fault") || stub.contains("throw"))
        assertTrue(stub.contains("= open"))
        val gradle = File("build.gradle.kts").readText()
        assertTrue(gradle.contains("getByName(\"release\").let { it.java.directories.add(\"src/qaGuardStub/java\")"))
        assertTrue(gradle.contains("maybeCreate(\"store\").let { it.java.directories.add(\"src/qaGuardStub/java\")"))
    }

    // Spec r3np §25.52Y.38 item 2 (b)(c)(g): the walletCredential trust record (in memory, set by bootstrap only).

    @Test
    fun trustRecordStoreBuildMatchesUntilActiveChanges() {
        bundledZip = zipOf("", "1.0.0", padding = 3)
        val sha = sha256(bundledZip!!)
        val store = storeStore()
        store.bootstrapIfNeeded()
        assertEquals(sha, store.verifiedActiveZipSha256())
        assertEquals(sha, EmbeddedPwaBundleStore.currentVerifiedActiveZipSha256())
        File(store.activeDir, "static/js/main.js").appendText("// changed")
        assertNull(store.verifiedActiveZipSha256())
    }

    @Test
    fun trustRecordRemoteBuildHashesEveryByteOfTheZip() {
        val zip = zipOf("", "1.0.0", padding = 3)
        val store = EmbeddedPwaBundleStore(root, { ByteArrayInputStream(zip) }, hashStore, remotePwaUpdate = true, expectedZipSha256 = sha256(zip))
        store.bootstrapIfNeeded()
        assertEquals(sha256(zip), store.verifiedActiveZipSha256())
        assertTrue(hashStore.value != null)
    }

    @Test
    fun trustRecordAbsentWhenLockDiffersOrIsMissing() {
        val zip = zipOf("", "1.0.0")
        for (expected in listOf(null, "0".repeat(64))) {
            root.deleteRecursively(); root.mkdirs()
            val store = EmbeddedPwaBundleStore(root, { ByteArrayInputStream(zip) }, hashStore, remotePwaUpdate = true, expectedZipSha256 = expected)
            store.bootstrapIfNeeded()
            assertNull("expected=$expected", store.verifiedActiveZipSha256())
        }
    }

    @Test
    fun trustRecordAbsentWhenANewerDownloadedBundleIsActive() {
        // a higher-version active with no verified-download record cannot be
        // verified by this shell. Markers in active/ are not a record, so it is repaired with the embedded ZIP rather
        // than kept, and trust is only that of the embedded ZIP.
        val zip = zipOf("", "1.0.0")
        val store = EmbeddedPwaBundleStore(root, { ByteArrayInputStream(zip) }, hashStore, remotePwaUpdate = true, expectedZipSha256 = sha256(zip))
        writeBundle(store.activeDir, "", "2.0.0")
        File(store.activeDir, EmbeddedPwaBundleStore.LOADED_SHA_MARKER).writeText(sha256(zip))
        store.bootstrapIfNeeded()
        assertEquals("1.0.0", store.activeVersion())
        assertEquals(sha256(zip), store.verifiedActiveZipSha256())
    }

    @Test
    fun trustRecordAbsentWhenTheZipCannotBeRead() {
        val store = EmbeddedPwaBundleStore(root, { throw java.io.IOException("unreadable") }, hashStore, remotePwaUpdate = true, expectedZipSha256 = "a".repeat(64))
        writeBundle(store.activeDir, "", "1.0.0")
        store.bootstrapIfNeeded()
        assertNull(store.verifiedActiveZipSha256())
    }

    // r3oj §25.52Y.38 item 2 (h): downloaded bundles are trusted per package, against the published zip_sha256.

    @Test
    fun otaDownloadIsStagedOnlyWithAValidSignature() {
        writeBundle(File(root, "active"), assetPrefix = "", version = "0.52.927")
        val store = otaStore()
        val bytes = zipOf(assetPrefix = "", version = "9.9.9")
        val zip = tmp.newFile("ota.zip").apply { writeBytes(bytes) }
        val p = OtaTestSigner.payload(bytes, "9.9.9")
        val bad = listOf(
            OtaTestSigner.updateJson(p, null, "9.9.9"),                                       // no signature
            OtaTestSigner.updateJson(p, OtaTestSigner.sign(p, OtaTestSigner.untrusted), "9.9.9"), // unknown key
            OtaTestSigner.updateJson(p, OtaTestSigner.sign(p, domain = "beamio-pwa-ota/v1\n"), "9.9.9"), // v1 domain
            OtaTestSigner.updateJson(p, OtaTestSigner.sign(p), "9.9.8"),                     // outer/payload mismatch
            OtaTestSigner.payload(bytes, "9.9.9", sha256 = "0".repeat(64)).let { q -> OtaTestSigner.updateJson(q, OtaTestSigner.sign(q), "9.9.9") }, // hash
            OtaTestSigner.payload(bytes, "9.9.9", contentDigest = "1".repeat(64)).let { q -> OtaTestSigner.updateJson(q, OtaTestSigner.sign(q), "9.9.9") }, // content
        )
        for (doc in bad) {
            assertThrows(IllegalStateException::class.java) {
                store.installDownloadToStaging(store.otaVerifier.verifyManifest(doc, store.selectedVerifiedVersion()), zip)
            }
            assertFalse(store.stagingDir.exists()); assertNull(store.pendingUpdateVersion())
        }
        // a top-level zip_sha256 alone is never trust
        val unsignedWithHash = JSONObject().put("ver", "9.9.9").put("filename", "SilentPassUI-9.9.9.zip").put("zip_sha256", sha256(bytes)).toString()
        assertEquals(OtaVerdict.MISSING_SIGNATURE, store.otaVerifier.verifyManifest(unsignedWithHash, "0.52.927").verdict)
        OtaTestSigner.stage(store, zip, "9.9.9")
        assertEquals("9.9.9", store.pendingUpdateVersion())
    }

    @Test
    fun verifiedOtaBundleIsTrustedWhenActiveAndOnlyWhileUnchanged() {
        val bundled = zipOf("", "1.0.0")
        val store = EmbeddedPwaBundleStore(root, { ByteArrayInputStream(bundled) }, hashStore, remotePwaUpdate = true, expectedZipSha256 = sha256(bundled), otaKeys = OtaTestSigner.keys)
        store.bootstrapIfNeeded()
        assertEquals(sha256(bundled), store.verifiedActiveZipSha256())
        val ota = tmp.newFile("ota2.zip").apply { writeBytes(zipOf("", "2.0.0", padding = 2)) }
        OtaTestSigner.stage(store, ota, "2.0.0")
        store.promoteStagingToActive()
        assertEquals("2.0.0", store.activeVersion())
        assertEquals(sha256(ota.readBytes()), store.verifiedActiveZipSha256())
        // next cold start keeps the newer verified download and its trust
        store.bootstrapIfNeeded()
        assertEquals("2.0.0", store.activeVersion())
        assertEquals(sha256(ota.readBytes()), store.verifiedActiveZipSha256())
        // a changed file: no trust
        File(store.activeDir, "static/js/main.js").appendText("// changed")
        assertNull(store.verifiedActiveZipSha256())
    }

    @Test
    fun otaRecordCannotBePlantedByTheDownloadedZip() {
        val store = otaStore()
        val evilDigest = "a".repeat(64)
        val zip = tmp.newFile("evil.zip").apply {
            val out = ByteArrayOutputStream()
            ZipOutputStream(out).use { z ->
                for ((n, b) in listOf("index.html" to indexHtml(""), "update.json" to updateJson("9.9.9"), "static/js/main.js" to "//",
                        "../${EmbeddedPwaBundleStore.OTA_RECORD_DIR}/$evilDigest.json" to "{\"zip_sha256\":\"${"b".repeat(64)}\"}")) {
                    z.putNextEntry(ZipEntry(n)); z.write(b.toByteArray()); z.closeEntry()
                }
            }
            writeBytes(out.toByteArray())
        }
        runCatching { OtaTestSigner.stage(store, zip, "9.9.9") }
        assertFalse(File(root, "${EmbeddedPwaBundleStore.OTA_RECORD_DIR}/$evilDigest.json").exists())
        assertFalse(store.stagingDir.exists()) // not canonical: rejected before unpacking
    }

    private fun assertActiveIsEmbedded(store: EmbeddedPwaBundleStore) {
        val html = File(store.activeDir, "index.html").readText()
        assertTrue(html, EmbeddedPwaBundleStore.indexHtmlUsesEmbeddedAssetPaths(html))
    }

    private fun writeBundle(dir: File, assetPrefix: String, version: String) {
        dir.mkdirs()
        File(dir, "index.html").writeText(indexHtml(assetPrefix))
        File(dir, "update.json").writeText(updateJson(version))
        // a complete bundle has the scripts its index.html names (the real bundles always do).
        File(dir, "${assetPrefix.removePrefix("/")}${if (assetPrefix.isEmpty()) "" else "/"}static/js/main.js".removePrefix("/")).apply { parentFile.mkdirs(); writeText("// fixture") }
    }

    private fun zipOf(assetPrefix: String, version: String, padding: Int = 0): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            (mapOf(
                "index.html" to indexHtml(assetPrefix),
                "update.json" to updateJson(version),
                "static/js/main.js" to "// fixture",
            ) + (1..padding).associate { "static/media/padding-file-with-a-long-name-$it.txt" to "p$it" })
                .forEach { (name, body) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(body.toByteArray())
                zip.closeEntry()
            }
        }
        return OtaTestSigner.canonicalize(out.toByteArray())
    }

    private fun sha256(bytes: ByteArray): String =
        java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun updateJson(version: String) = """{"ver":"$version","filename":"SilentPassUI-$version.zip"}"""

    /** Shaped like the real builds, incl. the `fc:miniapp` meta whose JSON has `https://beamio.app/app/`. */
    private fun indexHtml(assetPrefix: String) =
        """<!doctype html><html><head><link rel="icon" href="$assetPrefix/favicon.ico"/>""" +
            """<meta name="fc:miniapp" content='{"button":{"action":{"url":"https://beamio.app/app/"}}}'/>""" +
            """<script defer="defer" src="$assetPrefix/static/js/main.js"></script>""" +
            """<link href="$assetPrefix/static/css/main.css" rel="stylesheet"></head>""" +
            """<body><div id="root"></div></body></html>"""
}
