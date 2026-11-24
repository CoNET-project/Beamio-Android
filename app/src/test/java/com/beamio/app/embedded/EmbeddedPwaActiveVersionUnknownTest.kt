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
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * review (ota-active-version-unknown-boundary-review-2026-11-17): an unreadable active version is unknown, never
 * "0.0.0". Unknown never lets a remote bundle in: the OTA check is skipped, a staged bundle is not promoted, and the
 * bootstrap reinstalls the embedded ZIP so the active version is readable again.
 */
class EmbeddedPwaActiveVersionUnknownTest {
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

    /** Pinned like every production build (the embedded ZIP's SHA-256 from the lock), so it is a verified candidate. */
    private fun newStore() = EmbeddedPwaBundleStore(
        rootDir = root,
        openBundledZip = { ByteArrayInputStream(checkNotNull(bundledZip) { "no bundled zip" }) },
        activatedAssetHash = hashStore,
        expectedZipSha256 = bundledZip?.let { b -> MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) } },
    )

    /** Active bundle with a complete index and script. [version] null: update.json absent; [corrupt]: truncated JSON. */
    private fun writeBundle(dir: File, version: String?, corrupt: Boolean = false) {
        dir.mkdirs()
        File(dir, "index.html").writeText(indexHtml())
        File(dir, "static/js").mkdirs()
        File(dir, "static/js/main.js").writeText("// fixture")
        when {
            version == null -> Unit
            corrupt -> File(dir, "update.json").writeText("""{"ver":"$version""")
            else -> File(dir, "update.json").writeText(updateJson(version))
        }
    }

    private fun zipOf(version: String): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            mapOf(
                "index.html" to indexHtml(),
                "update.json" to updateJson(version),
                "static/js/main.js" to "// fixture",
            ).forEach { (name, body) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(body.toByteArray())
                zip.closeEntry()
            }
        }
        return OtaTestSigner.canonicalize(out.toByteArray())
    }

    private fun indexHtml() =
        """<!doctype html><html><head><link rel="icon" href="/favicon.ico"/>""" +
            """<script defer="defer" src="/static/js/main.js"></script>""" +
            """<link href="/static/css/main.css" rel="stylesheet"></head>""" +
            """<body><div id="root"></div></body></html>"""

    private fun updateJson(version: String) = """{"ver":"$version","filename":"SilentPassUI-$version.zip"}"""

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    /** A staged bundle as a finished download would leave it. */
    private fun writeStaged(store: EmbeddedPwaBundleStore, version: String) =
        writeBundle(store.stagingDir, version)

    // 1 unknown is not 0.0.0

    @Test
    fun corruptActiveUpdateJsonReadsAsUnknownNotZero() {
        writeBundle(File(root, "active"), "0.52.935", corrupt = true)
        val store = newStore()
        assertNull(store.activeVersion())
    }

    // 2 unknown skips the OTA check: no fetch, no download, no staging, no prompt

    @Test
    fun otaDecisionSkipsWhenActiveVersionIsUnknown() {
        assertEquals(OtaCheckDecision.SKIP_ACTIVE_UNKNOWN, decideOtaCheck(null, "0.52.933"))
        assertEquals(OtaCheckDecision.SKIP_ACTIVE_UNKNOWN, decideOtaCheck(null, "0.52.999"))
    }

    @Test
    fun otaDecisionStagesOnlyAHigherKnownVersion() {
        assertEquals(OtaCheckDecision.NO_NEWER, decideOtaCheck("0.52.935", "0.52.933"))
        assertEquals(OtaCheckDecision.NO_NEWER, decideOtaCheck("0.52.935", "0.52.935"))
        assertEquals(OtaCheckDecision.STAGE, decideOtaCheck("0.52.935", "0.52.936"))
    }

    // Required case: active update.json corrupt + remote 933 -> no download, active stays 935

    @Test
    fun corruptActiveIsRepairedToEmbedded935AndRemote933IsNotFetched() {
        writeBundle(File(root, "active"), "0.52.935", corrupt = true)
        bundledZip = zipOf("0.52.935")
        hashStore.value = sha256(bundledZip!!)
        val store = newStore()
        assertNull(store.activeVersion())

        store.bootstrapIfNeeded()

        assertEquals("0.52.935", store.activeVersion())
        assertEquals(OtaCheckDecision.NO_NEWER, decideOtaCheck(store.activeVersion(), "0.52.933"))
        assertFalse(store.stagingDir.exists())
    }

    // Required case: update.json missing -> after start, embedded 935 is back and its version is readable

    @Test
    fun missingActiveUpdateJsonIsReinstalledAndVersionIsReadable() {
        writeBundle(File(root, "active"), null)
        bundledZip = zipOf("0.52.935")
        hashStore.value = sha256(bundledZip!!)
        val store = newStore()
        assertNull(store.activeVersion())

        store.bootstrapIfNeeded()

        assertEquals("0.52.935", store.activeVersion())
        assertTrue(File(store.activeDir, "update.json").isFile)
    }

    // Required case: staged 933 + active 935 -> staged_not_newer, active unchanged

    @Test
    fun stagedNotNewerThanActive935IsRefused() {
        writeBundle(File(root, "active"), "0.52.935")
        val store = newStore()
        writeStaged(store, "0.52.933")

        val error = assertThrows(IllegalStateException::class.java) { store.promoteStagingToActive() }

        assertEquals("staged_not_verified", error.message) // unsigned staging is refused before any version check
        assertEquals("0.52.935", store.activeVersion())
        assertFalse(store.stagingDir.exists())
    }

    // Required case: staged 936 + active 935 -> normal promotion (positive)

    @Test
    fun stagedNewer936IsPromotedOverActive935() {
        // the staged bundle must carry a verified-download record (installDownloadToStaging).
        writeBundle(File(root, "active"), "0.52.935")
        val store = EmbeddedPwaBundleStore(root, { ByteArrayInputStream(checkNotNull(bundledZip)) }, hashStore, embeddedZipVer = "0.52.935", otaKeys = OtaTestSigner.keys)
        val zip = File(root.parentFile, "ota-936.zip").apply { writeBytes(zipOf("0.52.936")) }
        OtaTestSigner.stage(store, zip, "0.52.936")

        store.promoteStagingToActive()

        assertEquals("0.52.936", store.activeVersion())
        assertFalse(store.stagingDir.exists())
    }

    // Required case: active version unknown -> promote refused (negative)

    @Test
    fun promoteIsRefusedWhenActiveVersionIsUnknown() {
        writeBundle(File(root, "active"), "0.52.935", corrupt = true)
        val before = File(root, "active/update.json").readText()
        val store = newStore()
        writeStaged(store, "0.52.936")

        val error = assertThrows(IllegalStateException::class.java) { store.promoteStagingToActive() }

        assertEquals("staged_not_verified", error.message) // unsigned staging is refused before any version check
        assertFalse(store.stagingDir.exists())
        assertNull(store.pendingUpdateVersion())
        assertEquals(before, File(root, "active/update.json").readText())
    }

    // Start-up path: a staged 936 must not replace an unknown active; the bootstrap reinstalls the embedded 935

    @Test
    fun bootstrapDiscardsStagedBundleWhenActiveVersionIsUnknown() {
        writeBundle(File(root, "active"), "0.52.935", corrupt = true)
        bundledZip = zipOf("0.52.935")
        hashStore.value = sha256(bundledZip!!)
        val store = newStore()
        writeStaged(store, "0.52.936")

        store.bootstrapIfNeeded()

        assertEquals("0.52.935", store.activeVersion())
        assertFalse(store.stagingDir.exists())
    }
}
