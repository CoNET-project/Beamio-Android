package com.beamio.app.embedded

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * N1 (ota-integrity-plan.md): a remote manifest with a higher version is never requested when remote PWA
 * update is off. Lives in the debug test source set because the daemon class is compiled only into
 * non-store build types (the store variant has no daemon; see src/testStore).
 */
class EmbeddedPwaUpdateDaemonStoreTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var root: File
    private var bundledZip: ByteArray? = null
    private val hashStore = object : ActivatedAssetHashStore {
        var value: String? = null
        override fun get(): String? = value
        override fun set(value: String) { this.value = value }
    }
    private val bundledVersion = "0.52.935"
    private val higherVersion = "0.52.999"

    @Before
    fun setUp() {
        root = tmp.newFolder("silentpass_pwa")
    }

    private fun storeStore(expected: String? = sha256(checkNotNull(bundledZip))) = EmbeddedPwaBundleStore(
        rootDir = root,
        openBundledZip = { ByteArrayInputStream(checkNotNull(bundledZip)) },
        activatedAssetHash = hashStore,
        remotePwaUpdate = false,
        expectedZipSha256 = expected,
    )

    private fun bundledDigest(store: EmbeddedPwaBundleStore): String {
        val dir = tmp.newFolder()
        EmbeddedPwaZip.unzip(ByteArrayInputStream(checkNotNull(bundledZip)), dir)
        return store.contentDigest(dir)
    }

    private fun assertActiveIsBundled(store: EmbeddedPwaBundleStore) {
        assertEquals(bundledVersion, store.activeVersion())
        assertEquals(bundledDigest(store), store.contentDigest(store.activeDir))
        assertEquals(sha256(checkNotNull(bundledZip)), File(store.activeDir, EmbeddedPwaBundleStore.LOADED_SHA_MARKER).readText())
    }

    private fun evidence(case: String, store: EmbeddedPwaBundleStore, extra: String = "") {
        println(
            "EVIDENCE $case zipSha256=${sha256(checkNotNull(bundledZip))} activeVer=${store.activeVersion()} " +
                "activeDigest=${store.contentDigest(store.activeDir)} staging=${store.stagingDir.exists()} $extra",
        )
    }

    @Test
    fun storeN1RemoteManifestWithHigherVersionIsNeverRequested() {
        bundledZip = zipOf(bundledVersion)
        val remoteZip = zipOf(higherVersion)
        val remoteSha = java.security.MessageDigest.getInstance("SHA-256").digest(remoteZip).joinToString("") { "%02x".format(it) }
        val requests = java.util.concurrent.atomic.AtomicInteger(0)
        val server = com.sun.net.httpserver.HttpServer.create(java.net.InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/") { ex ->
            requests.incrementAndGet()
            val body = if (ex.requestURI.path.endsWith("update.json")) {
                // r3oj §25.52Y.38 item 2 (h): the published update.json carries the zip's sha256, or nothing is staged
                """{"ver":"$higherVersion","filename":"SilentPassUI-$higherVersion.zip","zip_sha256":"$remoteSha"}""".toByteArray()
            } else {
                remoteZip
            }
            ex.sendResponseHeaders(200, body.size.toLong())
            ex.responseBody.use { it.write(body) }
        }
        server.start()
        try {
            val base = "http://127.0.0.1:${server.address.port}/"
            val store = storeStore()
            store.bootstrapIfNeeded()
            val daemon = EmbeddedPwaUpdateDaemon(store, { _, _ -> }, remotePwaUpdate = false, manifestUrl = base + "update.json", bundleBaseUrl = base)
            daemon.start()
            daemon.checkNow()
            daemon.performCheck() // even a direct call must not reach the network

            assertEquals(0, requests.get())
            assertFalse(store.stagingDir.exists())
            assertNull(store.pendingUpdateVersion())
            assertActiveIsBundled(store)
            evidence("N1", store, "requests=${requests.get()} remoteVer=$higherVersion")

            // Control: the same harness with remote update enabled does download and stage 0.52.999,
            // so the zero above comes from the store switch, not from a broken harness.
            val otaRoot = tmp.newFolder("ota_control")
            val otaStore = EmbeddedPwaBundleStore(otaRoot, { ByteArrayInputStream(bundledZip!!) }, hashStore)
            otaStore.bootstrapIfNeeded()
            EmbeddedPwaUpdateDaemon(otaStore, { _, _ -> }, remotePwaUpdate = true, manifestUrl = base + "update.json", bundleBaseUrl = base)
                .performCheck()
            assertTrue(requests.get() >= 2)
            assertEquals(higherVersion, otaStore.pendingUpdateVersion())
            println("EVIDENCE N1-control requests=${requests.get()} otaPending=${otaStore.pendingUpdateVersion()}")
        } finally {
            server.stop(0)
        }
    }

    private fun zipOf(version: String): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            mapOf(
                "index.html" to """<!doctype html><html><head><script defer="defer" src="/static/js/main.js"></script></head><body><div id="root"></div></body></html>""",
                "update.json" to """{"ver":"$version","filename":"SilentPassUI-$version.zip"}""",
                "static/js/main.js" to "// fixture",
            ).forEach { (name, body) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(body.toByteArray())
                zip.closeEntry()
            }
        }
        return out.toByteArray()
    }

    private fun sha256(bytes: ByteArray): String =
        java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
