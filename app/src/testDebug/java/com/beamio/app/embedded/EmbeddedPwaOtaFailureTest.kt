package com.beamio.app.embedded

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.net.InetSocketAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 *OTA failures (DNS, TLS, HTTP 500, non-JSON manifest, a manifest request that hangs) never touch active/, and the
 * local bootstrap still completes and serves active/ while a check is stuck. No real external host is contacted: DNS uses
 * the reserved `.invalid` TLD, the rest a loopback server.
 */
class EmbeddedPwaOtaFailureTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var root: File
    private val hashStore = object : ActivatedAssetHashStore {
        var value: String? = null
        override fun get(): String? = value
        override fun set(value: String) { this.value = value }
    }

    @Before
    fun setUp() {
        root = tmp.newFolder("silentpass_pwa")
        val active = File(root, "active").apply { mkdirs() }
        File(active, "index.html").writeText("""<!doctype html><script defer src="/static/js/main.js"></script><div id="root"></div>""")
        File(active, "update.json").writeText("""{"ver":"0.53.0","filename":"SilentPassUI-0.53.0.zip"}""")
        File(active, "static/js").mkdirs(); File(active, "static/js/main.js").writeText("// app")
    }

    /** Remote-update store whose APK zip cannot be read (the worst case): bootstrap must still keep active/. */
    private fun store() = EmbeddedPwaBundleStore(root, { throw java.io.IOException("injected: asset read failed") }, hashStore, remotePwaUpdate = true)

    private fun snapshot() = File(root, "active").walkTopDown().filter { it.isFile }.associate { it.name to it.readBytes().contentHashCode() }

    private fun daemon(s: EmbeddedPwaBundleStore, manifestUrl: String) =
        EmbeddedPwaUpdateDaemon(s, { _, _ -> }, remotePwaUpdate = true, manifestUrl = manifestUrl, bundleBaseUrl = manifestUrl.substringBeforeLast('/') + "/")

    private fun assertUntouched(before: Map<String, Int>, case: String) {
        assertEquals(case, before, snapshot())
        assertFalse("$case: no staging", File(root, "staging").exists())
        println("EVIDENCE OTA $case -> active unchanged (${before.size} files), no staging")
    }

    @Test
    fun dnsFailureKeepsActive() {
        val s = store(); s.bootstrapIfNeeded(); val before = snapshot()
        daemon(s, "https://dns-failure.invalid/app/update.json").performCheck()
        assertUntouched(before, "DNS failure")
    }

    @Test
    fun tlsFailureKeepsActive() {
        // A plain HTTP server addressed over https: the TLS handshake fails.
        val server = com.sun.net.httpserver.HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/") { ex -> ex.sendResponseHeaders(200, 0); ex.close() }
        server.start()
        try {
            val s = store(); s.bootstrapIfNeeded(); val before = snapshot()
            daemon(s, "https://127.0.0.1:${server.address.port}/app/update.json").performCheck()
            assertUntouched(before, "TLS failure")
        } finally { server.stop(0) }
    }

    @Test
    fun http500AndNonJsonManifestKeepActive() {
        for ((case, code, body) in listOf(Triple("HTTP 500", 500, "oops"), Triple("non-JSON manifest", 200, "<html>parked domain</html>"))) {
            val server = com.sun.net.httpserver.HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
            server.createContext("/") { ex -> val b = body.toByteArray(); ex.sendResponseHeaders(code, b.size.toLong()); ex.responseBody.use { it.write(b) } }
            server.start()
            try {
                val s = store(); s.bootstrapIfNeeded(); val before = snapshot()
                daemon(s, "http://127.0.0.1:${server.address.port}/app/update.json").performCheck()
                assertUntouched(before, case)
            } finally { server.stop(0) }
        }
    }

    @Test
    fun hangingManifestDoesNotBlockTheLocalBootstrap() {
        val release = CountDownLatch(1)
        val requested = CountDownLatch(1)
        val server = com.sun.net.httpserver.HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.executor = java.util.concurrent.Executors.newCachedThreadPool()
        server.createContext("/") { ex -> requested.countDown(); release.await(20, TimeUnit.SECONDS); ex.sendResponseHeaders(500, -1); ex.close() }
        server.start()
        try {
            val s = store(); s.bootstrapIfNeeded(); val before = snapshot()
            val check = Thread { daemon(s, "http://127.0.0.1:${server.address.port}/app/update.json").performCheck() }.apply { isDaemon = true; start() }
            assertTrue("manifest request is in flight", requested.await(5, TimeUnit.SECONDS))
            // While update.json hangs, a new start's bootstrap completes at once and active/ is complete and served.
            val t0 = System.nanoTime()
            store().bootstrapIfNeeded()
            val ms = (System.nanoTime() - t0) / 1_000_000
            assertTrue("bootstrap did not wait for the manifest (${ms} ms)", ms < 2_000)
            assertTrue(store().hasCompleteBundle(File(root, "active")))
            assertEquals("0.53.0", s.activeVersion())
            release.countDown()
            check.join(10_000)
            assertUntouched(before, "update.json hang (bootstrap ${ms} ms while hanging)")
        } finally { release.countDown(); server.stop(0) }
    }
}
