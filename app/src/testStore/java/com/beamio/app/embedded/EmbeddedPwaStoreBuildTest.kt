package com.beamio.app.embedded

import com.beamio.app.BuildConfig
import java.io.ByteArrayInputStream
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test

/**
 * Runs only for the `store` build type (testStoreUnitTest): proves the remote PWA update
 * code is not compiled in (ota-pwa-protocol.md section 1; N1 compile-level half).
 */
class EmbeddedPwaStoreBuildTest {
    @Test
    fun storeBuildConfigDisablesRemoteUpdate() {
        assertFalse(BuildConfig.REMOTE_PWA_UPDATE)
        assertEquals(64, BuildConfig.PWA_ZIP_SHA256.length)
        println("EVIDENCE store-buildconfig REMOTE_PWA_UPDATE=${BuildConfig.REMOTE_PWA_UPDATE} PWA_ZIP_SHA256=${BuildConfig.PWA_ZIP_SHA256}")
    }

    @Test
    fun storeBuildConfigShaComesFromLockNotZip() {
        // Unit tests run with the module directory as working directory.
        val lock = java.io.File("pwa-embed.lock")
        val lockSha = lock.readLines().first { it.startsWith("zip_sha256=") }.substringAfter("=").trim()
        assertEquals(lockSha, BuildConfig.PWA_ZIP_SHA256)
        println("EVIDENCE store-buildconfig-from-lock lock=$lockSha buildconfig=${BuildConfig.PWA_ZIP_SHA256}")
    }

    @Test
    fun storeBootstrapAcceptsRealEmbeddedZip() {
        // The real asset (not a tiny fixture): its central directory is far past the unzip read-ahead.
        val zip = java.io.File("src/main/assets/SilentPassUI.zip").readBytes()
        val root = Files.createTempDirectory("store-real-zip").toFile()
        val store = EmbeddedPwaBundleStore(
            rootDir = root,
            openBundledZip = {
                object : java.io.FilterInputStream(ByteArrayInputStream(zip)) {
                    override fun read(b: ByteArray, off: Int, len: Int) = super.read(b, off, minOf(len, 4096))
                }
            },
            activatedAssetHash = object : ActivatedAssetHashStore {
                override fun get(): String? = null
                override fun set(value: String) {}
            },
            remotePwaUpdate = false,
            expectedZipSha256 = BuildConfig.PWA_ZIP_SHA256,
        )
        store.bootstrapIfNeeded()
        val marker = java.io.File(store.activeDir, EmbeddedPwaBundleStore.LOADED_SHA_MARKER).readText()
        assertEquals(BuildConfig.PWA_ZIP_SHA256, marker)
        println("EVIDENCE store-real-zip bytes=${zip.size} expected=${BuildConfig.PWA_ZIP_SHA256} marker=$marker activeVer=${store.activeVersion()}")
        root.deleteRecursively()
    }

    @Test
    fun storeBuildHasNoUpdateDaemonOrUrls() {
        for (name in listOf(
            "com.beamio.app.embedded.EmbeddedPwaUpdateDaemon",
            "com.beamio.app.embedded.EmbeddedPwaOtaConstants",
        )) {
            try {
                Class.forName(name)
                fail("$name must not exist in the store build")
            } catch (_: ClassNotFoundException) {
                println("EVIDENCE store-classpath absent=$name")
            }
        }
    }

    @Test
    fun storeFactoryNeverCreatesDaemon() {
        val root = Files.createTempDirectory("store-factory").toFile()
        val store = EmbeddedPwaBundleStore(
            rootDir = root,
            openBundledZip = { ByteArrayInputStream(ByteArray(0)) },
            activatedAssetHash = object : ActivatedAssetHashStore {
                override fun get(): String? = null
                override fun set(value: String) {}
            },
            remotePwaUpdate = false,
        )
        // Even a caller asking for remote update gets nothing: the store factory has no daemon.
        assertNull(EmbeddedPwaOtaFactory.create(store, { _, _ -> }, true))
        println("EVIDENCE store-factory create(remotePwaUpdate=true)=null")
        root.deleteRecursively()
    }
}
