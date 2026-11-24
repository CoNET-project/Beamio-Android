package com.beamio.app.embedded

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream

/** Release OTA download bounds: never more bytes than the signed size; HTML fallback pages are network errors. */
class EmbeddedPwaDownloadLimitTest {
    @Test
    fun downloadStopsAsSoonAsItExceedsTheSignedSize() {
        var served = 0L
        val endless = object : InputStream() {
            override fun read(): Int = throw UnsupportedOperationException()
            override fun read(b: ByteArray, off: Int, len: Int): Int { served += len; return len }
        }
        val out = ByteArrayOutputStream()
        assertThrows(EmbeddedPwaUpdateDaemon.DownloadTooLong::class.java) { EmbeddedPwaUpdateDaemon.copyBounded(endless, out, 100_000) }
        assertTrue("nothing past the signed size is written", out.size() <= 100_000)
        assertTrue("stopped at once, not read to the end", served <= 100_000 + 64 * 1024)
    }

    @Test
    fun exactSizeIsAccepted() {
        val out = ByteArrayOutputStream()
        assertEquals(1000L, EmbeddedPwaUpdateDaemon.copyBounded(ByteArrayInputStream(ByteArray(1000)), out, 1000))
        assertThrows(EmbeddedPwaUpdateDaemon.DownloadTooLong::class.java) {
            EmbeddedPwaUpdateDaemon.copyBounded(ByteArrayInputStream(ByteArray(1001)), ByteArrayOutputStream(), 1000)
        }
    }

    @Test
    fun htmlFallbackIsNotAManifest() {
        assertTrue(EmbeddedPwaUpdateDaemon.looksLikeHtml("  <!doctype html><html>"))
        assertFalse(EmbeddedPwaUpdateDaemon.looksLikeHtml("{\"ver\":\"0.53.49\"}"))
    }
}
