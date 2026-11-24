package com.beamio.app.embedded

import android.util.Log
import android.os.Handler
import android.os.Looper
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Polls `https://beamio.ca/app/update.json`, downloads newer bundles into `staging/`.
 *
 * Store builds (`remotePwaUpdate == false`, BuildConfig.REMOTE_PWA_UPDATE): the daemon never starts and
 * every entry point returns before any network request, so a remote manifest can never stage a bundle.
 */
class EmbeddedPwaUpdateDaemon(
    private val bundleStore: EmbeddedPwaBundleStore,
    private val onUpdateAvailable: (currentVer: String, pendingVer: String) -> Unit,
    private val remotePwaUpdate: Boolean = true,
    private val manifestUrl: String = EmbeddedPwaOtaConstants.REMOTE_UPDATE_MANIFEST,
    private val bundleBaseUrl: String = EmbeddedPwaOtaConstants.REMOTE_BUNDLE_BASE,
    private val checkIntervalMs: Long = CHECK_INTERVAL_MS,
) : EmbeddedPwaOtaDaemon {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()
    private val checkInFlight = AtomicBoolean(false)
    @Volatile
    private var stopped = false

    override fun start() {
        if (!remotePwaUpdate) {
            Log.i(TAG, "OTA disabled (store build): daemon not started")
            return
        }
        stopped = false
        Log.i(TAG, "OTA daemon started manifest=$manifestUrl")
        scheduleNext(0L)
    }

    override fun stop() {
        stopped = true
        Log.i(TAG, "OTA daemon stopped")
        mainHandler.removeCallbacksAndMessages(null)
    }

    override fun checkNow() {
        if (!remotePwaUpdate) return
        scheduleNext(0L)
    }

    private fun scheduleNext(delayMs: Long) {
        if (stopped) return
        mainHandler.postDelayed({
            if (stopped) return@postDelayed
            executor.execute {
                try {
                    performCheck()
                } finally {
                    if (!stopped) {
                        mainHandler.post { scheduleNext(checkIntervalMs) }
                    }
                }
            }
        }, delayMs)
    }

    internal fun performCheck() {
        if (!remotePwaUpdate) {
            Log.i(TAG, "OTA disabled (store build): check skipped")
            return
        }
        if (!checkInFlight.compareAndSet(false, true)) return
        try {
            // Reference = the selected verified bundle (or the embedded constant); never an unverified active version.
            val reference = bundleStore.selectedVerifiedVersion()
            Log.i(TAG, "OTA check begin reference=${reference ?: "unknown"} pending=${bundleStore.pendingUpdateVersion() ?: ""}")
            val body = try {
                fetchManifestText()
            } catch (e: Exception) {
                Log.w(TAG, "OTA manifest unavailable type=${e.javaClass.simpleName}")
                bundleStore.writeOtaStatus("network-error", null, null)
                return
            }
            if (body == null || looksLikeHtml(body)) {
                // Non-2xx or an HTML fallback page (captive portal, SPA catch-all): a network error, not a manifest.
                bundleStore.writeOtaStatus("network-error", null, null)
                return
            }
            // Only a signature by a compile-time key makes a download trusted; a top-level zip_sha256 is ignored.
            val check = bundleStore.otaVerifier.verifyManifest(body, reference)
            val manifest = check.manifest
            Log.i(TAG, "OTA manifest verdict=${check.verdict.code} ver=${manifest?.ver ?: "?"} reference=${reference ?: "unknown"}")
            if (check.verdict == OtaVerdict.DOWNGRADE) {
                bundleStore.writeOtaStatus("up-to-date", check.verdict.code, manifest?.ver)
                Log.i(TAG, "OTA no newer version")
                return
            }
            if (check.verdict != OtaVerdict.OK || manifest == null) {
                bundleStore.writeOtaStatus(check.verdict.status, check.verdict.code, manifest?.ver)
                return
            }
            val pending = bundleStore.pendingUpdateVersion()
            if (pending == manifest.ver) {
                Log.i(TAG, "OTA staged version still pending=$pending")
                postUpdateAvailable(reference ?: "", manifest.ver)
                return
            }
            val sizeVerdict = bundleStore.otaVerifier.checkDownloadSize(manifest)
            if (sizeVerdict != OtaVerdict.OK) {
                Log.w(TAG, "OTA bundle not downloaded verdict=${sizeVerdict.code} size=${manifest.size}")
                bundleStore.writeOtaStatus(sizeVerdict.status, sizeVerdict.code, manifest.ver)
                return
            }
            Log.i(TAG, "OTA downloading version=${manifest.ver}")
            val tempZip = File.createTempFile("silentpass_download_", ".zip")
            try {
                try {
                    download(bundleBaseUrl + manifest.filename, tempZip, manifest.size)
                } catch (e: DownloadTooLong) {
                    Log.w(TAG, "OTA download aborted: more bytes than the signed size")
                    bundleStore.writeOtaStatus(OtaVerdict.SIZE_MISMATCH.status, OtaVerdict.SIZE_MISMATCH.code, manifest.ver)
                    return
                } catch (e: Exception) {
                    Log.w(TAG, "OTA download failed type=${e.javaClass.simpleName}")
                    bundleStore.writeOtaStatus("network-error", null, manifest.ver)
                    return
                }
                try {
                    bundleStore.installDownloadToStaging(check, tempZip)
                } catch (e: EmbeddedPwaBundleStore.OtaRejected) {
                    Log.w(TAG, "OTA download not staged verdict=${e.verdict.code}: ${e.message}")
                    bundleStore.writeOtaStatus(e.verdict.status, e.verdict.code, manifest.ver)
                    return
                }
            } finally {
                tempZip.delete()
            }
            bundleStore.writeOtaStatus("verified-staged", OtaVerdict.OK.code, manifest.ver)
            Log.i(TAG, "OTA staged version=${manifest.ver}")
            postUpdateAvailable(reference ?: "", manifest.ver)
        } catch (error: Exception) {
            // Untrusted fetch: keep the last trusted bundle; no UI wipe.
            Log.e(TAG, "OTA check failed type=${error.javaClass.simpleName} message=${error.message}", error)
        } finally {
            checkInFlight.set(false)
        }
    }

    /** update.json text, or null on a non-2xx answer (network error). */
    private fun fetchManifestText(): String? {
        val conn = (URL(manifestUrl).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 30_000
            readTimeout = 30_000
            useCaches = false
            setRequestProperty("Cache-Control", "no-cache")
        }
        return try {
            val responseCode = conn.responseCode
            Log.i(TAG, "OTA manifest response=$responseCode")
            if (responseCode !in 200..299) return null
            conn.inputStream.bufferedReader().use { it.readText() }
        } finally {
            conn.disconnect()
        }
    }

    private fun download(url: String, target: File, signedSize: Long) {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 30_000
            readTimeout = 120_000
            useCaches = false
            setRequestProperty("Cache-Control", "no-cache")
        }
        try {
            val responseCode = conn.responseCode
            Log.i(TAG, "OTA download response=$responseCode url=$url")
            if (responseCode !in 200..299) throw IllegalStateException("Download failed: HTTP $responseCode")
            conn.inputStream.use { input -> target.outputStream().use { output -> copyBounded(input, output, signedSize) } }
        } finally {
            conn.disconnect()
        }
    }

    private fun postUpdateAvailable(current: String, pending: String) {
        mainHandler.post { onUpdateAvailable(current, pending) }
    }

    /** The server sent more bytes than the signed payload size; the download is stopped at once. */
    internal class DownloadTooLong : java.io.IOException("download longer than the signed size")

    companion object {
        private const val TAG = "BeamioEmbeddedPwa"

        /** Copies [input] to [output]; throws [DownloadTooLong] as soon as more than [limit] bytes arrive. */
        internal fun copyBounded(input: java.io.InputStream, output: java.io.OutputStream, limit: Long): Long {
            val buf = ByteArray(64 * 1024)
            var total = 0L
            while (true) {
                val n = input.read(buf)
                if (n < 0) return total
                if (total + n > limit) throw DownloadTooLong()
                output.write(buf, 0, n)
                total += n
            }
        }

        internal fun looksLikeHtml(body: String): Boolean = body.trimStart().startsWith("<")
        private const val CHECK_INTERVAL_MS = 15L * 60L * 1000L
    }
}
