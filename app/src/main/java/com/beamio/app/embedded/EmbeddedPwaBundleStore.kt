package com.beamio.app.embedded

import android.content.Context
import android.util.Log
import org.json.JSONObject
import java.io.File
import java.io.FilterInputStream
import java.io.InputStream
import java.security.DigestInputStream
import java.security.MessageDigest

/** Remembers the SHA-256 of the APK's bundled zip that was last activated. */
internal interface ActivatedAssetHashStore {
    fun get(): String?
    fun set(value: String)
}

/**
 * Documents-backed PWA bundle: `active/` (live), `staging/` (downloaded), `backup/` (rollback).
 *
 * Every candidate (APK zip, OTA download, staged update) must be a
 * `build:embedded` bundle (`PUBLIC_URL=/`). A web build (homepage `/app`)
 * loads `/app/static/...`, which the shell cannot serve, and shows only a
 * broken icon, so it never replaces `active/`.
 *
 * Store builds (`remotePwaUpdate == false`, BuildConfig.REMOTE_PWA_UPDATE): the bundled zip is the only
 * source. No remote install, no staging, no "newer version is kept": on every cold start `active/` must have
 * the same file contents as the bundled zip, otherwise it is replaced by it. The bundled zip itself must match
 * `expectedZipSha256` (BuildConfig.PWA_ZIP_SHA256); if it does not, or `active/` still differs after the
 * replacement, bootstrap fails and nothing is loaded (no fallback to an old `active/`).
 */
open class EmbeddedPwaBundleStore internal constructor(
    val rootDir: File,
    private val openBundledZip: () -> InputStream,
    private val activatedAssetHash: ActivatedAssetHashStore,
    val remotePwaUpdate: Boolean = true,
    private val expectedZipSha256: String? = null,
) {
    constructor(context: Context, remotePwaUpdate: Boolean, expectedZipSha256: String?) : this(
        rootDir = File(context.applicationContext.filesDir, EmbeddedPwaConstants.ROOT_DIR_NAME),
        // QaBootstrapFaults: debug-only fault injection for isolated acceptance (PM R1595); a plain pass-through in release/store.
        openBundledZip = com.beamio.app.qa.QaBootstrapFaults.wrapBundledZip(context) {
            context.applicationContext.assets.open(EmbeddedPwaConstants.BUNDLE_ASSET_NAME)
        },
        activatedAssetHash = SharedPrefsAssetHashStore(context.applicationContext),
        remotePwaUpdate = remotePwaUpdate,
        expectedZipSha256 = expectedZipSha256?.lowercase()?.takeIf { it.isNotBlank() },
    )

    // One lock for the whole process, not per instance: a relaunched MainActivity makes a new host and
    // store while the first bootstrap may still be running on the same silentpass_pwa/ directory.
    private val lock = PROCESS_LOCK

    val activeDir: File = File(rootDir, "active")
    val stagingDir: File = File(rootDir, "staging")
    val backupDir: File = File(rootDir, "backup")

    @Volatile
    private var pendingVersion: String? = readPendingVersionFromStaging()

    fun bootstrapIfNeeded() {
        verifiedBundle = null
        activeCheck = null
        if (!remotePwaUpdate) {
            synchronized(lock) { bootstrapStoreLocked() }
            return
        }
        synchronized(lock) {
            rootDir.mkdirs()
            recoverInterruptedSwapLocked()
            promoteStagingIfNewerLocked()
            val bundledDir = File(rootDir, "bundled")
            if (bundledDir.exists()) {
                bundledDir.deleteRecursively()
            }
            bundledDir.mkdirs()
            val digest = MessageDigest.getInstance("SHA-256")
            // §25.52Y.38 item 2 (c): SHA-256 of every byte of the bundled zip, for the walletCredential trust record. The
            // existing assetHash (bytes up to the central directory) keeps its meaning for the activation check.
            var partialHash: String? = null
            try {
                openBundledZip().use { input ->
                    DigestInputStream(input, digest).use { hashed ->
                        EmbeddedPwaZip.unzip(object : FilterInputStream(hashed) { override fun close() {} }, bundledDir)
                        partialHash = (digest.clone() as MessageDigest).digest().joinToString("") { byte -> "%02x".format(byte) }
                        val buf = ByteArray(64 * 1024)
                        while (hashed.read(buf) >= 0) Unit
                    }
                }
            } catch (e: Exception) {
                // PM R1574 (same class as POS (d)): reading the APK zip failed. A complete, embedded-path active/ is still
                // a working local UI: keep and load it; nothing is deleted. Without one, fail (the caller shows the retry page).
                bundledDir.deleteRecursively()
                if (hasCompleteBundle(activeDir) && usesEmbeddedAssetPaths(activeDir)) {
                    Log.w(TAG, "bootstrap: bundled SilentPassUI.zip unreadable (${e.javaClass.simpleName}); keeping active")
                    return
                }
                throw IllegalStateException("Bundled SilentPassUI.zip unreadable and no complete active bundle", e)
            }
            val fullZipHash = digest.digest().joinToString("") { byte -> "%02x".format(byte) }
            val assetHash = partialHash ?: fullZipHash
            if (!hasValidBundle(bundledDir)) {
                bundledDir.deleteRecursively()
                if (hasCompleteBundle(activeDir)) return
                throw IllegalStateException("Bundled SilentPassUI.zip did not contain index.html")
            }
            // PM R1574: an active/ whose index.html names scripts that are missing is not valid (it renders a blank page).
            val activeIsValid = hasCompleteBundle(activeDir)
            if (!usesEmbeddedAssetPaths(bundledDir)) {
                // Keep whatever is active so a later OTA can still repair it.
                bundledDir.deleteRecursively()
                if (activeIsValid) {
                    Log.w(TAG, "bootstrap: bundled SilentPassUI.zip loads assets from /app/ (web build); keeping active")
                    return
                }
                throw webBuildError("Bundled SilentPassUI.zip")
            }

            recordVerifiedBundleLocked(fullZipHash, bundledDir)
            val lastAssetHash = activatedAssetHash.get()
            // Repair an active web build left by an older shell.
            val activeUsesEmbeddedPaths = activeIsValid && usesEmbeddedAssetPaths(activeDir)
            val activeVersion = if (activeIsValid) readUpdateInfo(activeDir)?.ver else null
            val bundledVersion = readUpdateInfo(bundledDir)?.ver
            val contentChanged = assetHash != lastAssetHash
            val versionNewer =
                activeVersion != null &&
                    bundledVersion != null &&
                    isSemverNewer(activeVersion, bundledVersion)
            // Equal semver must still replace when the APK zip bytes changed.
            // A newer OTA (active semver > bundled) is left in place.
            val sameVersionNewBytes =
                activeVersion != null &&
                    bundledVersion != null &&
                    activeVersion == bundledVersion &&
                    contentChanged
            val shouldInstallBundled =
                !activeIsValid || !activeUsesEmbeddedPaths || versionNewer || sameVersionNewBytes
            Log.i(
                TAG,
                "bootstrap active=$activeVersion bundled=$bundledVersion " +
                    "contentChanged=$contentChanged install=$shouldInstallBundled",
            )

            if (!shouldInstallBundled) {
                bundledDir.deleteRecursively()
                return
            }
            if (!replaceActiveWithDirectoryLocked(bundledDir)) {
                bundledDir.deleteRecursively()
                throw IllegalStateException("Failed to activate bundled SilentPassUI.zip")
            }
            activatedAssetHash.set(assetHash)
            Log.i(TAG, "bootstrap activated bundled=$bundledVersion")
        }
    }

    /**
     * Store build: the bundled zip is the only source of `active/`.
     *  1. `staging/` and `backup/` are discarded (no remote or interrupted bundle is ever promoted).
     *  2. The bundled zip is extracted to `bundled/`; its SHA-256 must equal [expectedZipSha256].
     *  3. `active/` is kept only if its files are byte-identical to `bundled/` (content digest, not version,
     *     not the `.loaded-sha256` marker); otherwise it is replaced by `bundled/`.
     *  4. After the replacement `active/` must equal the bundled content; if not, it is deleted and bootstrap
     *     fails (the caller shows the unavailable page; no fallback to an old `active/`).
     */
    private fun bootstrapStoreLocked() {
        rootDir.mkdirs()
        val discarded = listOf(stagingDir, backupDir).filter { it.exists() }
        discarded.forEach { it.deleteRecursively() }
        pendingVersion = null
        if (discarded.isNotEmpty()) {
            Log.w(TAG, "store bootstrap: discarded ${discarded.joinToString { it.name }} (remote PWA update disabled)")
        }

        val bundledDir = File(rootDir, "bundled")
        if (bundledDir.exists()) bundledDir.deleteRecursively()
        bundledDir.mkdirs()
        val digest = MessageDigest.getInstance("SHA-256")
        try {
            openBundledZip().use { input ->
                DigestInputStream(input, digest).use { hashed ->
                    // ZipInputStream stops at the central directory, so unzip does not read the tail of the
                    // file. Keep the stream open across unzip, then read the rest so the SHA covers every byte.
                    EmbeddedPwaZip.unzip(object : FilterInputStream(hashed) { override fun close() {} }, bundledDir)
                    val buf = ByteArray(64 * 1024)
                    while (hashed.read(buf) >= 0) Unit
                }
            }
        } catch (e: Exception) {
            bundledDir.deleteRecursively()
            // PM R1574: the APK zip could not be read this time. Load active/ only if it is provably the content this same
            // APK zip (expectedZipSha256) produced on an earlier start: both markers match and its files hash to the
            // recorded content digest, with no missing script. Otherwise nothing is loaded. Nothing is deleted either way.
            if (activeVerifiedForExpectedZipLocked()) {
                Log.w(TAG, "store bootstrap: bundled SilentPassUI.zip unreadable (${e.javaClass.simpleName}); loading active, verified as this APK's content")
                return
            }
            throw BundleIntegrityException("store bootstrap: bundled SilentPassUI.zip unreadable and active/ not verified; nothing loaded")
        }
        val zipSha = digest.digest().joinToString("") { byte -> "%02x".format(byte) }
        // Fail closed: a store build without an expected SHA (lock missing at build time) loads nothing.
        if (expectedZipSha256 == null || zipSha != expectedZipSha256) {
            bundledDir.deleteRecursively()
            activeDir.deleteRecursively()
            throw BundleIntegrityException(
                "store bootstrap: bundled SilentPassUI.zip sha256 ${shortDigest(zipSha)} != expected ${shortDigest(expectedZipSha256)}; nothing loaded",
            )
        }
        if (!hasValidBundle(bundledDir)) {
            bundledDir.deleteRecursively()
            activeDir.deleteRecursively()
            throw BundleIntegrityException("store bootstrap: bundled SilentPassUI.zip did not contain index.html")
        }
        if (!usesEmbeddedAssetPaths(bundledDir)) {
            bundledDir.deleteRecursively()
            activeDir.deleteRecursively()
            throw webBuildError("Bundled SilentPassUI.zip")
        }

        val bundledLines = contentLines(bundledDir)
        val bundledDigest = digestOfLines(bundledLines)
        val bundledVersion = readUpdateInfo(bundledDir)?.ver
        val activeDigest = if (activeDir.isDirectory) contentDigest(activeDir) else null
        val source: String
        if (activeDigest == bundledDigest) {
            bundledDir.deleteRecursively()
            source = "kept"
        } else {
            if (!replaceActiveWithDirectoryLocked(bundledDir)) {
                bundledDir.deleteRecursively()
                activeDir.deleteRecursively()
                throw BundleIntegrityException("store bootstrap: failed to activate bundled SilentPassUI.zip")
            }
            backupDir.deleteRecursively()
            source = "bundled"
        }
        onStoreReplaced(activeDir)
        val loadedLines = contentLines(activeDir)
        val loadedDigest = digestOfLines(loadedLines)
        if (loadedDigest != bundledDigest) {
            activeDir.deleteRecursively()
            throw BundleIntegrityException(
                "store bootstrap: active/ content ${shortDigest(loadedDigest)} != bundled ${shortDigest(bundledDigest)} after replacement; " +
                    "${describeDifference(bundledLines, loadedLines)}; nothing loaded",
            )
        }
        File(activeDir, LOADED_SHA_MARKER).writeText(zipSha)
        File(activeDir, LOADED_CONTENT_MARKER).writeText(bundledDigest)
        activatedAssetHash.set(zipSha)
        verifiedBundle = VerifiedBundle(this, zipSha, bundledDigest)
        Log.i(
            TAG,
            "store bootstrap: source=$source ver=$bundledVersion zipSha256=${shortDigest(zipSha)} " +
                "contentDigest=${shortDigest(bundledDigest)} previousActive=${activeDigest?.let { shortDigest(it) } ?: "none"}",
        )
    }

    /**
     * Called after the store bootstrap replaced `active/`; does nothing in the app. PM R900 (same rule as iOS
     * BEAMIO_TEST_HOOKS): the unit-test hook that simulates on-disk corruption lives only in the test source set, in a
     * subclass that overrides this method; release and store contain no test hook.
     */
    protected open fun onStoreReplaced(activeDir: File) {}

    /** Thrown when the store build cannot prove that `active/` is the bundled zip. Nothing must be loaded. */
    class BundleIntegrityException(message: String) : IllegalStateException(message)

    /**
     * Activate an OTA bundle that was downloaded before the process was
     * stopped. This keeps a staged update from waiting for an APK restart.
     */
    private fun promoteStagingIfNewerLocked(): Boolean {
        if (!hasValidBundle(stagingDir)) return false
        if (!usesEmbeddedAssetPaths(stagingDir)) {
            Log.w(TAG, "bootstrap: staged bundle loads assets from /app/ (web build); discarding it")
            stagingDir.deleteRecursively()
            pendingVersion = null
            return false
        }
        val stagedVersion = readUpdateInfo(stagingDir)?.ver ?: return false
        val activeVersion = readUpdateInfo(activeDir)?.ver
        if (activeVersion != null && !isSemverNewer(activeVersion, stagedVersion)) {
            return false
        }
        if (!replaceActiveWithDirectoryLocked(stagingDir)) return false
        pendingVersion = null
        return true
    }

    fun activeVersion(): String = readUpdateInfo(activeDir)?.ver ?: "0.0.0"

    /**
     * Spec r3oj §25.52Y.38 item 2 (h) (PM R1908, R1920): a downloaded bundle is staged only when every byte of [zipFile]
     * hashes to [expectedZipSha256], the `zip_sha256` of the published update.json. Missing or different: nothing is
     * staged (not loaded). After staging, its content digest is recorded outside staging/ and active/ (B5 record) so the
     * trust check can match it when it becomes active.
     */
    fun installDownloadToStaging(zipFile: File, expectedVersion: String, expectedZipSha256: String?) {
        check(remotePwaUpdate) { REMOTE_DISABLED }
        val expected = expectedZipSha256?.lowercase()?.takeIf { SHA256_HEX.matches(it) }
        val actual = zipFile.inputStream().use { input ->
            val md = MessageDigest.getInstance("SHA-256")
            val buf = ByteArray(64 * 1024)
            while (true) { val n = input.read(buf); if (n < 0) break; md.update(buf, 0, n) }
            md.digest().joinToString("") { b -> "%02x".format(b) }
        }
        if (expected == null || actual != expected) {
            Log.w(TAG, "OTA zip sha256 ${shortDigest(actual)} not the published ${shortDigest(expected)}; not staged")
            throw IllegalStateException("Downloaded bundle sha256 not verified against the published update.json")
        }
        synchronized(lock) {
            if (stagingDir.exists()) {
                stagingDir.deleteRecursively()
            }
            stagingDir.mkdirs()
            zipFile.inputStream().use { input ->
                EmbeddedPwaZip.unzip(input, stagingDir)
            }
            if (!hasValidBundle(stagingDir)) {
                stagingDir.deleteRecursively()
                pendingVersion = null
                throw IllegalStateException("Downloaded bundle missing index.html")
            }
            if (!usesEmbeddedAssetPaths(stagingDir)) {
                stagingDir.deleteRecursively()
                pendingVersion = null
                throw webBuildError("Downloaded bundle")
            }
            // Ensure staging carries version metadata for cold-start pending restore.
            File(stagingDir, "update.json").writeText(
                JSONObject()
                    .put("ver", expectedVersion)
                    .put("filename", "SilentPassUI-$expectedVersion.zip")
                    .toString(),
            )
            writeOtaRecordLocked(contentDigest(stagingDir), actual, expectedVersion)
            pendingVersion = expectedVersion
        }
    }

    fun promoteStagingToActive() {
        check(remotePwaUpdate) { REMOTE_DISABLED }
        synchronized(lock) {
            if (!hasValidBundle(stagingDir)) {
                throw IllegalStateException("No staged PWA update")
            }
            // Staging may predate this check (written by an older shell).
            if (!usesEmbeddedAssetPaths(stagingDir)) {
                stagingDir.deleteRecursively()
                pendingVersion = null
                throw webBuildError("Staged bundle")
            }
            if (!replaceActiveWithDirectoryLocked(stagingDir)) {
                throw IllegalStateException("Failed to promote staged PWA update")
            }
            pendingVersion = null
        }
    }

    /**
     * Replace the active bundle without ever deleting it first.
     *
     * Both directories live under the same app-private filesystem, so renameTo
     * is the closest available atomic commit primitive. If the process dies
     * between the two renames, bootstrapIfNeeded() restores backupDir.
     */
    private fun replaceActiveWithDirectoryLocked(candidateDir: File): Boolean {
        if (!hasInstallableBundle(candidateDir)) return false
        if (backupDir.exists() && !backupDir.deleteRecursively()) return false

        val hadActive = activeDir.exists()
        if (hadActive && !activeDir.renameTo(backupDir)) return false
        if (candidateDir.renameTo(activeDir)) {
            return true
        }

        if (hadActive && !activeDir.exists() && backupDir.exists()) {
            backupDir.renameTo(activeDir)
        }
        return false
    }

    /**
     * §25.52Y.38 item 2 (b)(c)(g): remember, in memory only, the content digest of the bundled zip when every byte of it
     * hashes to [expectedZipSha256] (pwa-embed.lock). Nothing is written to disk, so a downloaded bundle cannot plant it.
     */
    private fun recordVerifiedBundleLocked(fullZipSha: String, bundledDir: File) {
        val expected = expectedZipSha256 ?: return
        if (fullZipSha != expected) {
            Log.w(TAG, "bootstrap: bundled zip sha256 ${shortDigest(fullZipSha)} != lock ${shortDigest(expected)}; no trust record")
            return
        }
        verifiedBundle = VerifiedBundle(this, fullZipSha, contentDigest(bundledDir))
    }

    /**
     * §25.52Y.38 item 2 (c) (iii) / (h), §25.52Y.41 item 2: the zip SHA-256 whose bytes active/ holds now, or null.
     * active/ must have exactly the content of the bundled zip verified at this process's bootstrap, or of a downloaded
     * bundle verified against the published update.json (B5 record). A partial or changed active/, or a downloaded bundle
     * without a record, gives null. The full content digest is recomputed whenever the file list, sizes or modification
     * times differ from the last check.
     */
    fun verifiedActiveZipSha256(): String? = synchronized(lock) {
        try {
            val fp = activeFingerprint()
            activeCheck?.takeIf { it.first == fp }?.let { return it.second }
            val digest = if (activeDir.isDirectory) contentDigest(activeDir) else null
            val embedded = verifiedBundle?.takeIf { it.store === this }
            val sha = when {
                digest == null -> null
                embedded != null && embedded.contentDigest == digest -> embedded.zipSha256
                else -> otaRecordZipSha(digest) // r3oj (h): a downloaded bundle verified against update.json
            }
            activeCheck = fp to sha
            sha
        } catch (_: Exception) {
            null
        }
    }

    /** Last trust check of active/: its fingerprint and the zip SHA-256 it matched (null = none). */
    @Volatile private var activeCheck: Pair<String, String?>? = null

    private val otaRecordDir: File get() = File(rootDir, OTA_RECORD_DIR)

    /** One small file per verified download, named by its content digest; keeps the newest [OTA_RECORDS_KEPT]. */
    private fun writeOtaRecordLocked(contentDigest: String, zipSha256: String, ver: String) {
        otaRecordDir.mkdirs()
        File(otaRecordDir, "$contentDigest.json").writeText(JSONObject().put("zip_sha256", zipSha256).put("ver", ver).toString())
        otaRecordDir.listFiles()?.sortedByDescending { it.lastModified() }?.drop(OTA_RECORDS_KEPT)?.forEach { it.delete() }
        activeCheck = null
    }

    private fun otaRecordZipSha(contentDigest: String): String? {
        if (!SHA256_HEX.matches(contentDigest)) return null
        val f = File(otaRecordDir, "$contentDigest.json").takeIf { it.isFile } ?: return null
        return runCatching { JSONObject(f.readText()).getString("zip_sha256").lowercase() }.getOrNull()?.takeIf { SHA256_HEX.matches(it) }
    }

    /** Relative path, size and modification time of every content file of active/ (no contents), hashed. */
    private fun activeFingerprint(): String {
        val root = activeDir.canonicalFile
        if (!root.isDirectory) return "absent"
        val lines = root.walkTopDown()
            .filter { it.isFile && it.name != LOADED_SHA_MARKER && it.name != LOADED_CONTENT_MARKER }
            .map { f -> f.canonicalFile.relativeTo(root).invariantSeparatorsPath + "\u0000" + f.length() + "\u0000" + f.lastModified() }
            .sorted().toList()
        return digestOfLines(lines)
    }

    /**
     * PM R1574: true when active/ is provably what this APK's bundled zip produced: `.loaded-sha256` equals
     * [expectedZipSha256], `.loaded-content-sha256` equals the current content digest of active/, and no script named by
     * index.html is missing.
     */
    private fun activeVerifiedForExpectedZipLocked(): Boolean = try {
        val expected = expectedZipSha256
        val zipMarker = File(activeDir, LOADED_SHA_MARKER).takeIf { it.isFile }?.readText()?.trim()
        val contentMarker = File(activeDir, LOADED_CONTENT_MARKER).takeIf { it.isFile }?.readText()?.trim()
        expected != null && zipMarker == expected && contentMarker != null &&
            hasCompleteBundle(activeDir) && usesEmbeddedAssetPaths(activeDir) && contentDigest(activeDir) == contentMarker
    } catch (_: Exception) {
        false
    }

    /** Recover a crash after active→backup but before candidate→active. */
    private fun recoverInterruptedSwapLocked() {
        if (!hasCompleteBundle(activeDir) && hasCompleteBundle(backupDir)) {
            backupDir.renameTo(activeDir)
        }
    }

    fun pendingUpdateVersion(): String? {
        if (!remotePwaUpdate) return null
        synchronized(lock) {
            if (pendingVersion == null || !hasInstallableBundle(stagingDir)) return null
            return pendingVersion
        }
    }

    private fun hasValidBundle(dir: File): Boolean =
        File(dir, "index.html").isFile

    /** PM R1574: [hasValidBundle] and every local script named by index.html exists (a missing script renders blank). */
    internal fun hasCompleteBundle(dir: File): Boolean = hasValidBundle(dir) && missingScripts(dir).isEmpty()

    /** Local `<script src>` paths of index.html that are not files under [dir] (absolute URLs are ignored). */
    internal fun missingScripts(dir: File): List<String> {
        val html = try { File(dir, "index.html").readText() } catch (_: Exception) { return listOf("index.html") }
        return SCRIPT_SRC.findAll(html).map { it.groupValues[1] }
            .filter { src -> !src.startsWith("//") && !Regex("^[a-zA-Z][a-zA-Z0-9+.-]*:").containsMatchIn(src) }
            .map { it.removePrefix("/").substringBefore('?').substringBefore('#') }
            .filter { it.isNotEmpty() && !File(dir, it).isFile }
            .toList()
    }

    private fun usesEmbeddedAssetPaths(dir: File): Boolean {
        val html = try {
            File(dir, "index.html").readText()
        } catch (_: Exception) {
            return false
        }
        return indexHtmlUsesEmbeddedAssetPaths(html)
    }

    private fun hasInstallableBundle(dir: File): Boolean =
        hasValidBundle(dir) && usesEmbeddedAssetPaths(dir)

    private fun readUpdateInfo(dir: File): EmbeddedPwaUpdateInfo? {
        val file = File(dir, "update.json")
        if (!file.isFile) return null
        return try {
            val json = JSONObject(file.readText())
            EmbeddedPwaUpdateInfo(
                ver = json.getString("ver"),
                filename = json.getString("filename"),
            )
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Digest of a bundle directory's file contents: every regular file (relative path and SHA-256), sorted,
     * except the [LOADED_SHA_MARKER] written by the store bootstrap. Two directories with the same digest
     * serve the same bytes.
     */
    internal fun contentDigest(dir: File): String = digestOfLines(contentLines(dir))

    private fun digestOfLines(lines: List<String>): String {
        val all = MessageDigest.getInstance("SHA-256")
        lines.forEach { all.update((it + "\n").toByteArray(Charsets.UTF_8)) }
        return all.digest().joinToString("") { b -> "%02x".format(b) }
    }

    /** Paths only (never file contents) of the first entries that differ, for the mismatch log. */
    private fun describeDifference(expected: List<String>, actual: List<String>): String {
        val e = expected.toSet()
        val a = actual.toSet()
        val missing = expected.filter { it !in a }.take(3).map { shortEntry(it) }
        val extra = actual.filter { it !in e }.take(3).map { shortEntry(it) }
        return "entries bundled=${expected.size} active=${actual.size} onlyBundled=$missing onlyActive=$extra"
    }

    /** "path\u0000sha" -> "path sha8…" for logs (PM R848: no full-length digest in shell logs). */
    private fun shortEntry(line: String): String {
        val i = line.indexOf('\u0000')
        return if (i < 0) line else line.substring(0, i) + " " + shortDigest(line.substring(i + 1))
    }

    private fun contentLines(dir: File): List<String> {
        val root = dir.canonicalFile
        return root.walkTopDown()
            .filter { it.isFile && it.name != LOADED_SHA_MARKER && it.name != LOADED_CONTENT_MARKER }
            .map { file ->
                val rel = file.canonicalFile.relativeTo(root).invariantSeparatorsPath
                val sha = MessageDigest.getInstance("SHA-256").digest(file.readBytes())
                    .joinToString("") { b -> "%02x".format(b) }
                "$rel\u0000$sha"
            }
            .sorted()
            .toList()
    }

    private fun readPendingVersionFromStaging(): String? {
        if (!remotePwaUpdate) return null
        if (!hasValidBundle(stagingDir)) return null
        return readUpdateInfo(stagingDir)?.ver
    }

    private class SharedPrefsAssetHashStore(context: Context) : ActivatedAssetHashStore {
        private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        override fun get(): String? = prefs.getString(KEY_ACTIVATED_ASSET_SHA256, null)

        override fun set(value: String) {
            prefs.edit().putString(KEY_ACTIVATED_ASSET_SHA256, value).apply()
        }
    }

    /** In-memory trust record of the bundled zip verified by this process's bootstrap (see [verifiedActiveZipSha256]). */
    private class VerifiedBundle(val store: EmbeddedPwaBundleStore, val zipSha256: String, val contentDigest: String)

    companion object {
        private val PROCESS_LOCK = Any()
        private val SHA256_HEX = Regex("^[0-9a-f]{64}$")
        /** B5 records of verified downloads (r3oj (h)); outside staging/ and active/, never written by unzip. */
        internal const val OTA_RECORD_DIR = "ota-verified"
        private const val OTA_RECORDS_KEPT = 3

        /** Process-wide: one bootstrap per process; set by it, read by [verifiedActiveZipSha256] under [PROCESS_LOCK]. */
        @Volatile private var verifiedBundle: VerifiedBundle? = null

        /** The zip SHA-256 active/ provably holds now (see the instance method), from the store that bootstrapped last. */
        fun currentVerifiedActiveZipSha256(): String? = verifiedBundle?.store?.verifiedActiveZipSha256()
        private const val TAG = "BeamioEmbeddedPwa"
        private const val PREFS_NAME = "embedded_pwa_bundle"
        private const val KEY_ACTIVATED_ASSET_SHA256 = "activated_asset_sha256"

        /** Written into `active/` by the store bootstrap: SHA-256 of the bundled zip it came from. */
        const val LOADED_SHA_MARKER = ".loaded-sha256"

        /** PM R1574: content digest of active/ recorded by the store bootstrap, used only to verify active/ when the APK zip is unreadable. */
        const val LOADED_CONTENT_MARKER = ".loaded-content-sha256"

        private val SCRIPT_SRC = Regex("""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", RegexOption.IGNORE_CASE)

        private const val REMOTE_DISABLED = "remote PWA update is disabled in this build (store build)"

        /**
         * `src`/`href` attribute values starting with `/app/` (any quoting).
         * Only attributes count: the embedded build's `fc:miniapp` meta JSON
         * legitimately contains `https://beamio.app/app/`.
         */
        private val WEB_BUILD_ASSET = Regex("""\b(?:src|href)\s*=\s*["']?/app/""", RegexOption.IGNORE_CASE)

        /**
         * False for a web build (`homepage: /app`); true for `build:embedded` (`PUBLIC_URL=/`).
         * Keep in sync with `scripts/checkEmbeddedPwaZip.sh` and the iOS shell.
         */
        fun indexHtmlUsesEmbeddedAssetPaths(html: String): Boolean =
            !WEB_BUILD_ASSET.containsMatchIn(html)

        private fun webBuildError(what: String) = IllegalStateException(
            "$what loads assets from /app/ (web build); rebuild with build:embedded (PUBLIC_URL=/)",
        )

        fun isSemverNewer(oldVer: String, newVer: String): Boolean {
            val oldParts = oldVer.split('.').map { it.toIntOrNull() ?: 0 }
            val newParts = newVer.split('.').map { it.toIntOrNull() ?: 0 }
            val count = maxOf(oldParts.size, newParts.size)
            for (i in 0 until count) {
                val o = oldParts.getOrElse(i) { 0 }
                val n = newParts.getOrElse(i) { 0 }
                if (n > o) return true
                if (n < o) return false
            }
            return false
        }
    }
}

/**
 * PM R848 (2026-11-14): shell logs and log-bound messages never carry a full 64-hex digest (the bundled ZIP SHA-256 and the
 * content digest change with every build and trip the T-131 LS-G1 log scan). Only the first 8 hex digits, then "…".
 */
internal fun shortDigest(h: String?): String = if (h == null) "null" else h.take(8) + "…"
