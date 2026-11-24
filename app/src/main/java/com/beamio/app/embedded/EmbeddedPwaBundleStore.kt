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
    /** BuildConfig.PWA_CONTENT_SHA256: content digest of the embedded ZIP, computed at build time. */
    private val expectedContentSha256: String? = null,
    /** BuildConfig.PWA_ZIP_VER: the embedded ZIP's version from pwa-embed.lock (logs and the OTA comparison only). */
    private val embeddedZipVer: String? = null,
    /** BuildConfig.VERSION_CODE: auxiliary record identity only (QA may change the ZIP under the same code). */
    private val shellBuild: Long = 0L,
    private val statter: FileStatter = AndroidFileStatter,
    /** Install identity ("fit:" + PackageInfo.firstInstallTime); null = unknown (records are not written). */
    private val installId: String? = null,
    /** Compile-time OTA public keys (production table, plus a test key only in QA builds). */
    otaKeys: List<OtaPublicKey> = emptyList(),
) {
    constructor(context: Context, remotePwaUpdate: Boolean, expectedZipSha256: String?) : this(
        context, remotePwaUpdate, expectedZipSha256, null, null, 0L, null, emptyList(),
    )

    constructor(
        context: Context,
        remotePwaUpdate: Boolean,
        expectedZipSha256: String?,
        expectedContentSha256: String?,
        embeddedZipVer: String?,
        shellBuild: Long,
        installId: String?,
        otaKeys: List<OtaPublicKey>,
    ) : this(
        rootDir = File(context.applicationContext.filesDir, EmbeddedPwaConstants.ROOT_DIR_NAME),
        // QaBootstrapFaults: debug-only fault injection for isolated acceptance; a plain pass-through in release/store.
        openBundledZip = com.beamio.app.qa.QaBootstrapFaults.wrapBundledZip(context) {
            context.applicationContext.assets.open(EmbeddedPwaConstants.BUNDLE_ASSET_NAME)
        },
        activatedAssetHash = SharedPrefsAssetHashStore(context.applicationContext),
        remotePwaUpdate = remotePwaUpdate,
        expectedZipSha256 = expectedZipSha256?.lowercase()?.takeIf { it.isNotBlank() },
        expectedContentSha256 = expectedContentSha256?.lowercase()?.takeIf { SHA256_HEX.matches(it) },
        embeddedZipVer = embeddedZipVer?.takeIf { it.isNotBlank() },
        shellBuild = shellBuild,
        statter = AndroidFileStatter,
        installId = installId,
        otaKeys = otaKeys,
    )

    // One lock for the whole process, not per instance: a relaunched MainActivity makes a new host and
    // store while the first bootstrap may still be running on the same silentpass_pwa/ directory.
    private val lock = PROCESS_LOCK

    val activeDir: File = File(rootDir, "active")
    val stagingDir: File = File(rootDir, "staging")
    val backupDir: File = File(rootDir, "backup")
    private val bundledDir: File get() = File(rootDir, "bundled")

    private val record = ColdStartRecordFile(rootDir)
    /** Signature verifier with the compile-time key table (no keys = nothing verifies = no OTA). */
    internal val otaVerifier = EmbeddedPwaOtaVerifier(otaKeys, shellBuild)
    private val keyTableId: String = EmbeddedPwaOtaKeys.tableId(otaKeys)
    /** Owner tag of this process's partial staging directory. */
    internal val instanceId: String = java.util.UUID.randomUUID().toString().replace("-", "")
    internal val counters = ColdStartCounters()
    private val variant: String get() = if (remotePwaUpdate) VARIANT_RELEASE else VARIANT_STORE
    private val pin: String? get() = expectedZipSha256?.takeIf { SHA256_HEX.matches(it) }

    /** The last cold start's path ("fast" / "full") and miss reason, for logs and tests. */
    @Volatile internal var lastPath: String = ""
        private set
    @Volatile internal var lastReason: String = ""
        private set

    /** True after a bootstrap that selected a verified active (fast hit or a trusted full pass); a later trust miss is then a mismatch. */
    @Volatile private var expectTrusted = false

    @Volatile
    private var pendingVersion: String? = readPendingVersionFromStaging()

    fun bootstrapIfNeeded() {
        val t0 = System.nanoTime()
        val c0 = counters.snapshot()
        verifiedBundle = null
        activeCheck = null
        expectTrusted = false
        synchronized(lock) {
            rootDir.mkdirs()
            val miss = fastPathMissReason()
            if (miss == null) {
                // Fast path: no APK ZIP read, no unpack, no version comparison, no full digest. Bridge trust is
                // seeded only from BuildConfig constants; the first trust check still hashes active/ in full.
                verifiedBundle = VerifiedBundle(this, checkNotNull(pin), checkNotNull(expectedContentSha256))
                expectTrusted = true
                lastPath = "fast"
                lastReason = "hit"
                logColdStart("fast", "hit", t0, c0)
                return
            }
            lastPath = "full"
            lastReason = miss
            try {
                if (!record.invalidate()) {
                    // "Delete before change": a record that cannot be deleted blocks any change to active/. Open a
                    // complete active as it is (trust still needs a full digest), write nothing, retry next start.
                    Log.e(TAG, "coldstart record cannot be deleted; active/ is not changed this start")
                    if (pin != null && expectedContentSha256 != null) verifiedBundle = VerifiedBundle(this, pin!!, expectedContentSha256)
                    if (!hasCompleteBundle(activeDir)) throw IllegalStateException("coldstart record cannot be deleted and no complete active bundle")
                    return
                }
                deleteForeignPartialsLocked()
                if (remotePwaUpdate) fullPassReleaseLocked(readOtaStatusLocked()) else bootstrapStoreLocked()
            } finally {
                logColdStart("full", miss, t0, c0)
            }
        }
    }

    private fun logColdStart(path: String, reason: String, t0: Long, c0: IntArray) {
        val c = counters.snapshot()
        Log.i(
            TAG,
            "coldstart path=$path variant=$variant zipRead=${c[0] - c0[0]} unpack=${c[1] - c0[1]} " +
                "compare=${c[2] - c0[2]} digest=${c[3] - c0[3]} reason=$reason ms=${(System.nanoTime() - t0) / 1_000_000}",
        )
    }

    /** null = fast-path hit; otherwise the miss reason. Reads only small files and lstat facts. */
    private fun fastPathMissReason(): String? {
        val pinNow = pin ?: return "no-pin"
        val contentNow = expectedContentSha256 ?: return "no-content-const"
        val install = installId ?: return "install-unknown"
        val rec = record.read() ?: return if (record.file.exists()) "parse-error" else "no-record"
        if (rec.ruleVersion != ColdStartRecord.RULE_VERSION) return "rule-changed"
        if (rec.variant != variant) return "variant-changed"
        if (rec.installId != install) return "install-changed"
        if (rec.embeddedZipSha256 != pinNow) return "zip-changed"
        if (rec.embeddedContentDigest != contentNow) return "content-const-changed"
        if (record.tmpFile.exists() || bundledDir.exists()) return "residue"
        if (foreignPartialExistsLocked()) return "residue"
        if (!remotePwaUpdate && (backupDir.exists() || stagingDir.exists())) return "residue"
        if (remotePwaUpdate && File(stagingDir, "index.html").exists()) return "staging-present"
        if (!hasCompleteBundle(activeDir)) return "active-incomplete"
        val fp = activeFingerprintV2() ?: return "fingerprint-unknown"
        if (fp != rec.activeFingerprint) return "fingerprint-changed"
        when (rec.selectedOrigin) {
            ColdStartRecord.ORIGIN_EMBEDDED -> if (rec.selectedContentDigest != contentNow) return "selected-mismatch"
            ColdStartRecord.ORIGIN_OTA -> {
                if (!remotePwaUpdate) return "selected-mismatch"
                if (rec.otaKeyTableId != keyTableId) return "key-table-changed"
                val f = File(rootDir, rec.otaSignedFile ?: return "selected-mismatch")
                if (!f.isFile || f.length() > 8192 || sha256Hex(f.readBytes()) != rec.otaSignedFileSha256) return "ota-signed-changed"
            }
            else -> return "selected-mismatch"
        }
        return null
    }

    private fun activeFingerprintV2(): String? =
        bundleFingerprint(activeDir, statter, setOf(LOADED_SHA_MARKER, LOADED_CONTENT_MARKER))

    /** Reference to the signed object of an OTA bundle selected by a full pass (selection only, never trust). */
    private data class OtaRef(val signedFile: String, val signedFileSha256: String, val keyId: String, val zipSha256: String)

    /** Writes the completion record after active/ is final and verified ("write after"); a failure only costs a full pass next time. */
    private fun commitRecordLocked(origin: String, selectedDigest: String, ota: OtaRef?, decision: String, embeddedOutcome: String, network: String) {
        val pinNow = pin ?: return
        val contentNow = expectedContentSha256 ?: return
        val install = installId ?: return Unit.also { Log.w(TAG, "coldstart record not written: install identity unknown") }
        val fp = activeFingerprintV2() ?: return
        val ok = record.write(
            ColdStartRecord(
                ruleVersion = ColdStartRecord.RULE_VERSION,
                variant = variant,
                installId = install,
                shellBuild = shellBuild,
                embeddedZipSha256 = pinNow,
                embeddedContentDigest = contentNow,
                embeddedVer = embeddedZipVer,
                embeddedOutcome = embeddedOutcome,
                selectedOrigin = origin,
                selectedContentDigest = selectedDigest,
                selectedVer = readUpdateInfo(activeDir)?.ver,
                otaSignedFile = ota?.signedFile,
                otaSignedFileSha256 = ota?.signedFileSha256,
                otaKeyId = ota?.keyId,
                otaKeyTableId = if (ota != null) keyTableId else null,
                otaZipSha256 = ota?.zipSha256,
                generation = generationCounter,
                network = network,
                activeFingerprint = fp,
                decision = decision,
                completedAtUtc = ColdStartRecord.nowUtc(),
            ),
        )
        if (!ok) Log.w(TAG, "coldstart record not written (next start runs the full pass)")
    }

    /** Reads every byte of the APK ZIP and returns its SHA-256 without unpacking (zipRead +1). */
    private fun hashBundledZipLocked(): String {
        counters.zipRead++
        val digest = MessageDigest.getInstance("SHA-256")
        openBundledZip().use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) { val n = input.read(buf); if (n < 0) break; digest.update(buf, 0, n) }
        }
        return digest.digest().joinToString("") { b -> "%02x".format(b) }
    }

    /**
     * Unpacks the APK ZIP into `bundled/` and returns (full SHA-256, partial asset hash). zipRead +1, unpack +1.
     * ZipInputStream stops at the central directory; the rest is read so the SHA covers every byte.
     */
    private fun unpackBundledZipLocked(): Pair<String, String> {
        counters.zipRead++
        counters.unpack++
        val dir = bundledDir
        if (dir.exists()) dir.deleteRecursively()
        dir.mkdirs()
        val digest = MessageDigest.getInstance("SHA-256")
        var partialHash: String? = null
        openBundledZip().use { input ->
            DigestInputStream(input, digest).use { hashed ->
                EmbeddedPwaZip.unzip(object : FilterInputStream(hashed) { override fun close() {} }, dir)
                partialHash = (digest.clone() as MessageDigest).digest().joinToString("") { byte -> "%02x".format(byte) }
                val buf = ByteArray(64 * 1024)
                while (hashed.read(buf) >= 0) Unit
            }
        }
        val full = digest.digest().joinToString("") { byte -> "%02x".format(byte) }
        return full to (partialHash ?: full)
    }

    /** A signed staged download that verified (S+). */
    private data class StagedCandidate(val digest: String, val manifest: OtaManifest, val ref: OtaRef) {
        val ver: PwaVersion get() = checkNotNull(PwaVersion.parse(manifest.ver))
    }

    /**
     * Release (website) full pass:
     *  1. recover an interrupted swap; legacy `ota-verified/` records are deleted (never trust);
     *  2. classify the embedded ZIP (pin match), the local bundle (V_EMB / V_OTA / U by full digest and signature) and
     *     a staged download (S+ only with a valid signed object; anything else in staging is deleted);
     *  3. [selectCandidate]; install the embedded ZIP, promote the staged bundle or keep the local one;
     *  4. for a verified selection, a newer S+ is promoted afterwards (compare first, then promote);
     *  5. seed trust from constants and write the record only for a verified selection.
     */
    private fun fullPassReleaseLocked(network: String) {
        recoverInterruptedSwapLocked()
        File(rootDir, LEGACY_OTA_RECORD_DIR).takeIf { it.exists() }?.deleteRecursively()
        var reference = expectedContentSha256
        var zipHash: String? = null
        var assetHash: String? = null
        var bundledReady = false
        try {
            if (reference == null) {
                val (full, partial) = unpackBundledZipLocked()
                zipHash = full
                assetHash = partial
                bundledReady = true
            } else {
                zipHash = hashBundledZipLocked()
            }
        } catch (e: Exception) {
            bundledDir.deleteRecursively()
            Log.w(TAG, "bootstrap: bundled SilentPassUI.zip unreadable (${e.javaClass.simpleName})")
        }
        if (bundledReady) {
            reference = checkBundledCandidateLocked() ?: return
        }
        val embeddedOk = zipHash != null && pin != null && zipHash == pin && reference != null

        val activeComplete = hasCompleteBundle(activeDir) && usesEmbeddedAssetPaths(activeDir)
        val activeDigest = if (activeComplete) countedDigest(activeDir) else null
        val activeVerStr = if (activeComplete) readUpdateInfo(activeDir)?.ver else null
        var activeOta: Pair<OtaManifest, OtaRef>? = null
        val local = when {
            activeDigest == null -> LocalClass.U
            activeDigest == reference -> LocalClass.V_EMB
            else -> {
                activeOta = otaIdentityLocked(activeDigest, activeVerStr)
                if (activeOta != null) LocalClass.V_OTA else LocalClass.U
            }
        }
        val staged = classifyStagingLocked()
        val embeddedVer = PwaVersion.parse(embeddedZipVer ?: if (bundledReady) readUpdateInfo(bundledDir)?.ver else null)
        val sel = selectCandidate(
            local, PwaVersion.parse(activeVerStr), activeDir.exists(), embeddedOk, embeddedVer, staged != null, staged?.ver,
        )
        counters.compare += sel.compares
        Log.i(TAG, "bootstrap local=$local embeddedOk=$embeddedOk staged=${staged?.manifest?.ver ?: "none"} pick=${sel.pick} decision=${sel.decision} network=$network")

        var decision = sel.decision
        var origin = ColdStartRecord.ORIGIN_EMBEDDED
        var selectedDigest: String? = reference
        var otaRef: OtaRef? = null
        var verified = true
        when (sel.pick) {
            Pick.LOCAL -> {
                bundledDir.deleteRecursively()
                if (local == LocalClass.V_OTA) {
                    origin = ColdStartRecord.ORIGIN_OTA
                    selectedDigest = activeDigest
                    otaRef = activeOta?.second
                }
            }
            Pick.EMBEDDED -> {
                val installed = installEmbeddedLocked(bundledReady, checkNotNull(zipHash), assetHash, verifiedInstall = true)
                if (installed == null) {
                    // The embedded package failed after unpacking (content not the build constant): no verified selection.
                    verified = false
                    decision = null
                    if (staged != null && promoteStagedLocked(staged)) {
                        origin = ColdStartRecord.ORIGIN_OTA
                        selectedDigest = staged.digest
                        otaRef = staged.ref
                        verified = true
                        decision = "selected-ota-over-embedded"
                    } else if (!hasCompleteBundle(activeDir)) {
                        throw IllegalStateException("Bundled SilentPassUI.zip does not match its build identity and no local bundle")
                    }
                } else {
                    selectedDigest = installed
                }
            }
            Pick.STAGED -> {
                val s = checkNotNull(staged)
                if (!promoteStagedLocked(s)) throw IllegalStateException("Failed to activate the verified staged bundle")
                origin = ColdStartRecord.ORIGIN_OTA
                selectedDigest = s.digest
                otaRef = s.ref
                bundledDir.deleteRecursively()
            }
            Pick.NONE -> {
                verified = false
                if (activeComplete) {
                    bundledDir.deleteRecursively()
                    Log.w(TAG, "bootstrap: no verified candidate; keeping the local bundle without bridge trust")
                } else if (zipHash != null) {
                    // The APK ZIP is readable but not the pinned one and nothing else is loadable: install it as a recovery
                    // UI without bridge trust and without a record.
                    installEmbeddedLocked(bundledReady, zipHash, assetHash, verifiedInstall = false)
                        ?: if (!hasCompleteBundle(activeDir)) throw IllegalStateException("No loadable bundle") else Unit
                } else {
                    throw IllegalStateException("Bundled SilentPassUI.zip unreadable and no complete active bundle")
                }
            }
        }

        // Compare first, then promote: a newer signed staged bundle replaces a verified selection afterwards.
        if (verified && staged != null && sel.pick != Pick.STAGED && stagingDir.exists()) {
            val selectedVer = PwaVersion.parse(readUpdateInfo(activeDir)?.ver)
            counters.compare++
            if (selectedVer != null && staged.ver > selectedVer) {
                if (promoteStagedLocked(staged)) {
                    origin = ColdStartRecord.ORIGIN_OTA
                    selectedDigest = staged.digest
                    otaRef = staged.ref
                    decision = "promoted-ota"
                }
            } else {
                deleteStagingLocked("not newer than the selected bundle")
            }
        }

        if (zipHash != null && zipHash == pin && expectedContentSha256 != null) {
            verifiedBundle = VerifiedBundle(this, zipHash, expectedContentSha256)
        } else if (zipHash != null && zipHash == pin && expectedContentSha256 == null && reference != null) {
            verifiedBundle = VerifiedBundle(this, zipHash, reference)
        }
        if (verified && decision != null && selectedDigest != null) {
            expectTrusted = true
            commitRecordLocked(origin, selectedDigest, otaRef, decision, sel.embeddedOutcome, network)
        }
        gcSignedObjectsLocked()
    }

    /**
     * Unpacks (when needed) and installs the embedded ZIP. Returns its content digest, or null when the unpacked content
     * is not the build constant (E-x) and [verifiedInstall] is set (nothing is replaced then).
     */
    private fun installEmbeddedLocked(bundledReady: Boolean, zipHash: String, assetHash: String?, verifiedInstall: Boolean): String? {
        var asset = assetHash
        if (!bundledReady) {
            try {
                val (full, partial) = unpackBundledZipLocked()
                if (full != zipHash) throw IllegalStateException("bundled zip changed between reads")
                asset = partial
            } catch (e: Exception) {
                bundledDir.deleteRecursively()
                Log.w(TAG, "bootstrap: bundled SilentPassUI.zip unreadable on unpack (${e.javaClass.simpleName})")
                return null
            }
            if (!hasValidBundle(bundledDir) || !usesEmbeddedAssetPaths(bundledDir)) {
                bundledDir.deleteRecursively()
                return null
            }
        }
        val bundledDigest = countedDigest(bundledDir)
        if (verifiedInstall && expectedContentSha256 != null && bundledDigest != expectedContentSha256) {
            Log.e(TAG, "bootstrap: bundled content ${shortDigest(bundledDigest)} != build constant ${shortDigest(expectedContentSha256)}; not installed")
            bundledDir.deleteRecursively()
            return null
        }
        if (!replaceActiveWithDirectoryLocked(bundledDir)) {
            bundledDir.deleteRecursively()
            throw IllegalStateException("Failed to activate bundled SilentPassUI.zip")
        }
        asset?.let { activatedAssetHash.set(it) }
        generationCounter++
        Log.i(TAG, "bootstrap activated bundled=${readUpdateInfo(activeDir)?.ver}")
        return bundledDigest
    }

    /**
     * Checks an unpacked `bundled/` before it may be used (index.html, embedded asset paths). Returns its content
     * digest, or null when bootstrap ends here keeping a valid active; throws when nothing loadable remains.
     */
    private fun checkBundledCandidateLocked(): String? {
        if (!hasValidBundle(bundledDir)) {
            bundledDir.deleteRecursively()
            if (hasCompleteBundle(activeDir)) return null
            throw IllegalStateException("Bundled SilentPassUI.zip did not contain index.html")
        }
        if (!usesEmbeddedAssetPaths(bundledDir)) {
            bundledDir.deleteRecursively()
            if (hasCompleteBundle(activeDir)) {
                Log.w(TAG, "bootstrap: bundled SilentPassUI.zip loads assets from /app/ (web build); keeping active")
                return null
            }
            throw webBuildError("Bundled SilentPassUI.zip")
        }
        return countedDigest(bundledDir)
    }

    /**
     * S+ classification of `staging/`: complete, embedded asset paths, and `ota-signed/<digest>.json` verifies with a
     * compile-time key for exactly this content, version and shell. Anything else in staging is deleted (never a candidate).
     */
    private fun classifyStagingLocked(): StagedCandidate? {
        if (!stagingDir.exists()) return null
        if (!hasCompleteBundle(stagingDir) || !usesEmbeddedAssetPaths(stagingDir)) {
            deleteStagingLocked("incomplete or web build")
            return null
        }
        // Before a staged bundle can be promoted, its signed object is verified again (no per-process cache) and
        // the full digest of staging/ is recomputed now and must equal payload.contentDigest.
        val digest = countedDigest(stagingDir)
        val identity = otaIdentityLocked(digest, readUpdateInfo(stagingDir)?.ver, fresh = true)
        if (identity == null) {
            deleteStagingLocked("no valid signed object")
            return null
        }
        return StagedCandidate(digest, identity.first, identity.second)
    }

    private fun promoteStagedLocked(s: StagedCandidate): Boolean {
        if (!replaceActiveWithDirectoryLocked(stagingDir)) return false
        pendingVersion = null
        generationCounter++
        Log.i(TAG, "bootstrap promoted signed staged bundle ver=${s.manifest.ver}")
        return true
    }

    private fun deleteStagingLocked(why: String) {
        if (stagingDir.exists()) {
            Log.w(TAG, "bootstrap: staged bundle discarded ($why)")
            stagingDir.deleteRecursively()
        }
        pendingVersion = null
    }

    private fun countedDigest(dir: File): String {
        counters.fullDigest++
        processFullDigests++
        return contentDigest(dir)
    }

    /** Store-build activation failure: delete the record first, then active/ (pinning semantics: nothing is loaded). */
    private fun deleteActiveLocked() {
        record.invalidate()
        activeDir.deleteRecursively()
    }

    /**
     * Store build: the bundled zip is the only source of `active/`.
     *  1. `staging/` and `backup/` are discarded (no remote or interrupted bundle is ever promoted).
     *  2. The bundled zip's SHA-256 must equal [expectedZipSha256] (pinning); otherwise active/ is deleted, nothing loads.
     *  3. `active/` is kept, without unpacking, when its content digest equals the build-time constant
     *     [expectedContentSha256]; otherwise the ZIP is unpacked, checked against the constant and replaces active/
     *     (an active that cannot be proven equal to the pinned package is repaired).
     *  4. After the replacement `active/` must equal the bundled content; if not, it is deleted and bootstrap
     *     fails (the caller shows the unavailable page; no fallback to an old `active/`).
     *  5. The completion record is written last.
     */
    private fun bootstrapStoreLocked() {
        val discarded = listOf(stagingDir, backupDir).filter { it.exists() }
        discarded.forEach { it.deleteRecursively() }
        pendingVersion = null
        if (discarded.isNotEmpty()) {
            Log.w(TAG, "store bootstrap: discarded ${discarded.joinToString { it.name }} (remote PWA update disabled)")
        }
        bundledDir.deleteRecursively()

        val constant = expectedContentSha256
        val activeDigestNow = if (constant != null && hasCompleteBundle(activeDir) && usesEmbeddedAssetPaths(activeDir)) countedDigest(activeDir) else null
        val keepWithoutUnpack = constant != null && activeDigestNow == constant
        var zipSha: String
        try {
            zipSha = if (keepWithoutUnpack) hashBundledZipLocked() else unpackBundledZipLocked().first
        } catch (e: Exception) {
            bundledDir.deleteRecursively()
            // the APK zip could not be read this time. Load active/ only if it is provably the content this same
            // APK zip (expectedZipSha256) produced on an earlier start: both markers match and its files hash to the
            // recorded content digest, with no missing script. Otherwise nothing is loaded. Nothing is deleted either way.
            if (activeVerifiedForExpectedZipLocked()) {
                Log.w(TAG, "store bootstrap: bundled SilentPassUI.zip unreadable (${e.javaClass.simpleName}); loading active, verified as this APK's content")
                return
            }
            throw BundleIntegrityException("store bootstrap: bundled SilentPassUI.zip unreadable and active/ not verified; nothing loaded")
        }
        // Fail closed: a store build without an expected SHA (lock missing at build time) loads nothing.
        if (expectedZipSha256 == null || zipSha != expectedZipSha256) {
            bundledDir.deleteRecursively()
            deleteActiveLocked()
            throw BundleIntegrityException(
                "store bootstrap: bundled SilentPassUI.zip sha256 ${shortDigest(zipSha)} != expected ${shortDigest(expectedZipSha256)}; nothing loaded",
            )
        }

        val bundledDigest: String
        val bundledVersion: String?
        val source: String
        val previousActive: String?
        if (keepWithoutUnpack) {
            bundledDigest = checkNotNull(constant)
            bundledVersion = readUpdateInfo(activeDir)?.ver
            previousActive = activeDigestNow
            source = "kept"
        } else {
            if (!hasValidBundle(bundledDir)) {
                bundledDir.deleteRecursively()
                deleteActiveLocked()
                throw BundleIntegrityException("store bootstrap: bundled SilentPassUI.zip did not contain index.html")
            }
            if (!usesEmbeddedAssetPaths(bundledDir)) {
                bundledDir.deleteRecursively()
                deleteActiveLocked()
                throw webBuildError("Bundled SilentPassUI.zip")
            }
            val bundledLines = countedLines(bundledDir)
            bundledDigest = digestOfLines(bundledLines)
            if (constant != null && bundledDigest != constant) {
                bundledDir.deleteRecursively()
                deleteActiveLocked()
                throw BundleIntegrityException(
                    "store bootstrap: bundled content ${shortDigest(bundledDigest)} != build constant ${shortDigest(constant)}; nothing loaded",
                )
            }
            bundledVersion = readUpdateInfo(bundledDir)?.ver
            previousActive = if (activeDir.isDirectory) (activeDigestNow ?: countedDigest(activeDir)) else null
            if (previousActive == bundledDigest) {
                bundledDir.deleteRecursively()
                source = "kept"
            } else {
                if (!replaceActiveWithDirectoryLocked(bundledDir)) {
                    bundledDir.deleteRecursively()
                    deleteActiveLocked()
                    throw BundleIntegrityException("store bootstrap: failed to activate bundled SilentPassUI.zip")
                }
                backupDir.deleteRecursively()
                generationCounter++
                source = "bundled"
            }
            onStoreReplaced(activeDir)
            val loadedLines = countedLines(activeDir)
            val loadedDigest = digestOfLines(loadedLines)
            if (loadedDigest != bundledDigest) {
                deleteActiveLocked()
                throw BundleIntegrityException(
                    "store bootstrap: active/ content ${shortDigest(loadedDigest)} != bundled ${shortDigest(bundledDigest)} after replacement; " +
                        "${describeDifference(bundledLines, loadedLines)}; nothing loaded",
                )
            }
        }
        File(activeDir, LOADED_SHA_MARKER).writeText(zipSha)
        File(activeDir, LOADED_CONTENT_MARKER).writeText(bundledDigest)
        activatedAssetHash.set(zipSha)
        verifiedBundle = VerifiedBundle(this, zipSha, bundledDigest)
        Log.i(
            TAG,
            "store bootstrap: source=$source ver=$bundledVersion zipSha256=${shortDigest(zipSha)} " +
                "contentDigest=${shortDigest(bundledDigest)} previousActive=${previousActive?.let { shortDigest(it) } ?: "none"}",
        )
        val decision = when {
            source == "kept" -> "kept-identical"
            previousActive == null -> "installed-first"
            else -> "repaired-unverifiable"
        }
        expectTrusted = true
        commitRecordLocked(ColdStartRecord.ORIGIN_EMBEDDED, bundledDigest, null, decision, if (source == "kept") "identical" else "enabled", "n/a")
    }

    private fun countedLines(dir: File): List<String> {
        counters.fullDigest++
        processFullDigests++
        return contentLines(dir)
    }

    /**
 * Called after the store bootstrap replaced `active/`; does nothing in the app. (same rule as iOS
     * BEAMIO_TEST_HOOKS): the unit-test hook that simulates on-disk corruption lives only in the test source set, in a
     * subclass that overrides this method; release and store contain no test hook.
     */
    protected open fun onStoreReplaced(activeDir: File) {}

    /** Thrown when the store build cannot prove that `active/` is the bundled zip. Nothing must be loaded. */
    class BundleIntegrityException(message: String) : IllegalStateException(message)

    /**
     * Version of the active bundle, or null when it cannot be read (update.json missing, truncated or corrupt).
     * An unreadable version is unknown, never "0.0.0": callers must not compare or display a substitute.
     */
    fun activeVersion(): String? = readUpdateInfo(activeDir)?.ver

    /** Raised when a downloaded bundle is not staged; [verdict] is recorded in ota-status. */
    class OtaRejected(val verdict: OtaVerdict, message: String) : IllegalStateException(message)

    /**
     * Stages a signed download: [check] must be an OK manifest check from [otaVerifier]; [zipFile]
     * (outside silentpass_pwa/) must match the signed size and SHA-256, be a canonical ZIP, contain update.json with the
     * signed version (never rewritten) and unpack to exactly the signed content digest. Unpacking happens outside the lock
     * into a partial directory owned by this process; under the lock the reference version is read again, the signed
     * object is written atomically, then the partial directory becomes `staging/`.
     */
    fun installDownloadToStaging(check: OtaManifestCheck, zipFile: File) {
        check(remotePwaUpdate) { REMOTE_DISABLED }
        val manifest = check.manifest
        val signed = check.signedObject
        if (check.verdict != OtaVerdict.OK || manifest == null || signed == null) {
            throw OtaRejected(check.verdict, "manifest not verified: ${check.verdict.code}")
        }
        val partial = File(rootDir, "$PARTIAL_PREFIX$instanceId")
        try {
            val verdict = unpackVerifiedDownload(otaVerifier, manifest, zipFile, partial)
            if (verdict != OtaVerdict.OK) throw OtaRejected(verdict, "download ${verdict.code}")
            if (!hasCompleteBundle(partial)) throw OtaRejected(OtaVerdict.CONTENT_MISMATCH, "download missing scripts named by index.html")
            if (!usesEmbeddedAssetPaths(partial)) throw OtaRejected(OtaVerdict.CONTENT_MISMATCH, "download is a web build")
            synchronized(lock) {
                val reference = PwaVersion.parse(selectedVerifiedVersionLocked())
                val offered = checkNotNull(PwaVersion.parse(manifest.ver))
                if (reference == null || offered <= reference) throw OtaRejected(OtaVerdict.DOWNGRADE, "no longer newer than the selected bundle")
                if (!writeSignedObjectLocked(manifest.contentDigest, signed)) throw IllegalStateException("signed object not written")
                stagingDir.deleteRecursively()
                if (!partial.renameTo(stagingDir)) throw IllegalStateException("staging rename failed")
                pendingVersion = manifest.ver
                gcSignedObjectsLocked()
            }
        } finally {
            if (partial.exists()) partial.deleteRecursively()
        }
    }

    /**
     * Explicit apply from the page: the staged bundle must be S+ (signed object verifies for its content) and strictly
     * newer than the selected verified bundle; the record must be deleted first (else refused).
     */
    fun promoteStagingToActive() {
        check(remotePwaUpdate) { REMOTE_DISABLED }
        synchronized(lock) {
            if (!hasValidBundle(stagingDir)) throw IllegalStateException("No staged PWA update")
            if (!usesEmbeddedAssetPaths(stagingDir)) {
                deleteStagingLocked("web build")
                throw webBuildError("Staged bundle")
            }
            val staged = classifyStagingLocked() ?: throw IllegalStateException("staged_not_verified")
            val reference = PwaVersion.parse(selectedVerifiedVersionLocked())
                ?: throw IllegalStateException("active_version_unknown")
            if (staged.ver <= reference) {
                deleteStagingLocked("not newer")
                throw IllegalStateException("staged_not_newer")
            }
            if (!replaceActiveWithDirectoryLocked(stagingDir)) {
                throw IllegalStateException("Failed to promote staged PWA update")
            }
            pendingVersion = null
            generationCounter++
        }
    }

    /**
     * Version the OTA check compares against: the selected verified bundle (active/ when it is verified as embedded or as
     * a signed download), otherwise the embedded build constant. Never an unverified active version, never "0.0.0".
     */
    fun selectedVerifiedVersion(): String? = synchronized(lock) { selectedVerifiedVersionLocked() }

    private fun selectedVerifiedVersionLocked(): String? {
        val trusted = verifiedActiveZipSha256()
        val activeVer = readUpdateInfo(activeDir)?.ver
        return if (trusted != null && PwaVersion.parse(activeVer) != null) activeVer else embeddedZipVer?.takeIf { PwaVersion.parse(it) != null }
    }

    private val signedDir: File get() = File(rootDir, SIGNED_DIR)

    /** Per-process cache: SHA-256 of a signed object file -> verified manifest. */
    private val signedCache = HashMap<String, OtaManifest>()

    /**
     * OTA identity of a bundle whose full digest is [digest]: `ota-signed/<digest>.json` verifies with a compile-time key,
     * for this digest, version [ver] and shell. The verification is cached by the file bytes' SHA-256 (once per process).
     */
    private fun otaIdentityLocked(digest: String, ver: String?, fresh: Boolean = false): Pair<OtaManifest, OtaRef>? {
        if (!SHA256_HEX.matches(digest)) return null
        val f = File(signedDir, "$digest.json").takeIf { it.isFile && it.length() <= 8192 } ?: return null
        val bytes = try { f.readBytes() } catch (_: Exception) { return null }
        val fileSha = sha256Hex(bytes)
        val manifest = signedCache[fileSha]?.takeIf { !fresh && it.contentDigest == digest && it.ver == ver }
            ?: otaVerifier.verifyStoredIdentity(bytes, digest, ver)?.also { signedCache[fileSha] = it }
            ?: return null
        return manifest to OtaRef("$SIGNED_DIR/$digest.json", fileSha, manifest.keyId, manifest.sha256)
    }

    private fun writeSignedObjectLocked(digest: String, signed: JSONObject): Boolean = try {
        signedDir.mkdirs()
        val target = File(signedDir, "$digest.json")
        val tmp = File(signedDir, ".$digest.json.tmp")
        java.io.FileOutputStream(tmp).use { out ->
            out.write(signed.toString().toByteArray(Charsets.UTF_8))
            out.flush()
            out.fd.sync()
        }
        tmp.renameTo(target)
    } catch (_: Exception) {
        false
    }

    /** Keeps the newest 3 signed objects plus the ones the current active and staging bundles reference. */
    private fun gcSignedObjectsLocked() {
        val files = signedDir.listFiles()?.filter { it.isFile } ?: return
        val keep = HashSet<String>()
        record.read()?.otaSignedFile?.let { keep.add(File(it).name) }
        files.sortedByDescending { it.lastModified() }.take(SIGNED_KEPT).forEach { keep.add(it.name) }
        files.filter { it.name !in keep }.forEach { it.delete() }
    }

    private fun foreignPartialExistsLocked(): Boolean =
        rootDir.listFiles()?.any { it.name.startsWith(PARTIAL_PREFIX) && it.name != "$PARTIAL_PREFIX$instanceId" } ?: false

    private fun deleteForeignPartialsLocked() {
        rootDir.listFiles()?.filter { it.name.startsWith(PARTIAL_PREFIX) && it.name != "$PARTIAL_PREFIX$instanceId" }
            ?.forEach { it.deleteRecursively() }
    }

    /** Diagnostic OTA check status (`ota-status.v1.json`, atomic write); never trust, never selection input. */
    fun writeOtaStatus(result: String, verdict: String?, ver: String?) {
        try {
            synchronized(lock) {
                rootDir.mkdirs()
                val tmp = File(rootDir, ".$OTA_STATUS_FILE.tmp")
                tmp.writeText(JSONObject().put("result", result).put("verdict", verdict ?: JSONObject.NULL)
                    .put("ver", ver ?: JSONObject.NULL).put("atUtc", ColdStartRecord.nowUtc()).toString())
                tmp.renameTo(File(rootDir, OTA_STATUS_FILE))
            }
        } catch (_: Exception) {
        }
    }

    private fun readOtaStatusLocked(): String = try {
        File(rootDir, OTA_STATUS_FILE).takeIf { it.isFile }?.readText()?.let { JSONObject(it).getString("result") } ?: "unconfirmed"
    } catch (_: Exception) {
        "unconfirmed"
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
        // "Delete before change": no completion record may survive a change to active/; if it cannot be deleted, refuse.
        if (!record.invalidate()) {
            Log.e(TAG, "coldstart record cannot be deleted; refusing to change active/")
            return false
        }
        activeCheck = null
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
     * §25.52Y.38 item 2 (c) (iii) / (h), §25.52Y.41 item 2: the zip SHA-256 whose bytes active/ holds now, or null.
     * active/ must have exactly the content of the bundled zip verified at this process's bootstrap, or of a downloaded
     * bundle verified against the published update.json (B5 record). A partial or changed active/, or a downloaded bundle
     * without a record, gives null. The full content digest is recomputed whenever the file list, sizes or modification
     * times differ from the last check.
     */
    fun verifiedActiveZipSha256(): String? {
        var mismatch = false
        val result = synchronized(lock) {
            try {
                // Cache key: the same metadata fingerprint as the completion record (size, mtime, ctime, inode). A
                // same-size rewrite with the mtime restored still changes ctime, so it is never served from the cache.
                // Without a readable fingerprint nothing is cached and every check hashes active/ in full.
                val fp = activeFingerprintV2()
                if (fp != null) activeCheck?.takeIf { it.first == fp }?.let { return@synchronized it.second }
                val digest = if (activeDir.isDirectory) countedDigest(activeDir) else null
                val embedded = verifiedBundle?.takeIf { it.store === this }
                val sha = when {
                    digest == null -> null
                    embedded != null && embedded.contentDigest == digest -> embedded.zipSha256
                    else -> otaIdentityLocked(digest, readUpdateInfo(activeDir)?.ver)?.first?.sha256 // signed download
                }
                Log.i(TAG, "trust digest computed trusted=${sha != null} process_total=$processFullDigests")
                if (sha == null && digest != null && expectTrusted) {
                    // The bundle selected as verified no longer matches any trusted source (silently changed after
                    // start). The bridge stays closed, the completion record is deleted (next cold start repairs) and
                    // the page is taken down (trustMismatchListener → unavailable page with Retry).
                    expectTrusted = false
                    record.invalidate()
                    mismatch = true
                }
                activeCheck = if (fp != null) fp to sha else null
                sha
            } catch (_: Exception) {
                null
            }
        }
        if (mismatch) {
            Log.e(TAG, "trust mismatch: active/ is not the verified bundle; bridge closed, record deleted, page taken down")
            trustMismatchListener?.invoke()
        }
        return result
    }

    /** Last trust check of active/: its fingerprint and the zip SHA-256 it matched (null = none). */
    @Volatile private var activeCheck: Pair<String, String?>? = null

    /**
 *true when active/ is provably what this APK's bundled zip produced: `.loaded-sha256` equals
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
            record.invalidate()
            if (activeDir.exists()) activeDir.deleteRecursively()
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

    /**: [hasValidBundle] and every local script named by index.html exists (a missing script renders blank). */
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

    /** "path\u0000sha" -> "path sha8…" for logs (no full-length digest in shell logs). */
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
        /** Legacy (pre-signature) download records: never trust, deleted by the release full pass. */
        internal const val OTA_RECORD_DIR = "ota-verified"
        private const val LEGACY_OTA_RECORD_DIR = OTA_RECORD_DIR
        /** Signed objects of downloads (`<contentDigest>.json`), verified with compile-time keys once per process. */
        internal const val SIGNED_DIR = "ota-signed"
        private const val SIGNED_KEPT = 3
        internal const val PARTIAL_PREFIX = ".staging-partial-"

        /**
         * Spec v2 §6 steps 10–13 for a downloaded [zipFile] against a verified [manifest]: size, SHA-256, canonical ZIP
         * (structure from the central directory first, then unpacking into [partial], each entry cut off at its declared
         * length), update.json version and the beamio-tree-v1 digest. On anything but OK, [partial] is deleted.
         */
        internal fun unpackVerifiedDownload(verifier: EmbeddedPwaOtaVerifier, manifest: OtaManifest, zipFile: File, partial: File): OtaVerdict {
            val integrity = verifier.verifyBundle(manifest, zipFile)
            if (integrity != OtaVerdict.OK) return integrity
            val verdict = try {
                val layout = EmbeddedPwaCanonicalZip.validate(zipFile)
                val unpacked = EmbeddedPwaCanonicalZip.extract(zipFile, layout, partial)
                when {
                    unpacked.updateVer != manifest.ver -> OtaVerdict.CONTENT_MISMATCH
                    unpacked.contentDigest != manifest.contentDigest -> OtaVerdict.CONTENT_MISMATCH
                    else -> OtaVerdict.OK
                }
            } catch (e: EmbeddedPwaCanonicalZip.NonCanonical) {
                Log.w(TAG, "OTA download not canonical: ${e.message}")
                OtaVerdict.NONCANONICAL_ZIP
            } catch (e: java.io.IOException) {
                Log.w(TAG, "OTA download unreadable type=${e.javaClass.simpleName}")
                OtaVerdict.NONCANONICAL_ZIP
            }
            if (verdict != OtaVerdict.OK) partial.deleteRecursively()
            return verdict
        }
        internal const val OTA_STATUS_FILE = "ota-status.v1.json"

        internal fun sha256Hex(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

        /** Process-wide: one bootstrap per process; set by it, read by [verifiedActiveZipSha256] under [PROCESS_LOCK]. */
        @Volatile private var verifiedBundle: VerifiedBundle? = null

        /** The zip SHA-256 active/ provably holds now (see the instance method), from the store that bootstrapped last. */
        fun currentVerifiedActiveZipSha256(): String? = verifiedBundle?.store?.verifiedActiveZipSha256()
        internal const val VARIANT_STORE = "store"
        internal const val VARIANT_RELEASE = "release"

        /** Process-wide number of full content digests (bootstrap and trust checks), for the acceptance counts. */
        @Volatile internal var processFullDigests = 0

        /**
         * Called (on the checking thread) when a trust check finds that the active bundle selected as verified no longer
         * matches: the shell takes the page down and shows the unavailable page with Retry.
         */
        @Volatile var trustMismatchListener: (() -> Unit)? = null

        /** Process-wide count of active/ changes, for the record's generation (logs and tests only). */
        @Volatile private var generationCounter = 0L
        private const val TAG = "BeamioEmbeddedPwa"
        private const val PREFS_NAME = "embedded_pwa_bundle"
        private const val KEY_ACTIVATED_ASSET_SHA256 = "activated_asset_sha256"

        /** Written into `active/` by the store bootstrap: SHA-256 of the bundled zip it came from. */
        const val LOADED_SHA_MARKER = ".loaded-sha256"

        /**: content digest of active/ recorded by the store bootstrap, used only to verify active/ when the APK zip is unreadable. */
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

        /** Strict comparison: true only when both versions parse as plain x.y.z and [newVer] is higher. */
        fun isSemverNewer(oldVer: String, newVer: String): Boolean {
            val o = PwaVersion.parse(oldVer) ?: return false
            val n = PwaVersion.parse(newVer) ?: return false
            return n > o
        }
    }
}

/**
 * (2026-11-14): shell logs and log-bound messages never carry a full 64-hex digest (the bundled ZIP SHA-256 and the
 * content digest change with every build and trip the T-131 LS-G1 log scan). Only the first 8 hex digits, then "…".
 */
internal fun shortDigest(h: String?): String = if (h == null) "null" else h.take(8) + "…"
