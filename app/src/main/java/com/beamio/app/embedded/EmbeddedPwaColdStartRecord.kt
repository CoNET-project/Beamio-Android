package com.beamio.app.embedded

import android.os.Build
import android.system.Os
import android.system.OsConstants
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Cold-start completion record, version 2: `silentpass_pwa/coldstart-record.v2.json`.
 *
 * The record only decides which bundle a cold start opens and whether the embedded ZIP must be read again. It never
 * takes part in bridge trust: trust comes from BuildConfig constants or a compile-time key signature, checked against a
 * full content digest of active/. It binds the install identity (firstInstallTime), the embedded ZIP identity and the
 * rule version; it is written with tmp + fsync + rename + directory fsync and deleted before any change to active/.
 */
internal data class ColdStartRecord(
    val ruleVersion: Int,
    val variant: String,
    val installId: String,
    val shellBuild: Long,
    val embeddedZipSha256: String,
    val embeddedContentDigest: String,
    val embeddedVer: String?,
    val embeddedOutcome: String,
    val selectedOrigin: String,
    val selectedContentDigest: String,
    val selectedVer: String?,
    val otaSignedFile: String?,
    val otaSignedFileSha256: String?,
    val otaKeyId: String?,
    val otaKeyTableId: String?,
    val otaZipSha256: String?,
    val generation: Long,
    val network: String,
    val activeFingerprint: String,
    val decision: String,
    val completedAtUtc: String,
) {
    fun toJson(): String {
        val ota: Any = if (selectedOrigin == ORIGIN_OTA) JSONObject()
            .put("signedFile", otaSignedFile)
            .put("signedFileSha256", otaSignedFileSha256)
            .put("keyId", otaKeyId)
            .put("keyTableId", otaKeyTableId)
            .put("zipSha256", otaZipSha256) else JSONObject.NULL
        return JSONObject()
            .put("schema", SCHEMA)
            .put("ruleVersion", ruleVersion)
            .put("platform", "android")
            .put("variant", variant)
            .put("installId", installId)
            .put("shellBuild", shellBuild.toString())
            .put("embedded", JSONObject()
                .put("zipSha256", embeddedZipSha256)
                .put("contentDigest", embeddedContentDigest)
                .put("ver", embeddedVer ?: JSONObject.NULL)
                .put("outcome", embeddedOutcome))
            .put("selected", JSONObject()
                .put("origin", selectedOrigin)
                .put("contentDigest", selectedContentDigest)
                .put("ver", selectedVer ?: JSONObject.NULL)
                .put("ota", ota)
                .put("generation", generation))
            .put("network", network)
            .put("activeFingerprint", activeFingerprint)
            .put("decision", decision)
            .put("result", RESULT_COMPLETE)
            .put("completedAtUtc", completedAtUtc)
            .toString()
    }

    companion object {
        const val SCHEMA = "beamio.pwa.coldstart.v2"
        /** Selection rule version (compile time); bump whenever the selection rules change. */
        const val RULE_VERSION = 2
        const val RESULT_COMPLETE = "complete"
        const val FILE_NAME = "coldstart-record.v2.json"
        const val TMP_NAME = ".coldstart-record.v2.json.tmp"
        val LEGACY_NAMES = listOf("coldstart-record.v1.json", ".coldstart-record.v1.json.tmp")
        const val ORIGIN_EMBEDDED = "embedded"
        const val ORIGIN_OTA = "ota"
        private val HEX64 = Regex("^[0-9a-f]{64}$")
        private val HEX16 = Regex("^[0-9a-f]{16}$")

        private fun JSONObject.optStr(key: String): String? = if (isNull(key)) null else optString(key).takeIf { it.isNotEmpty() }

        /** Parses a record; anything malformed, of another schema or not "complete" gives null (= no record). */
        fun parse(text: String): ColdStartRecord? = try {
            val j = JSONObject(text)
            val e = j.getJSONObject("embedded")
            val s = j.getJSONObject("selected")
            val ota = if (s.isNull("ota")) null else s.getJSONObject("ota")
            val rec = ColdStartRecord(
                ruleVersion = j.getInt("ruleVersion"),
                variant = j.getString("variant"),
                installId = j.getString("installId"),
                shellBuild = j.getString("shellBuild").toLong(),
                embeddedZipSha256 = e.getString("zipSha256"),
                embeddedContentDigest = e.getString("contentDigest"),
                embeddedVer = e.optStr("ver"),
                embeddedOutcome = e.getString("outcome"),
                selectedOrigin = s.getString("origin"),
                selectedContentDigest = s.getString("contentDigest"),
                selectedVer = s.optStr("ver"),
                otaSignedFile = ota?.optStr("signedFile"),
                otaSignedFileSha256 = ota?.optStr("signedFileSha256"),
                otaKeyId = ota?.optStr("keyId"),
                otaKeyTableId = ota?.optStr("keyTableId"),
                otaZipSha256 = ota?.optStr("zipSha256"),
                generation = s.getLong("generation"),
                network = j.getString("network"),
                activeFingerprint = j.getString("activeFingerprint"),
                decision = j.getString("decision"),
                completedAtUtc = j.getString("completedAtUtc"),
            )
            val otaOk = when (rec.selectedOrigin) {
                ORIGIN_EMBEDDED -> ota == null
                ORIGIN_OTA -> rec.otaSignedFile != null && HEX64.matches(rec.otaSignedFileSha256 ?: "") &&
                    HEX16.matches(rec.otaKeyTableId ?: "") && HEX64.matches(rec.otaZipSha256 ?: "")
                else -> false
            }
            val ok = j.getString("schema") == SCHEMA && j.getString("platform") == "android" &&
                j.getString("result") == RESULT_COMPLETE && rec.installId.isNotEmpty() &&
                HEX64.matches(rec.embeddedZipSha256) && HEX64.matches(rec.embeddedContentDigest) &&
                HEX64.matches(rec.selectedContentDigest) && HEX64.matches(rec.activeFingerprint) && otaOk
            if (ok) rec else null
        } catch (_: Exception) {
            null
        }

        fun nowUtc(): String = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
            .apply { timeZone = TimeZone.getTimeZone("UTC") }.format(Date())
    }
}

/** Reads, writes and deletes the record in [rootDir] (`silentpass_pwa/`), never inside active/, staging/ or bundled/. */
internal class ColdStartRecordFile(private val rootDir: File) {
    val file: File get() = File(rootDir, ColdStartRecord.FILE_NAME)
    val tmpFile: File get() = File(rootDir, ColdStartRecord.TMP_NAME)

    fun read(): ColdStartRecord? = try {
        file.takeIf { it.isFile }?.readText()?.let { ColdStartRecord.parse(it) }
    } catch (_: Exception) {
        null
    }

    /** Atomic commit: tmp, fsync(fd), rename over the final name, fsync(directory). A failure leaves "no record". */
    fun write(record: ColdStartRecord): Boolean = try {
        rootDir.mkdirs()
        val tmp = tmpFile
        FileOutputStream(tmp).use { out ->
            out.write(record.toJson().toByteArray(Charsets.UTF_8))
            out.flush()
            out.fd.sync()
        }
        if (!tmp.renameTo(file)) {
            tmp.delete()
            false
        } else {
            fsyncDirectory(rootDir)
            true
        }
    } catch (_: Exception) {
        tmpFile.delete()
        false
    }

    /**
     * "Delete before change": removes the record, a stray tmp and the legacy v1 files, then syncs the directory.
     * Returns false when any of them is still there: the caller must not change active/.
     */
    fun invalidate(): Boolean {
        val all = listOf(file, tmpFile) + ColdStartRecord.LEGACY_NAMES.map { File(rootDir, it) }
        val had = all.any { it.exists() }
        all.forEach { it.delete() }
        if (had) fsyncDirectory(rootDir)
        return all.none { it.exists() }
    }

    private fun fsyncDirectory(dir: File) {
        if (Build.VERSION.SDK_INT < 26) return
        try {
            FileChannel.open(dir.toPath(), StandardOpenOption.READ).use { it.force(true) }
        } catch (_: Throwable) {
            // Directory fsync is not available everywhere. Losing the directory entry only means "no record" on the
            // next start: a full pass, the safe direction.
        }
    }
}

/** lstat facts used by the metadata fingerprint. */
internal data class FileStat(
    val size: Long,
    val mtimeNs: Long,
    val ctimeNs: Long,
    val inode: Long,
    val isSymlink: Boolean,
    val isRegular: Boolean,
    val isDirectory: Boolean,
)

internal fun interface FileStatter {
    /** lstat (no symlink following); null when it cannot be read. */
    fun lstat(f: File): FileStat?
}

/** Production lstat through android.system.Os (ctime/mtime in ns from API 27, seconds before). */
internal object AndroidFileStatter : FileStatter {
    override fun lstat(f: File): FileStat? = try {
        val st = Os.lstat(f.path)
        val (mt, ct) = if (Build.VERSION.SDK_INT >= 27) {
            (st.st_mtim.tv_sec * 1_000_000_000L + st.st_mtim.tv_nsec) to (st.st_ctim.tv_sec * 1_000_000_000L + st.st_ctim.tv_nsec)
        } else {
            (st.st_mtime * 1_000_000_000L) to (st.st_ctime * 1_000_000_000L)
        }
        FileStat(
            size = st.st_size,
            mtimeNs = mt,
            ctimeNs = ct,
            inode = st.st_ino,
            isSymlink = OsConstants.S_ISLNK(st.st_mode),
            isRegular = OsConstants.S_ISREG(st.st_mode),
            isDirectory = OsConstants.S_ISDIR(st.st_mode),
        )
    } catch (_: Throwable) {
        null
    }
}

/**
 * Metadata fingerprint of a bundle directory: one line `relpath NUL size NUL mtime_ns NUL ctime_ns NUL inode`
 * per regular file (markers excluded), sorted, SHA-256. A symlink, an unreadable entry or a missing directory gives
 * null (unknown = miss). No file contents are read.
 */
internal fun bundleFingerprint(dir: File, statter: FileStatter, excludedNames: Set<String>): String? {
    val rootStat = statter.lstat(dir) ?: return null
    if (rootStat.isSymlink || !rootStat.isDirectory) return null
    val lines = ArrayList<String>()
    val stack = ArrayDeque<Pair<File, String>>()
    stack.addLast(dir to "")
    while (stack.isNotEmpty()) {
        val (d, prefix) = stack.removeLast()
        val children = d.listFiles() ?: return null
        for (child in children) {
            val st = statter.lstat(child) ?: return null
            if (st.isSymlink) return null
            val rel = if (prefix.isEmpty()) child.name else "$prefix/${child.name}"
            when {
                st.isDirectory -> stack.addLast(child to rel)
                st.isRegular -> if (child.name !in excludedNames) {
                    lines.add("$rel\u0000${st.size}\u0000${st.mtimeNs}\u0000${st.ctimeNs}\u0000${st.inode}")
                }
                else -> return null
            }
        }
    }
    lines.sortWith { a, b -> compareUtf8(a, b) }
    val md = MessageDigest.getInstance("SHA-256")
    lines.forEach { md.update((it + "\n").toByteArray(Charsets.UTF_8)) }
    return md.digest().joinToString("") { b -> "%02x".format(b) }
}

private fun compareUtf8(a: String, b: String): Int {
    val x = a.toByteArray(Charsets.UTF_8)
    val y = b.toByteArray(Charsets.UTF_8)
    val n = minOf(x.size, y.size)
    for (i in 0 until n) {
        val c = (x[i].toInt() and 0xff) - (y[i].toInt() and 0xff)
        if (c != 0) return c
    }
    return x.size - y.size
}

/**
 * Strict PWA version: exactly three dot-separated decimal numbers, no leading zeros, at most 9 digits each.
 * Anything else (suffixes, prefixes, two or four parts, empty) is "unknown" (null), never 0.
 */
internal data class PwaVersion(val major: Int, val minor: Int, val patch: Int) : Comparable<PwaVersion> {
    override fun compareTo(other: PwaVersion): Int =
        compareValuesBy(this, other, { it.major }, { it.minor }, { it.patch })

    companion object {
        private val STRICT = Regex("^(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})$")

        fun parse(ver: String?): PwaVersion? {
            val m = STRICT.matchEntire(ver ?: return null) ?: return null
            return PwaVersion(m.groupValues[1].toInt(), m.groupValues[2].toInt(), m.groupValues[3].toInt())
        }
    }
}

/** Local bundle class (cryptographic conclusion only, never the record or a version number). */
internal enum class LocalClass { V_EMB, V_OTA, U }

internal enum class Pick { LOCAL, EMBEDDED, STAGED, NONE }

/**
 * Result of [selectCandidate]. [decision] null means: do not write a completion record (retry next start).
 * [compares] counts version comparisons made by the selection (for the acceptance counters).
 */
internal data class Selection(val pick: Pick, val decision: String?, val embeddedOutcome: String, val compares: Int)

/**
 * The single selection rule for a full pass (same table on iOS and Android).
 *
 * - Verified local bundle (V_EMB / V_OTA): kept unless the embedded package is strictly newer ("same or older never
 *   overwrites"); an older or same-version embedded package is recorded as compared-but-not-enabled.
 * - Unverifiable local bundle (U): choose only among verified candidates (embedded ZIP that matches the pin, signed
 *   staged download), the higher version wins; on a tie the embedded package wins. No verified candidate: nothing is
 *   selected (the caller keeps an untrusted but complete local bundle without bridge, or shows the retry page).
 * Staged downloads for a verified local bundle are handled after this decision by the caller.
 */
internal fun selectCandidate(
    local: LocalClass,
    localVer: PwaVersion?,
    hasActive: Boolean,
    embeddedOk: Boolean,
    embeddedVer: PwaVersion?,
    stagedVerified: Boolean,
    stagedVer: PwaVersion?,
): Selection {
    if (local != LocalClass.U) {
        if (!embeddedOk) return Selection(Pick.LOCAL, null, "not-selected", 0)
        if (local == LocalClass.V_EMB) return Selection(Pick.LOCAL, "kept-identical", "identical", 0)
        if (embeddedVer == null || localVer == null) return Selection(Pick.LOCAL, "embedded-ver-unknown", "ver-unknown", 0)
        return when {
            embeddedVer > localVer -> Selection(Pick.EMBEDDED, "installed-newer", "enabled", 1)
            embeddedVer == localVer -> Selection(Pick.LOCAL, "embedded-same-ignored", "same-version-ignored", 1)
            else -> Selection(Pick.LOCAL, "embedded-older-ignored", "older-ignored", 1)
        }
    }
    val installDecision = if (hasActive) "repaired-unverifiable" else "installed-first"
    val staged = stagedVerified && stagedVer != null
    return when {
        embeddedOk && staged -> {
            if (embeddedVer == null) Selection(Pick.EMBEDDED, "embedded-ver-unknown", "ver-unknown", 0)
            else if (stagedVer!! > embeddedVer) Selection(Pick.STAGED, "selected-ota-over-embedded", "not-selected", 1)
            else Selection(Pick.EMBEDDED, installDecision, "enabled", 1)
        }
        embeddedOk -> Selection(Pick.EMBEDDED, if (embeddedVer == null) "embedded-ver-unknown" else installDecision, if (embeddedVer == null) "ver-unknown" else "enabled", 0)
        staged -> Selection(Pick.STAGED, "selected-ota-over-embedded", "not-selected", 0)
        else -> Selection(Pick.NONE, null, "not-selected", 0)
    }
}

/** Per-store counters for the cold-start acceptance: APK ZIP opens, unpacks, version comparisons, full digests. */
internal class ColdStartCounters {
    @Volatile var zipRead = 0
    @Volatile var unpack = 0
    @Volatile var compare = 0
    @Volatile var fullDigest = 0
    fun snapshot() = intArrayOf(zipRead, unpack, compare, fullDigest)
}
