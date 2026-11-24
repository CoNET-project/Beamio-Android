package com.beamio.app.embedded

import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.security.MessageDigest
import java.util.zip.CRC32
import java.util.zip.Inflater

/**
 * Canonical ZIP form of a downloaded OTA bundle (manifest v2 spec §5: structure, limits and letter
 * case). The structure is checked from the central directory first; entries are unpacked only afterwards, each read at
 * the offset the central directory gives (never by streaming local headers), so every platform sees the same entry set.
 *
 * [validate] reads only headers. [extract] unpacks a validated layout into a directory, never writing more than the
 * declared uncompressed length of an entry, and returns the beamio-tree-v1 digest and the `update.json` version.
 */
internal object EmbeddedPwaCanonicalZip {
    const val MAX_ENTRIES = 10000
    const val MAX_UNCOMPRESSED = 256L * 1024 * 1024
    const val MAX_NAME_BYTES = 255
    /** Shell-side limit for the root update.json, which is held in memory to read its version (not a spec v2.0 rule). */
    const val MAX_UPDATE_JSON_BYTES = 1L * 1024 * 1024
    /** Allowed general-purpose flag bits: 1–2 (deflate option hints) and 11 (UTF-8 names). */
    private const val ALLOWED_FLAGS = 0x0806
    private val NAME_CHARS = Regex("""^[A-Za-z0-9._/@+~-]+$""")
    val FORBIDDEN_FILES = setOf(".source.json", ".loaded-sha256", ".loaded-content-sha256")

    class NonCanonical(reason: String) : Exception(reason)

    data class Entry(
        val name: String,
        val method: Int,
        val crc: Long,
        val compressedSize: Long,
        val size: Long,
        val dataOffset: Long,
    )

    data class Layout(val entries: List<Entry>)

    data class Extracted(val contentDigest: String, val updateVer: String?)

    /** Why [name] is not canonical, or null when it is. */
    fun nameProblem(name: String): String? {
        if (name.isEmpty()) return "empty name"
        if (name.toByteArray(Charsets.UTF_8).size > MAX_NAME_BYTES) return "name too long"
        if (!NAME_CHARS.matches(name)) return "disallowed character"
        if (name.startsWith("/")) return "absolute path"
        if (name.endsWith("/")) return "directory entry"
        val parts = name.split('/')
        for (p in parts) {
            if (p.isEmpty() || p == "." || p == "..") return "empty, . or .. segment"
            if (p == "__MACOSX") return "__MACOSX"
            if (p.startsWith("._")) return "AppleDouble ._ file"
        }
        if (parts.last() in FORBIDDEN_FILES) return "shell marker file"
        return null
    }

    /** Structure, names and limits from the central directory and local headers; no entry data is inflated. */
    fun validate(file: File): Layout = RandomAccessFile(file, "r").use { raf -> validate(raf) }

    private fun validate(raf: RandomAccessFile): Layout {
        val length = raf.length()
        if (length < 22) throw NonCanonical("too short")
        val eocdPos = length - 22
        val eocd = readAt(raf, eocdPos, 22)
        if (u32(eocd, 0) != 0x06054b50L) throw NonCanonical("end of central directory is not at the end of the file")
        if (u16(eocd, 20) != 0) throw NonCanonical("archive comment present")
        val disk = u16(eocd, 4)
        val cdDisk = u16(eocd, 6)
        val entriesOnDisk = u16(eocd, 8)
        val entriesTotal = u16(eocd, 10)
        val cdSize = u32(eocd, 12)
        val cdOffset = u32(eocd, 16)
        if (disk != 0 || cdDisk != 0 || entriesOnDisk != entriesTotal) throw NonCanonical("multi-disk zip")
        if (entriesTotal == 0xffff || cdSize == 0xffffffffL || cdOffset == 0xffffffffL) throw NonCanonical("zip64")
        if (entriesTotal > MAX_ENTRIES) throw NonCanonical("too many entries")
        if (cdOffset + cdSize != eocdPos) throw NonCanonical("central directory does not end at the end-of-central-directory record")
        if (cdSize > Int.MAX_VALUE) throw NonCanonical("central directory too large")
        val cd = readAt(raf, cdOffset, cdSize.toInt())

        val names = HashSet<String>()
        val folded = HashSet<String>()
        val entries = ArrayList<Entry>(entriesTotal)
        var p = 0
        var total = 0L
        var nextLocal = 0L
        for (n in 0 until entriesTotal) {
            if (p + 46 > cd.size || u32(cd, p) != 0x02014b50L) throw NonCanonical("bad central directory header")
            val madeBy = u16(cd, p + 4)
            val flags = u16(cd, p + 8)
            val method = u16(cd, p + 10)
            val crc = u32(cd, p + 16)
            val compSize = u32(cd, p + 20)
            val size = u32(cd, p + 24)
            val nameLen = u16(cd, p + 28)
            val extraLen = u16(cd, p + 30)
            val commentLen = u16(cd, p + 32)
            val extAttr = u32(cd, p + 38)
            val localOff = u32(cd, p + 42)
            if (p + 46 + nameLen > cd.size) throw NonCanonical("bad central directory header")
            val nameBytes = cd.copyOfRange(p + 46, p + 46 + nameLen)
            val name = String(nameBytes, Charsets.UTF_8)
            p += 46 + nameLen + extraLen + commentLen
            if (p > cd.size) throw NonCanonical("bad central directory header")
            if (flags and 0x1 != 0) throw NonCanonical("encrypted entry")
            if (flags and ALLOWED_FLAGS.inv() != 0) throw NonCanonical("flags ${Integer.toHexString(flags)}")
            if (commentLen != 0) throw NonCanonical("entry comment")
            if (method != 0 && method != 8) throw NonCanonical("compression method $method")
            if (compSize == 0xffffffffL || size == 0xffffffffL || localOff == 0xffffffffL) throw NonCanonical("zip64 entry")
            nameProblem(name)?.let { throw NonCanonical(it) }
            if (!names.add(name)) throw NonCanonical("duplicate entry")
            if (!folded.add(name.lowercase(java.util.Locale.ROOT))) throw NonCanonical("entry differs from another only by letter case")
            if (madeBy shr 8 == 3) {
                val type = (extAttr ushr 16) and 0xF000L
                if (type != 0L && type != 0x8000L) throw NonCanonical("not a regular file")
            }
            if (localOff != nextLocal) throw NonCanonical("local header is not where the previous entry ended (gap, overlap or reordering)")
            if (localOff + 30 > cdOffset) throw NonCanonical("bad local header")
            val lh = readAt(raf, localOff, 30)
            if (u32(lh, 0) != 0x04034b50L) throw NonCanonical("bad local header")
            if (u16(lh, 6) != flags || u16(lh, 8) != method) throw NonCanonical("local header flags or method differ")
            if (u32(lh, 14) != crc || u32(lh, 18) != compSize || u32(lh, 22) != size) throw NonCanonical("local header crc or sizes differ")
            val lNameLen = u16(lh, 26)
            val lExtraLen = u16(lh, 28)
            if (localOff + 30 + lNameLen > cdOffset) throw NonCanonical("bad local header")
            if (!readAt(raf, localOff + 30, lNameLen).contentEquals(nameBytes)) throw NonCanonical("local name differs")
            val dataStart = localOff + 30 + lNameLen + lExtraLen
            if (dataStart + compSize > cdOffset) throw NonCanonical("data out of range")
            nextLocal = dataStart + compSize
            total += size
            // Declared total is checked against the limit before anything is inflated (all headers are read first).
            if (total > MAX_UNCOMPRESSED) throw NonCanonical("uncompressed size too large")
            entries.add(Entry(name, method, crc, compSize, size, dataStart))
        }
        if (p != cd.size) throw NonCanonical("central directory size mismatch")
        if (nextLocal != cdOffset) throw NonCanonical("bytes between the last entry and the central directory")
        if ("index.html" !in names) throw NonCanonical("missing index.html")
        if ("update.json" !in names) throw NonCanonical("missing update.json")
        return Layout(entries)
    }

    /**
     * Unpacks a validated [layout] of [file] into [dest] (created empty). Each entry is inflated from its central
     * directory offset and cut off at its declared length: more output than declared, a size or CRC-32 difference, or an
     * unfinished deflate stream is non-canonical. Returns the beamio-tree-v1 digest of the entries and update.json's ver.
     */
    fun extract(file: File, layout: Layout, dest: File): Extracted {
        if (dest.exists()) dest.deleteRecursively()
        if (!dest.mkdirs()) throw IllegalStateException("cannot create ${dest.name}")
        val destCanonical = dest.canonicalPath + File.separator
        val lines = ArrayList<String>(layout.entries.size)
        var updateJsonBytes: ByteArray? = null
        RandomAccessFile(file, "r").use { raf ->
            for (e in layout.entries) {
                val out = File(dest, e.name)
                if (!out.canonicalPath.startsWith(destCanonical)) throw NonCanonical("path outside the bundle")
                out.parentFile?.mkdirs()
                val sha = MessageDigest.getInstance("SHA-256")
                val crc = CRC32()
                if (e.name == "update.json" && e.size > MAX_UPDATE_JSON_BYTES) throw NonCanonical("update.json too large")
                val keep = if (e.name == "update.json") java.io.ByteArrayOutputStream(e.size.toInt()) else null
                var written = 0L
                FileOutputStream(out).use { fos ->
                    val sink = { buf: ByteArray, len: Int ->
                        if (written + len > e.size) throw NonCanonical("entry longer than declared")
                        fos.write(buf, 0, len)
                        sha.update(buf, 0, len)
                        crc.update(buf, 0, len)
                        keep?.write(buf, 0, len)
                        written += len
                    }
                    raf.seek(e.dataOffset)
                    if (e.method == 0) {
                        copyRaw(raf, e.compressedSize, sink)
                    } else {
                        inflateRaw(raf, e.compressedSize, e.size, sink)
                    }
                }
                if (written != e.size) throw NonCanonical("size differs")
                if (crc.value != e.crc) throw NonCanonical("crc differs")
                lines.add("${e.name}\u0000${EmbeddedPwaOtaVerifier.hex(sha.digest())}")
                if (keep != null) updateJsonBytes = keep.toByteArray()
            }
        }
        // Defence in depth: the shell's own marker files must not exist before the shell writes them.
        for (marker in FORBIDDEN_FILES) {
            if (File(dest, marker).exists()) throw NonCanonical("shell marker file in the bundle")
        }
        val updateObj = try {
            JSONObject(String(checkNotNull(updateJsonBytes), Charsets.UTF_8))
        } catch (_: Exception) {
            throw NonCanonical("update.json is not a JSON object")
        }
        return Extracted(treeDigestOfLines(lines), updateObj.opt("ver") as? String)
    }

    /** beamio-tree-v1 over "path\u0000sha" lines (paths canonical ASCII, so string order is byte order). */
    fun treeDigestOfLines(lines: List<String>): String {
        val md = MessageDigest.getInstance("SHA-256")
        lines.sorted().forEach { md.update((it + "\n").toByteArray(Charsets.UTF_8)) }
        return EmbeddedPwaOtaVerifier.hex(md.digest())
    }

    private fun copyRaw(raf: RandomAccessFile, count: Long, sink: (ByteArray, Int) -> Unit) {
        val buf = ByteArray(64 * 1024)
        var left = count
        while (left > 0) {
            val n = raf.read(buf, 0, minOf(buf.size.toLong(), left).toInt())
            if (n < 0) throw NonCanonical("unexpected end of file")
            sink(buf, n)
            left -= n
        }
    }

    private fun inflateRaw(raf: RandomAccessFile, compressed: Long, declared: Long, sink: (ByteArray, Int) -> Unit) {
        val inflater = Inflater(true)
        try {
            val inBuf = ByteArray(64 * 1024)
            val outBuf = ByteArray(64 * 1024)
            var left = compressed
            var produced = 0L
            while (!inflater.finished()) {
                if (inflater.needsInput()) {
                    if (left <= 0) throw NonCanonical("deflate stream does not finish")
                    val n = raf.read(inBuf, 0, minOf(inBuf.size.toLong(), left).toInt())
                    if (n < 0) throw NonCanonical("unexpected end of file")
                    left -= n
                    inflater.setInput(inBuf, 0, n)
                }
                // Never ask for more than one byte past the declared length: anything beyond it is refused at once.
                val room = minOf(outBuf.size.toLong(), declared - produced + 1).toInt()
                val got = try {
                    inflater.inflate(outBuf, 0, room)
                } catch (_: java.util.zip.DataFormatException) {
                    throw NonCanonical("cannot inflate")
                }
                if (got > 0) {
                    sink(outBuf, got)
                    produced += got
                } else if (inflater.needsDictionary()) {
                    throw NonCanonical("cannot inflate")
                } else if (!inflater.finished() && !inflater.needsInput()) {
                    throw NonCanonical("cannot inflate")
                }
            }
        } finally {
            inflater.end()
        }
    }

    private fun readAt(raf: RandomAccessFile, pos: Long, len: Int): ByteArray {
        val b = ByteArray(len)
        raf.seek(pos)
        raf.readFully(b)
        return b
    }

    private fun u16(b: ByteArray, o: Int): Int = (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8)
    private fun u32(b: ByteArray, o: Int): Long = (u16(b, o).toLong()) or (u16(b, o + 2).toLong() shl 16)
}
