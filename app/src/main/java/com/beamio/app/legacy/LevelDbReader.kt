package com.beamio.app.legacy

import java.io.File

/**
 * Read-only LevelDB reader for a copied Chromium IndexedDB directory. Never writes. Reads only the live files named by
 * CURRENT → MANIFEST (tables) plus the current and previous write-ahead logs, and returns the newest live value per
 * user key (deletions applied). Comparator order is not needed because every live file is read in full.
 */
internal object LevelDbReader {
    class Corrupt(msg: String) : Exception(msg)

    class Entry(val key: ByteArray, val seq: Long, val value: ByteArray)

    private class Ver(val seq: Long, val put: Boolean, val value: ByteArray?)

    fun readLive(dir: File): List<Entry> {
        val current = File(dir, "CURRENT").takeIf { it.isFile }?.readText()?.trim() ?: throw Corrupt("no CURRENT")
        if (!current.matches(Regex("MANIFEST-\\d+"))) throw Corrupt("bad CURRENT")
        val manifest = parseManifest(File(dir, current).takeIf { it.isFile }?.readBytes() ?: throw Corrupt("no manifest"))
        val latest = HashMap<Key, Ver>()
        fun offer(k: ByteArray, seq: Long, put: Boolean, v: ByteArray?) {
            val key = Key(k)
            val old = latest[key]
            if (old == null || seq > old.seq) latest[key] = Ver(seq, put, v)
        }
        for (num in manifest.tables) {
            val f = tableFile(dir, num) ?: throw Corrupt("missing table $num")
            readTable(f.readBytes()) { k, seq, put, v -> offer(k, seq, put, v) }
        }
        val logs = dir.listFiles().orEmpty().mapNotNull { f -> Regex("(\\d+)\\.log").matchEntire(f.name)?.let { it.groupValues[1].toLong() to f } }
            .filter { (n, _) -> n >= manifest.logNumber || n == manifest.prevLogNumber }
            .sortedBy { it.first }
        for ((_, f) in logs) readLog(f.readBytes()) { k, seq, put, v -> offer(k, seq, put, v) }
        return latest.entries.filter { it.value.put }.map { Entry(it.key.b, it.value.seq, it.value.value!!) }
    }

    private class Key(val b: ByteArray) {
        override fun equals(other: Any?) = other is Key && b.contentEquals(other.b)
        override fun hashCode() = b.contentHashCode()
    }

    private fun tableFile(dir: File, num: Long): File? {
        val base = "%06d".format(num)
        return listOf("$base.ldb", "$base.sst").map { File(dir, it) }.firstOrNull { it.isFile }
    }

    // ---- write-ahead log (also the MANIFEST format) ----

    internal fun logRecords(data: ByteArray): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        var buf: java.io.ByteArrayOutputStream? = null
        var pos = 0
        while (pos + 7 <= data.size) {
            val left = 32768 - (pos % 32768)
            if (left < 7) { pos += left; continue }
            val len = (data[pos + 4].toInt() and 0xff) or ((data[pos + 5].toInt() and 0xff) shl 8)
            val type = data[pos + 6].toInt() and 0xff
            if (type == 0 && len == 0) { pos += left; continue }
            if (pos + 7 + len > data.size) break // torn tail: ignore, like LevelDB recovery
            val frag = data.copyOfRange(pos + 7, pos + 7 + len)
            pos += 7 + len
            when (type) {
                1 -> out += frag
                2 -> buf = java.io.ByteArrayOutputStream().also { it.write(frag) }
                3 -> buf?.write(frag)
                4 -> { buf?.let { it.write(frag); out += it.toByteArray() }; buf = null }
                else -> throw Corrupt("log record type $type")
            }
        }
        return out
    }

    private fun readLog(data: ByteArray, sink: (ByteArray, Long, Boolean, ByteArray?) -> Unit) {
        for (rec in logRecords(data)) {
            if (rec.size < 12) throw Corrupt("batch header")
            var seq = le64(rec, 0)
            val count = le32(rec, 8)
            val r = Cursor(rec, 12)
            repeat(count) {
                val t = r.byte()
                val k = r.slice(r.varint().toInt())
                when (t) {
                    1 -> sink(k, seq, true, r.slice(r.varint().toInt()))
                    0 -> sink(k, seq, false, null)
                    else -> throw Corrupt("batch op $t")
                }
                seq++
            }
        }
    }

    // ---- MANIFEST (VersionEdit records) ----

    private class Manifest(val tables: Set<Long>, val logNumber: Long, val prevLogNumber: Long)

    private fun parseManifest(data: ByteArray): Manifest {
        val live = HashSet<Pair<Int, Long>>()
        var logNumber = 0L
        var prevLog = -1L
        for (rec in logRecords(data)) {
            val r = Cursor(rec, 0)
            while (!r.done()) {
                when (val tag = r.varint().toInt()) {
                    1 -> r.slice(r.varint().toInt()) // comparator name
                    2 -> logNumber = r.varint()
                    3 -> r.varint() // next file number
                    4 -> r.varint() // last sequence
                    5 -> { r.varint(); r.slice(r.varint().toInt()) } // compact pointer
                    6 -> { val lvl = r.varint().toInt(); live.remove(lvl to r.varint()) }
                    7 -> {
                        val lvl = r.varint().toInt(); val num = r.varint(); r.varint()
                        r.slice(r.varint().toInt()); r.slice(r.varint().toInt())
                        live.add(lvl to num)
                    }
                    9 -> prevLog = r.varint()
                    else -> throw Corrupt("manifest tag $tag")
                }
            }
        }
        return Manifest(live.map { it.second }.toSet(), logNumber, prevLog)
    }

    // ---- SSTable ----

    private fun readTable(data: ByteArray, sink: (ByteArray, Long, Boolean, ByteArray?) -> Unit) {
        if (data.size < 48) throw Corrupt("table too small")
        val footer = data.size - 48
        if (le64(data, data.size - 8) != MAGIC) throw Corrupt("table magic")
        val f = Cursor(data, footer)
        f.varint(); f.varint() // metaindex handle
        val indexOff = f.varint(); val indexSize = f.varint()
        for ((_, handle) in blockEntries(readBlock(data, indexOff, indexSize))) {
            val h = Cursor(handle, 0)
            val off = h.varint(); val size = h.varint()
            for ((ikey, value) in blockEntries(readBlock(data, off, size))) {
                if (ikey.size < 8) throw Corrupt("internal key")
                val trailer = le64(ikey, ikey.size - 8)
                val type = (trailer and 0xff).toInt()
                val seq = trailer ushr 8
                val ukey = ikey.copyOfRange(0, ikey.size - 8)
                when (type) {
                    1 -> sink(ukey, seq, true, value)
                    0 -> sink(ukey, seq, false, null)
                    else -> throw Corrupt("value type $type")
                }
            }
        }
    }

    private fun readBlock(data: ByteArray, off: Long, size: Long): ByteArray {
        val o = off.toInt(); val s = size.toInt()
        if (off < 0 || size < 0 || o + s + 5 > data.size) throw Corrupt("block handle")
        return when (data[o + s].toInt()) {
            0 -> data.copyOfRange(o, o + s)
            1 -> Snappy.decompress(data, o, o + s)
            else -> throw Corrupt("block compression ${data[o + s]}")
        }
    }

    private fun blockEntries(b: ByteArray): List<Pair<ByteArray, ByteArray>> {
        if (b.size < 4) throw Corrupt("block")
        val restarts = le32(b, b.size - 4)
        val end = b.size - 4 - 4 * restarts
        if (restarts < 0 || end < 0) throw Corrupt("restarts")
        val out = ArrayList<Pair<ByteArray, ByteArray>>()
        val r = Cursor(b, 0)
        var last = ByteArray(0)
        while (r.pos < end) {
            val shared = r.varint().toInt(); val nonShared = r.varint().toInt(); val vlen = r.varint().toInt()
            if (shared > last.size) throw Corrupt("shared prefix")
            val key = ByteArray(shared + nonShared)
            System.arraycopy(last, 0, key, 0, shared)
            System.arraycopy(r.slice(nonShared), 0, key, shared, nonShared)
            out += key to r.slice(vlen)
            last = key
        }
        return out
    }

    // ---- helpers ----

    internal class Cursor(val b: ByteArray, var pos: Int) {
        fun done() = pos >= b.size
        fun byte(): Int { if (pos >= b.size) throw Corrupt("eof"); return b[pos++].toInt() and 0xff }
        fun varint(): Long {
            var r = 0L; var s = 0
            while (true) {
                val c = byte()
                r = r or ((c and 0x7f).toLong() shl s)
                if (c and 0x80 == 0) return r
                s += 7
                if (s > 63) throw Corrupt("varint")
            }
        }
        fun slice(n: Int): ByteArray {
            if (n < 0 || pos + n > b.size) throw Corrupt("slice")
            return b.copyOfRange(pos, pos + n).also { pos += n }
        }
    }

    internal fun le32(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8) or ((b[o + 2].toInt() and 0xff) shl 16) or ((b[o + 3].toInt() and 0xff) shl 24)

    internal fun le64(b: ByteArray, o: Int): Long {
        var r = 0L
        for (i in 7 downTo 0) r = (r shl 8) or (b[o + i].toLong() and 0xff)
        return r
    }

    private const val MAGIC = -0x24b88adb747f04a9L // 0xdb4775248b80fb57
}
