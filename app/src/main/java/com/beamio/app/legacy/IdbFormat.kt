package com.beamio.app.legacy

/**
 * Chromium IndexedDB on-disk formats (read-only subset): key prefixes, metadata names, IDB keys, value wrapping
 * (Blink IDBValueWrapper, Snappy) and a V8 ValueSerializer subset (objects, arrays, strings, numbers, booleans, null).
 * Anything outside the subset throws [Unsupported]: the caller fails closed and leaves the old record alone.
 */
internal object IdbFormat {
    class Unsupported(msg: String) : Exception(msg)

    // ---- keys ----

    class Prefix(val db: Long, val store: Long, val index: Long, val len: Int)

    fun prefix(k: ByteArray): Prefix? {
        if (k.isEmpty()) return null
        val b = k[0].toInt() and 0xff
        val dbLen = ((b ushr 5) and 7) + 1
        val osLen = ((b ushr 2) and 7) + 1
        val ixLen = (b and 3) + 1
        val total = 1 + dbLen + osLen + ixLen
        if (k.size < total) return null
        fun int(o: Int, n: Int): Long { var r = 0L; for (i in n - 1 downTo 0) r = (r shl 8) or (k[o + i].toLong() and 0xff); return r }
        return Prefix(int(1, dbLen), int(1 + dbLen, osLen), int(1 + dbLen + osLen, ixLen), total)
    }

    private fun utf16be(b: ByteArray, o: Int, chars: Int): String {
        if (o + 2 * chars > b.size) throw Unsupported("utf16")
        val sb = StringBuilder(chars)
        for (i in 0 until chars) sb.append((((b[o + 2 * i].toInt() and 0xff) shl 8) or (b[o + 2 * i + 1].toInt() and 0xff)).toChar())
        return sb.toString()
    }

    /** Global DatabaseName key → (name, id). */
    fun databaseName(k: ByteArray, v: ByteArray): Pair<String, Long>? {
        if (k.size < 6 || k[0] != 0.toByte() || k[1] != 0.toByte() || k[2] != 0.toByte() || k[3] != 0.toByte() || (k[4].toInt() and 0xff) != 0xC9) return null
        val c = LevelDbReader.Cursor(k, 5)
        val originLen = c.varint().toInt(); c.pos += 2 * originLen
        val nameLen = c.varint().toInt()
        val name = utf16be(k, c.pos, nameLen)
        return name to LevelDbReader.Cursor(v, 0).varint()
    }

    /** Object store name metadata → (db, storeId, name). */
    fun objectStoreName(k: ByteArray, v: ByteArray): Triple<Long, Long, String>? {
        val p = prefix(k) ?: return null
        if (p.db == 0L || p.store != 0L || p.index != 0L || k.size <= p.len || (k[p.len].toInt() and 0xff) != 50) return null
        val c = LevelDbReader.Cursor(k, p.len + 1)
        val store = c.varint()
        if (c.done() || c.byte() != 0) return null
        return Triple(p.db, store, utf16be(v, 0, v.size / 2))
    }

    /** IDB key of an object store data row (index 1): a string key, a number key, or null for others. */
    sealed class IdbKey { data class Str(val s: String) : IdbKey(); data class Num(val d: Double) : IdbKey() }

    fun dataKey(k: ByteArray, p: Prefix): IdbKey? {
        if (p.index != 1L || k.size <= p.len) return null
        val c = LevelDbReader.Cursor(k, p.len)
        return when (c.byte()) {
            1 -> { val n = c.varint().toInt(); IdbKey.Str(utf16be(k, c.pos, n)) }
            3 -> IdbKey.Num(java.lang.Double.longBitsToDouble(LevelDbReader.le64(k, c.pos)))
            else -> null
        }
    }

    // ---- values ----

    /** Object store data value: varint version, then the Blink value (maybe Snappy-wrapped). Returns V8 bytes. */
    fun unwrapValue(v: ByteArray): ByteArray {
        val c = LevelDbReader.Cursor(v, 0)
        c.varint() // row version
        var body = v.copyOfRange(c.pos, v.size)
        if (body.size >= 3 && body[0] == 0xFF.toByte() && body[1] == 0x11.toByte()) {
            body = when (body[2].toInt()) {
                2 -> Snappy.decompress(body, 3, body.size)
                1 -> throw Unsupported("value stored as external blob")
                else -> throw Unsupported("wrapper ${body[2]}")
            }
        }
        // Blink envelope: FF <version> [FE <u64 offset> <u32 size>] then V8: FF <version>
        val b = LevelDbReader.Cursor(body, 0)
        if (b.byte() != 0xFF) throw Unsupported("blink header")
        val blinkVersion = b.varint()
        if (blinkVersion >= 21 && !b.done() && body[b.pos] == 0xFE.toByte()) b.pos += 1 + 8 + 4
        if (b.byte() != 0xFF) throw Unsupported("v8 header")
        val v8Version = b.varint()
        // V8 version 16 (value-serializer.cc, "Version 16: don't truncate JSArrayBuffer's and JSArrayBufferView's lengths and offsets"): no new
        // object, string or number tags; only ArrayBuffer and view lengths change. B and V are still not in this subset and fail closed.
        if (v8Version < 13 || v8Version > 16) throw Unsupported("v8 version $v8Version")
        return body.copyOfRange(b.pos, body.size).also { body.fill(0) }
    }

    sealed class V8 {
        class Obj(val props: LinkedHashMap<String, V8>) : V8()
        class Arr(val items: List<V8>) : V8()
        /** One-byte (Latin-1) string bytes, or two-byte chars. Kept as arrays so callers can wipe them. */
        class Str(val latin1: ByteArray?, val chars: CharArray?) : V8() {
            fun text(): String = latin1?.let { String(it, Charsets.ISO_8859_1) } ?: String(chars!!)
            fun wipe() { latin1?.fill(0); chars?.fill('\u0000') }
        }
        class Num(val d: Double) : V8()
        class Bool(val b: Boolean) : V8()
        object Null : V8()
    }

    fun parseV8(b: ByteArray): V8 = V8Reader(b).value()

    private class V8Reader(b: ByteArray) {
        val c = LevelDbReader.Cursor(b, 0)
        fun value(): V8 {
            var t = c.byte()
            while (t == 0x00) t = c.byte() // padding
            return when (t.toChar()) {
                'o' -> obj()
                '"' -> V8.Str(c.slice(c.varint().toInt()), null)
                'c' -> {
                    val n = c.varint().toInt()
                    if (n % 2 != 0) throw Unsupported("two-byte length")
                    val raw = c.slice(n)
                    val ch = CharArray(n / 2) { i -> ((raw[2 * i].toInt() and 0xff) or ((raw[2 * i + 1].toInt() and 0xff) shl 8)).toChar() }
                    raw.fill(0)
                    V8.Str(null, ch)
                }
                'S' -> {
                    val raw = c.slice(c.varint().toInt())
                    val s = String(raw, Charsets.UTF_8).toCharArray(); raw.fill(0)
                    V8.Str(null, s)
                }
                'I' -> { val z = c.varint(); V8.Num(((z ushr 1) xor -(z and 1)).toDouble()) }
                'U' -> V8.Num(c.varint().toDouble())
                'N' -> V8.Num(java.lang.Double.longBitsToDouble(LevelDbReader.le64(c.slice(8), 0)))
                'T' -> V8.Bool(true)
                'F' -> V8.Bool(false)
                '0', '_' -> V8.Null
                'A' -> {
                    val n = c.varint().toInt()
                    val items = ArrayList<V8>(minOf(n, 4096))
                    repeat(n) { items += value() }
                    // trailing named properties then '$' numProps length
                    while (true) {
                        val save = c.pos
                        if (c.byte() == '$'.code) { c.varint(); c.varint(); break }
                        c.pos = save
                        value(); value()
                    }
                    V8.Arr(items)
                }
                else -> throw Unsupported("v8 tag 0x%02x".format(t))
            }
        }

        fun obj(): V8.Obj {
            val props = LinkedHashMap<String, V8>()
            while (true) {
                val save = c.pos
                if (c.byte() == '{'.code) { c.varint(); return V8.Obj(props) }
                c.pos = save
                val k = value()
                val key = when (k) { is V8.Str -> k.text(); is V8.Num -> k.d.toLong().toString(); else -> throw Unsupported("object key") }
                props[key] = value()
            }
        }
    }
}
