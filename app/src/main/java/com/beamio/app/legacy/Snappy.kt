package com.beamio.app.legacy

/** Raw Snappy block decompression (no framing). Used by LevelDB table blocks and Blink IndexedDB value wrapping. */
internal object Snappy {
    class Corrupt(msg: String) : Exception(msg)

    fun decompress(src: ByteArray, from: Int = 0, to: Int = src.size): ByteArray {
        var i = from
        var n = 0L
        var shift = 0
        while (true) {
            if (i >= to) throw Corrupt("length varint")
            val c = src[i++].toInt() and 0xff
            n = n or ((c and 0x7f).toLong() shl shift)
            if (c and 0x80 == 0) break
            shift += 7
            if (shift > 35) throw Corrupt("length varint too long")
        }
        if (n > MAX_OUT) throw Corrupt("output too large")
        val out = ByteArray(n.toInt())
        var o = 0
        while (i < to) {
            val tag = src[i++].toInt() and 0xff
            when (tag and 3) {
                0 -> {
                    var len = tag ushr 2
                    if (len >= 60) {
                        val nb = len - 59
                        if (i + nb > to) throw Corrupt("literal length")
                        len = 0
                        for (b in 0 until nb) len = len or ((src[i + b].toInt() and 0xff) shl (8 * b))
                        i += nb
                    }
                    len += 1
                    if (len < 0 || i + len > to || o + len > out.size) throw Corrupt("literal")
                    System.arraycopy(src, i, out, o, len)
                    i += len
                    o += len
                }
                else -> {
                    val len: Int
                    val off: Int
                    when (tag and 3) {
                        1 -> {
                            if (i >= to) throw Corrupt("copy1")
                            len = ((tag ushr 2) and 7) + 4
                            off = ((tag ushr 5) shl 8) or (src[i++].toInt() and 0xff)
                        }
                        2 -> {
                            if (i + 2 > to) throw Corrupt("copy2")
                            len = (tag ushr 2) + 1
                            off = (src[i].toInt() and 0xff) or ((src[i + 1].toInt() and 0xff) shl 8)
                            i += 2
                        }
                        else -> {
                            if (i + 4 > to) throw Corrupt("copy4")
                            len = (tag ushr 2) + 1
                            off = (src[i].toInt() and 0xff) or ((src[i + 1].toInt() and 0xff) shl 8) or
                                ((src[i + 2].toInt() and 0xff) shl 16) or ((src[i + 3].toInt() and 0xff) shl 24)
                            i += 4
                        }
                    }
                    if (off <= 0 || off > o || o + len > out.size) throw Corrupt("copy offset")
                    for (k in 0 until len) out[o + k] = out[o + k - off]
                    o += len
                }
            }
        }
        if (o != out.size) throw Corrupt("short output")
        return out
    }

    private const val MAX_OUT = 64L * 1024 * 1024
}
